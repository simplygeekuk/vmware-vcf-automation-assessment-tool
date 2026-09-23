"""Authentication: CSP gateway username/password flow and refresh-token flow.

Both flows end in the same IaaS bearer token, used against every service
(IaaS, blueprint, deployment, catalog, event-broker, policy, form-service, ABX).
"""

from __future__ import annotations

import getpass
import logging

import requests

from . import retry

log = logging.getLogger(__name__)


class AuthError(RuntimeError):
    pass


def obtain_refresh_token(
    session: requests.Session,
    url: str,
    username: str,
    password: str,
    domain: str | None,
    timeout: int,
    verify: bool | str = True,
    retries: int = retry.DEFAULT_RETRIES,
) -> str:
    body = {"username": username, "password": password}
    if domain:
        body["domain"] = domain
    log.info("Logging in to CSP gateway as %s%s", username, f"@{domain}" if domain else "")
    # verify passed per request: environment CA-bundle variables override
    # session-level verify inside requests, and the auth calls must honor
    # --insecure/--ca-bundle exactly like every other call.
    # Retried like every other call: a timeout on the very first request of
    # the run used to end it before a single object was read.
    resp = retry.send_with_retry(
        lambda: session.post(
            f"{url}/csp/gateway/am/api/login?access_token",
            json=body,
            timeout=timeout,
            verify=verify,
        ),
        "CSP login",
        retries=retries,
        logger=log,
    )
    if resp.status_code == 400 and not domain:
        # CSP returns 400 for bad credentials as well as a missing domain, so
        # the server body is the only way to tell the two apart.
        raise AuthError(
            f"CSP login failed with 400: {resp.text[:300].strip() or '(empty response body)'}\n"
            "A 400 here means either bad credentials or, for LDAP/AD users, a "
            "missing identity source domain (pass --domain, e.g. --domain corp.local)."
        )
    if not resp.ok:
        raise AuthError(f"CSP login failed: HTTP {resp.status_code}: {resp.text[:300]}")
    token = resp.json().get("refresh_token")
    if not token:
        raise AuthError("CSP login succeeded but response contained no refresh_token")
    return token


def exchange_for_bearer(
    session: requests.Session,
    url: str,
    refresh_token: str,
    timeout: int,
    verify: bool | str = True,
    retries: int = retry.DEFAULT_RETRIES,
) -> str:
    log.info("Exchanging refresh token at /iaas/api/login")
    resp = retry.send_with_retry(
        lambda: session.post(
            f"{url}/iaas/api/login",
            json={"refreshToken": refresh_token},
            timeout=timeout,
            verify=verify,
        ),
        "IaaS token exchange",
        retries=retries,
        logger=log,
    )
    if not resp.ok:
        raise AuthError(f"IaaS login failed: HTTP {resp.status_code}: {resp.text[:300]}")
    token = resp.json().get("token")
    if not token:
        raise AuthError("IaaS login succeeded but response contained no token")
    return token


def get_bearer_token(cfg, session: requests.Session) -> str:
    """Run whichever flow the config selects and return the bearer token.

    Stores the refresh token on cfg so the client can re-authenticate once on a
    mid-run 401.
    """
    retries = cfg.retries
    if not cfg.refresh_token:
        if cfg.password is None:
            cfg.password = getpass.getpass(f"Password for {cfg.username}: ")
        cfg.refresh_token = obtain_refresh_token(
            session,
            cfg.url,
            cfg.username,
            cfg.password,
            cfg.domain,
            cfg.timeout,
            cfg.verify,
            retries,
        )
    return exchange_for_bearer(
        session, cfg.url, cfg.refresh_token, cfg.timeout, cfg.verify, retries
    )
