"""HTTP client for the VCF Automation services.

Encapsulates the two pagination dialects the platform uses:
- IaaS ("odata-style"): $top/$skip with totalElements
- Spring-style (deployment, catalog, blueprint, event-broker, policy...): page/size
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator

import requests
import urllib3

from . import auth, retry

log = logging.getLogger(__name__)

# /deployment/api/deployments rejects page sizes above 200.
DEPLOYMENT_MAX_PAGE_SIZE = 200

# The CSP identity endpoints reject a pageLimit above this with a 400 that
# names the parameter and the bound.
CSP_MAX_PAGE_SIZE = 200
# Documented stable fallback when a service has no /about endpoint.
FALLBACK_API_VERSION = "2020-08-25"

# Re-logins allowed with no successful call in between. A bearer that expires
# twice during a long sweep is two separate episodes with hundreds of good
# calls between them, so the budget resets on success rather than being spent
# once for the life of the client. What it still bounds is the case that made
# a limit necessary at all: an endpoint answering 401 for a reason a fresh
# token cannot fix, which would otherwise buy a login per request.
MAX_CONSECUTIVE_REAUTHS = 2


class ApiError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class ApiClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base_url = cfg.url
        self.timeout = cfg.timeout
        self.retries = cfg.retries
        self.session = requests.Session()
        self.session.verify = cfg.verify
        if cfg.verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.iaas_api_version: str | None = None
        self._reauths_since_success = 0

    # -- auth -------------------------------------------------------------

    def login(self) -> None:
        token = auth.get_bearer_token(self.cfg, self.session)
        self.session.headers["Authorization"] = f"Bearer {token}"

    def pin_api_versions(self) -> dict:
        """Fetch /iaas/api/about and pin the latest IaaS apiVersion.

        The deployment and catalog services on some 8.x builds have no /about
        endpoint at all, so those use FALLBACK_API_VERSION implicitly (they
        also accept requests without apiVersion; we simply don't send one).
        """
        about = self.get("/iaas/api/about")
        self.iaas_api_version = about.get("latestApiVersion") or FALLBACK_API_VERSION
        log.info("Pinned IaaS apiVersion=%s", self.iaas_api_version)
        return about

    # -- request core -----------------------------------------------------

    def get(self, path: str, params: dict | None = None) -> dict:
        # Absolute URLs supported for external endpoints (e.g. external vRO)
        # that accept the same bearer token.
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        attempt = 0
        while True:
            try:
                # verify passed per request: requests lets REQUESTS_CA_BUNDLE
                # and CURL_CA_BUNDLE in the environment override session-level
                # verify, which silently defeated --insecure and --ca-bundle
                # on hosts that export them.
                resp = self.session.get(
                    url, params=params, timeout=self.timeout, verify=self.cfg.verify
                )
            except requests.RequestException as exc:
                # A timed-out or dropped call is repeated: one slow answer
                # from a busy appliance used to end the whole area's
                # collection. A settled failure (bad certificate, bad URL)
                # is not retried - see retry.is_transient.
                if attempt >= self.retries or not retry.is_transient(exc):
                    raise ApiError(
                        f"GET {path} failed after {attempt + 1} attempt(s): {exc}"
                    ) from exc
                delay = retry.backoff_delay(attempt)
                attempt += 1
                log.warning(
                    "GET %s: %s; retrying in %.0fs (attempt %d of %d)",
                    path,
                    retry.describe(exc),
                    delay,
                    attempt + 1,
                    self.retries + 1,
                )
                time.sleep(delay)
                continue

            if (
                resp.status_code == 401
                and self._reauths_since_success < MAX_CONSECUTIVE_REAUTHS
                and self.cfg.refresh_token
            ):
                # Bearer expired mid-run; re-login and repeat the call.
                # Deliberately not counted as a retry: a 401 arriving after
                # three 5xx retries used to consume the loop and fail without
                # ever using the fresh token.
                log.warning("Got 401 on %s; re-authenticating", path)
                self._reauths_since_success += 1
                self.login()
                continue
            if resp.status_code in retry.RETRY_STATUS and attempt < self.retries:
                delay = retry.backoff_delay(attempt, resp.headers.get("Retry-After"))
                attempt += 1
                log.info(
                    "HTTP %s on %s; retrying in %.0fs (attempt %d of %d)",
                    resp.status_code,
                    path,
                    delay,
                    attempt + 1,
                    self.retries + 1,
                )
                time.sleep(delay)
                continue
            if not resp.ok:
                raise ApiError(
                    f"GET {path} -> HTTP {resp.status_code}: {resp.text[:300]}",
                    status_code=resp.status_code,
                )
            # One good answer proves the current token works, which is what
            # makes the next expiry a new episode rather than a repeat of this
            # one.
            self._reauths_since_success = 0
            try:
                return resp.json()
            except ValueError as exc:
                raise ApiError(f"GET {path} returned non-JSON response") from exc

    # -- pagination helpers ----------------------------------------------

    def iter_odata(
        self, path: str, params: dict | None = None, page_size: int | None = None
    ) -> Iterator[dict]:
        """IaaS-style pagination: $top/$skip, response {'content': [...], 'totalElements': N}."""
        size = page_size or self.cfg.page_size
        skip = 0
        last_fp: tuple | None = None
        while True:
            p = {**(params or {}), "$top": size, "$skip": skip}
            if self.iaas_api_version:
                p["apiVersion"] = self.iaas_api_version
            body = self.get(path, params=p)
            content = body.get("content", [])
            fp = _page_fingerprint(content)
            if content and fp == last_fp:
                # A server ignoring $skip re-serves the same page; yielding
                # it again would duplicate every row (a live vRO build did
                # exactly this with its own startIndex).
                log.warning("%s repeated a page despite $skip advancing; stopping", path)
                break
            last_fp = fp
            yield from content
            skip += len(content)
            total = body.get("totalElements")
            if not content:
                break
            if isinstance(total, int) and skip >= total:
                break
            if not isinstance(total, int) and len(content) < size:
                # No usable total: a short page is the only end signal. A
                # missing totalElements used to read as 0 and truncated the
                # listing to its first page.
                break

    def iter_csp(
        self, path: str, params: dict | None = None, page_size: int | None = None
    ) -> Iterator[dict]:
        """CSP identity pagination: pageStart/pageLimit, response {'results': [...]}.

        The third dialect, and the one that fails silently: these endpoints
        accept page/size without complaint and ignore them, serving the same
        first page forever. A live probe read one page of 140 groups as 28140
        rows and reported two thirds of the estate's groups as missing before
        the parameter names were read off the endpoint's own 400 response.
        pageLimit is capped at 200 server-side.
        """
        size = min(page_size or self.cfg.page_size, CSP_MAX_PAGE_SIZE)
        start = 0
        last_fp: tuple | None = None
        while True:
            p = {**(params or {}), "pageStart": start, "pageLimit": size}
            body = self.get(path, params=p)
            content = body.get("results") or body.get("content") or []
            fp = _page_fingerprint(content)
            if content and fp == last_fp:
                log.warning("%s repeated a page despite pageStart advancing; stopping", path)
                break
            last_fp = fp
            yield from content
            if not content:
                break
            start += len(content)
            total = body.get("totalResults")
            if isinstance(total, int) and start >= total:
                break
            if not isinstance(total, int) and len(content) < size:
                break

    def iter_paged(
        self, path: str, params: dict | None = None, page_size: int | None = None
    ) -> Iterator[dict]:
        """Spring-style pagination: page/size, response {'content': [...], 'last'/'totalPages'}."""
        size = page_size or self.cfg.page_size
        page = 0
        last_fp: tuple | None = None
        while True:
            p = {**(params or {}), "page": page, "size": size}
            body = self.get(path, params=p)
            content = body.get("content", [])
            fp = _page_fingerprint(content)
            if content and fp == last_fp:
                # A server ignoring the page param with neither last nor
                # totalPages in the envelope would otherwise loop forever.
                log.warning("%s repeated a page despite the page param advancing; stopping", path)
                break
            last_fp = fp
            yield from content
            page += 1
            if not content or body.get("last") is True:
                break
            total_pages = body.get("totalPages")
            if total_pages is not None and page >= total_pages:
                break


def _page_fingerprint(content: list) -> tuple:
    """Cheap identity for a page: its length plus first/last element ids."""

    def ident(element) -> str:
        if isinstance(element, dict):
            return str(element.get("id") or element.get("name") or element)
        return str(element)

    if not content:
        return (0,)
    return (len(content), ident(content[0]), ident(content[-1]))
