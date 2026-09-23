"""Retry policy for transient HTTP failures, shared by the client and the auth flows.

A read timeout on one call is not a reason to lose a whole collection run, so a
request that could plausibly succeed on a repeat is sent again with exponential
backoff. Everything the tool sends is a read or an idempotent token exchange,
so repeating a request cannot change the estate.
"""

from __future__ import annotations

import logging
import time

import requests

log = logging.getLogger(__name__)

DEFAULT_RETRIES = 3
# Retry-After can name a very long wait; past a minute the run is better off
# recording the gap and moving on to the next call.
MAX_BACKOFF = 60.0
# Status codes worth repeating: rate limiting and the gateway/backend errors an
# 8.x appliance emits while a service restarts or a slow query times out.
RETRY_STATUS = {429, 500, 502, 503, 504}


def is_transient(exc: BaseException) -> bool:
    """True when the same request could plausibly succeed if sent again.

    A TLS failure arrives as a ConnectionError but is settled - the trust
    decision will not change between attempts - so it fails on the first
    answer instead of costing the operator four attempts of silence.
    """
    if isinstance(exc, requests.exceptions.SSLError):
        return False
    return isinstance(
        exc,
        (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError,
        ),
    )


def backoff_delay(attempt: int, retry_after: str | None = None) -> float:
    """Seconds to wait before attempt+1. The server's Retry-After wins."""
    if retry_after:
        try:
            return min(float(retry_after), MAX_BACKOFF)
        except ValueError:
            pass
    return min(float(2**attempt), MAX_BACKOFF)


def describe(exc: BaseException) -> str:
    """One short phrase naming what went wrong, for the retry log line."""
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "read timed out"
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "connection timed out"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timed out"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection failed"
    return type(exc).__name__


def send_with_retry(send, what: str, retries: int = DEFAULT_RETRIES, logger=None):
    """Call send() and repeat it while it fails transiently.

    send() performs exactly one request and returns its response; `what`
    names the call in the log line.

    A request fails transiently in two ways, and this used to repeat only one
    of them. The call raising is the obvious one. The call ANSWERING 429 or a
    5xx is the other, and it is the shape an appliance takes while its services
    come up after a restart - which is exactly when the CSP login is the first
    request of the run. The client's own loop has always repeated both; here a
    503 went straight through to "login failed" and ended the assessment before
    a single object was read.

    The last response is returned, or the last exception re-raised, once the
    budget is spent: the caller still fails, just not on the first blip.
    """
    logger = logger or log
    attempt = 0
    while True:
        try:
            resp = send()
        except requests.RequestException as exc:
            if attempt >= retries or not is_transient(exc):
                raise
            delay = backoff_delay(attempt)
            reason = describe(exc)
        else:
            # The server's own Retry-After wins over the backoff curve, the
            # same way it does in the client.
            if resp.status_code not in RETRY_STATUS or attempt >= retries:
                return resp
            delay = backoff_delay(attempt, resp.headers.get("Retry-After"))
            reason = f"HTTP {resp.status_code}"
        attempt += 1
        logger.warning(
            "%s: %s; retrying in %.0fs (attempt %d of %d)",
            what,
            reason,
            delay,
            attempt + 1,
            retries + 1,
        )
        time.sleep(delay)
