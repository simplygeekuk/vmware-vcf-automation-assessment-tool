"""CSP login error reporting against a stubbed session."""

import pytest

from vcf_automation_assessment_tool.auth import AuthError, obtain_refresh_token


class FakeResponse:
    def __init__(self, status_code, body="", json_body=None):
        self.status_code = status_code
        self.text = body
        self.ok = status_code < 400
        self._json = json_body

    def json(self):
        return self._json


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def post(self, url, json=None, timeout=None, verify=True):
        # verify is passed per request so environment CA-bundle variables
        # cannot override the run's TLS choice; recorded for assertions.
        self.requests.append({"url": url, "json": json, "verify": verify})
        return self.response


def login(session, domain=None):
    return obtain_refresh_token(
        session, "https://example.test", "someuser", "secret", domain, timeout=30
    )


def test_400_without_domain_surfaces_server_body():
    body = '{"errors":["Unable to authenticate user, check username and password."]}'
    session = FakeSession(FakeResponse(400, body))
    with pytest.raises(AuthError) as err:
        login(session)
    assert "check username and password" in str(err.value)
    assert "--domain" in str(err.value)  # the domain hint stays


def test_400_without_domain_and_empty_body_says_so():
    session = FakeSession(FakeResponse(400, "   "))
    with pytest.raises(AuthError, match=r"\(empty response body\)"):
        login(session)


def test_400_with_domain_uses_generic_error():
    session = FakeSession(FakeResponse(400, "bad creds"))
    with pytest.raises(AuthError, match="HTTP 400: bad creds"):
        login(session, domain="corp.local")


def test_domain_included_in_request_body():
    session = FakeSession(FakeResponse(200, json_body={"refresh_token": "tok"}))
    assert login(session, domain="corp.local") == "tok"
    assert session.requests[0]["json"]["domain"] == "corp.local"


def test_success_without_domain_omits_key():
    session = FakeSession(FakeResponse(200, json_body={"refresh_token": "tok"}))
    assert login(session) == "tok"
    assert "domain" not in session.requests[0]["json"]
