"""Transient failures are retried; settled ones fail on the first answer."""

import pytest
import requests

from vcf_automation_assessment_tool import retry
from vcf_automation_assessment_tool.auth import obtain_refresh_token
from vcf_automation_assessment_tool.client import ApiClient, ApiError
from vcf_automation_assessment_tool.config import RunConfig


@pytest.fixture(autouse=True)
def no_sleeping(monkeypatch):
    """Backoff waits are asserted on, never actually served."""
    slept = []
    # client and retry share the one time module, so this covers both.
    monkeypatch.setattr(retry.time, "sleep", slept.append)
    return slept


class FakeResponse:
    def __init__(self, status_code=200, json_body=None, headers=None):
        self.status_code = status_code
        self.ok = status_code < 400
        self.text = ""
        self.headers = headers or {}
        self._json = json_body if json_body is not None else {}

    def json(self):
        return self._json


def make_client(answers, retries=3):
    """answers: what each successive session.get returns, or raises."""
    cfg = RunConfig(url="https://example.test", retries=retries)
    client = ApiClient(cfg)
    calls = []

    def fake_get(url, params=None, timeout=None, verify=True):
        answer = answers[len(calls)]
        calls.append(url)
        if isinstance(answer, Exception):
            raise answer
        return answer

    client.session.get = fake_get
    client.calls = calls
    return client


def test_read_timeout_is_retried_then_succeeds(no_sleeping):
    client = make_client(
        [requests.exceptions.ReadTimeout("timed out"), FakeResponse(json_body={"id": "a"})]
    )
    assert client.get("/iaas/api/things") == {"id": "a"}
    assert len(client.calls) == 2
    assert no_sleeping == [1.0]


def test_timeout_fails_only_after_the_retry_budget(no_sleeping):
    client = make_client([requests.exceptions.ReadTimeout("timed out")] * 4)
    with pytest.raises(ApiError, match="after 4 attempt"):
        client.get("/iaas/api/things")
    assert len(client.calls) == 4
    assert no_sleeping == [1.0, 2.0, 4.0]


def test_retries_zero_tries_each_call_once(no_sleeping):
    client = make_client([requests.exceptions.ConnectTimeout("timed out")], retries=0)
    with pytest.raises(ApiError, match="after 1 attempt"):
        client.get("/iaas/api/things")
    assert len(client.calls) == 1
    assert no_sleeping == []


def test_tls_failure_is_not_retried(no_sleeping):
    # The trust decision cannot change between attempts, so repeating it only
    # delays the operator's answer.
    client = make_client([requests.exceptions.SSLError("certificate verify failed")] * 4)
    with pytest.raises(ApiError, match="after 1 attempt"):
        client.get("/iaas/api/things")
    assert len(client.calls) == 1


def test_retryable_status_honours_retry_after(no_sleeping):
    client = make_client(
        [
            FakeResponse(503, headers={"Retry-After": "5"}),
            FakeResponse(json_body={"id": "a"}),
        ]
    )
    assert client.get("/iaas/api/things") == {"id": "a"}
    assert no_sleeping == [5.0]


def test_retry_after_is_capped():
    assert retry.backoff_delay(0, "3600") == retry.MAX_BACKOFF
    assert retry.backoff_delay(0, "not-a-number") == 1.0
    assert retry.backoff_delay(9) == retry.MAX_BACKOFF


def test_login_timeout_is_retried(no_sleeping):
    """A timeout on the first call of the run must not end the run."""
    answers = [
        requests.exceptions.ReadTimeout("timed out"),
        FakeResponse(json_body={"refresh_token": "tok"}),
    ]
    calls = []

    class FakeSession:
        def post(self, url, json=None, timeout=None, verify=True):
            answer = answers[len(calls)]
            calls.append(url)
            if isinstance(answer, Exception):
                raise answer
            return answer

    token = obtain_refresh_token(
        FakeSession(), "https://example.test", "someuser", "secret", None, timeout=30
    )
    assert token == "tok"
    assert len(calls) == 2


def test_login_gives_up_after_the_budget(no_sleeping):
    class FakeSession:
        def post(self, url, json=None, timeout=None, verify=True):
            raise requests.exceptions.ConnectTimeout("timed out")

    with pytest.raises(requests.exceptions.ConnectTimeout):
        obtain_refresh_token(
            FakeSession(), "https://example.test", "someuser", "secret", None, timeout=30, retries=1
        )


def test_retries_resolve_from_the_config_file(tmp_path):
    from vcf_automation_assessment_tool.cli import build_parser

    cfg_file = tmp_path / "cfg.yaml"
    cfg_file.write_text("retries: 5" + chr(10), encoding="utf-8")
    args = build_parser().parse_args(["--config", str(cfg_file)])
    assert RunConfig.load(args).retries == 5
    args = build_parser().parse_args(["--config", str(cfg_file), "--retries", "0"])
    assert RunConfig.load(args).retries == 0


def test_negative_retries_is_a_configuration_error():
    cfg = RunConfig(url="https://example.test", username="admin", retries=-1)
    assert any("retries" in e for e in cfg.validate())


def _login_session(answers, calls):
    class FakeSession:
        def post(self, url, json=None, timeout=None, verify=True):
            answer = answers[len(calls)]
            calls.append(url)
            if isinstance(answer, Exception):
                raise answer
            return answer

    return FakeSession()


def test_login_retries_a_5xx_not_just_a_dropped_connection(no_sleeping):
    """An appliance still starting its services answers, it does not drop the
    call - and the login is the first request of the run, so failing on that
    answer ended the assessment before anything was read."""
    calls = []
    session = _login_session(
        [FakeResponse(503), FakeResponse(json_body={"refresh_token": "tok"})], calls
    )
    token = obtain_refresh_token(
        session, "https://example.test", "someuser", "secret", None, timeout=30
    )
    assert token == "tok"
    assert len(calls) == 2
    assert no_sleeping == [1.0]


def test_login_honours_retry_after_on_a_429(no_sleeping):
    calls = []
    session = _login_session(
        [
            FakeResponse(429, headers={"Retry-After": "7"}),
            FakeResponse(json_body={"refresh_token": "tok"}),
        ],
        calls,
    )
    obtain_refresh_token(session, "https://example.test", "someuser", "secret", None, timeout=30)
    assert no_sleeping == [7.0]


def test_login_stops_repeating_a_5xx_and_reports_it(no_sleeping):
    """The budget spent, the last response is returned rather than swallowed,
    so the caller still gets the AuthError naming the status."""
    from vcf_automation_assessment_tool.auth import AuthError

    calls = []
    session = _login_session([FakeResponse(503)] * 4, calls)
    with pytest.raises(AuthError, match="503"):
        obtain_refresh_token(
            session, "https://example.test", "someuser", "secret", None, timeout=30, retries=2
        )
    assert len(calls) == 3


def test_a_400_login_is_not_retried(no_sleeping):
    """Bad credentials will not become good on a repeat."""
    from vcf_automation_assessment_tool.auth import AuthError

    calls = []
    session = _login_session([FakeResponse(400)] * 4, calls)
    with pytest.raises(AuthError):
        obtain_refresh_token(
            session, "https://example.test", "someuser", "secret", None, timeout=30
        )
    assert len(calls) == 1
    assert no_sleeping == []


def _reauth_client(answers):
    client = make_client(answers)
    client.cfg.refresh_token = "tok"
    logins = []
    client.login = lambda: logins.append(True)
    client.logins = logins
    return client


def test_a_second_token_expiry_re_authenticates_again(no_sleeping):
    """The budget resets on a good answer. A long sweep can outlive its bearer
    more than once, and a one-shot flag made every expiry after the first fatal.
    """
    client = _reauth_client(
        [
            FakeResponse(401),
            FakeResponse(json_body={"id": "a"}),
            FakeResponse(401),
            FakeResponse(json_body={"id": "b"}),
        ]
    )
    assert client.get("/iaas/api/things") == {"id": "a"}
    assert client.get("/iaas/api/other") == {"id": "b"}
    assert len(client.logins) == 2


def test_a_401_a_fresh_token_cannot_fix_stops_re_authenticating(no_sleeping):
    """Not every 401 is an expired bearer. Without a bound, an endpoint that
    always answers 401 would buy a login per request for the rest of the run."""
    from vcf_automation_assessment_tool.client import MAX_CONSECUTIVE_REAUTHS

    client = _reauth_client([FakeResponse(401)] * 10)
    with pytest.raises(ApiError, match="401"):
        client.get("/iaas/api/things")
    assert len(client.logins) == MAX_CONSECUTIVE_REAUTHS
