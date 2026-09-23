"""What the run does when an artifact it was asked for cannot be written.

Losing one output must not cost the others, and it must never reach the
operator as a traceback. The run still fails: something asked for is missing.
"""

import vcf_automation_assessment_tool.cli as cli
from vcf_automation_assessment_tool.config import RunConfig


class FakeClient:
    """Enough of ApiClient to get _main as far as the output writes."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.iaas_api_version = "2021-07-15"

    def login(self):
        return None

    def pin_api_versions(self):
        return {"latestApiVersion": "2021-07-15", "supportedApis": []}

    def get(self, path, params=None):
        # /vco/api/about is best-effort in _main and its absence is normal.
        raise cli.ApiError(f"no {path} on this build")


def _collect_one_project(client, data):
    data.raw["infrastructure"] = {"projects": [{"id": "p1", "name": "Proj"}]}


def _run(monkeypatch, tmp_path, extra_args):
    monkeypatch.setattr(cli, "ApiClient", FakeClient)
    monkeypatch.setattr(cli, "COLLECTORS", [("infrastructure", _collect_one_project)])
    return cli.main(
        [
            "--url",
            "https://vra.example.test",
            "--refresh-token",
            "tok",
            "--output",
            str(tmp_path / "report.html"),
            *extra_args,
        ]
    )


def test_a_failed_json_dump_still_leaves_the_report(monkeypatch, tmp_path, capsys):
    """The dump exists to protect a finished collection. Losing it used to end
    the run with a traceback and no artifacts at all, which is the opposite of
    what it is for."""
    # A directory where a file was asked for: open() raises OSError on every
    # platform, and the parent already exists so the pre-flight check passes.
    blocked = tmp_path / "dump.json"
    blocked.mkdir()

    rc = _run(monkeypatch, tmp_path, ["--json", str(blocked)])

    assert rc == 1, "a missing artifact is a failed run"
    assert (tmp_path / "report.html").exists(), "the report must survive the dump failing"
    captured = capsys.readouterr()
    assert "could not write" in captured.err
    assert "report written" in captured.out


def test_a_redacted_report_that_cannot_be_written_says_so(sample_data, tmp_path, capsys):
    from vcf_automation_assessment_tool.checks import run_checks

    run_checks(sample_data)
    cfg = RunConfig()
    cfg.redact = True
    blocked = tmp_path / "redacted.html"
    blocked.mkdir()

    assert cli._write_redacted(sample_data, cfg, str(blocked)) is False
    assert "could not write the redacted report" in capsys.readouterr().err


def test_a_redaction_key_that_cannot_be_written_fails_the_run(sample_data, tmp_path, capsys):
    """The report landed, the key did not. Saying so matters: the key is the
    only way a finding traces back to a real name."""
    from vcf_automation_assessment_tool.checks import run_checks

    run_checks(sample_data)
    cfg = RunConfig()
    cfg.redact = True
    cfg.redact_key = str(tmp_path / "key.csv")
    (tmp_path / "key.csv").mkdir()
    out = tmp_path / "redacted.html"

    assert cli._write_redacted(sample_data, cfg, str(out)) is False
    assert out.exists(), "the report itself was written before the key failed"
    err = capsys.readouterr().err
    assert "redaction key" in err and "could not be" in err
