"""RunConfig resolution for the per-finding row cap: CLI > config file >
default, and the validation floor. Every case passes --config explicitly so
a real config.yaml in the working directory can
never leak into a test."""

from vcf_automation_assessment_tool.cli import build_parser
from vcf_automation_assessment_tool.config import RunConfig


def _load(tmp_path, argv, yaml_text="{}\n"):
    cfg_file = tmp_path / "cfg.yaml"
    cfg_file.write_text(yaml_text, encoding="utf-8")
    return RunConfig.load(build_parser().parse_args(["--config", str(cfg_file), *argv]))


def test_max_rows_per_finding_defaults_to_500(tmp_path):
    assert _load(tmp_path, []).max_rows_per_finding == 500


def test_max_rows_per_finding_read_from_config_file(tmp_path):
    cfg = _load(tmp_path, [], "max_rows_per_finding: 1200\n")
    assert cfg.max_rows_per_finding == 1200


def test_max_rows_per_finding_cli_overrides_config_file(tmp_path):
    cfg = _load(tmp_path, ["--max-rows-per-finding", "50"], "max_rows_per_finding: 1200\n")
    assert cfg.max_rows_per_finding == 50


def test_keyboard_interrupt_exits_cleanly(monkeypatch, capsys):
    # Ctrl+C at any point must end with one stderr line and exit code 130,
    # never a traceback.
    import vcf_automation_assessment_tool.cli as cli

    def interrupted(args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.RunConfig, "load", staticmethod(interrupted))
    rc = cli.main(["--url", "https://vra.example.com", "--username", "admin"])
    assert rc == 130
    assert "interrupted" in capsys.readouterr().err


def test_max_rows_per_finding_below_one_fails_validation(tmp_path):
    cfg = _load(
        tmp_path,
        [],
        "url: https://vra.example.com\nusername: admin\nmax_rows_per_finding: 0\n",
    )
    assert any("max_rows_per_finding" in error for error in cfg.validate())


def test_malformed_yaml_is_a_clean_value_error(tmp_path):
    """A stray tab in the config file surfaces as the cli's one-line error,
    not a yaml traceback."""
    import pytest

    from vcf_automation_assessment_tool.cli import build_parser
    from vcf_automation_assessment_tool.config import RunConfig

    bad = tmp_path / "cfg.yaml"
    bad.write_text("url: https://x\n\tbroken: true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid YAML"):
        RunConfig.load(build_parser().parse_args(["--config", str(bad)]))


def test_legacy_config_filename_warns_when_nothing_loads(tmp_path, monkeypatch, caplog):
    """A leftover pre-rename config file earns a pointer at the rename
    instead of an unexplained missing-URL failure."""
    import logging

    from vcf_automation_assessment_tool.cli import build_parser
    from vcf_automation_assessment_tool.config import RunConfig

    monkeypatch.chdir(tmp_path)
    (tmp_path / "aria-automation-assessment-tool.yaml").write_text(
        "url: https://x\n", encoding="utf-8"
    )
    with caplog.at_level(logging.WARNING):
        cfg = RunConfig.load(build_parser().parse_args([]))
    assert cfg.url == ""  # the legacy file is not read
    assert any("no longer read" in r.message for r in caplog.records)


def test_cli_ca_bundle_beats_a_leftover_file_insecure(tmp_path):
    """TLS trust resolves as a pair: --ca-bundle on the CLI must not be
    silently defeated by insecure: true still sitting in the yaml."""
    cfg = _load(
        tmp_path,
        ["--ca-bundle", "C:/certs/ca.pem"],
        "url: https://x\ninsecure: true\n",
    )
    assert cfg.insecure is False
    assert cfg.verify == "C:/certs/ca.pem"


def test_file_insecure_still_applies_without_cli_tls_flags(tmp_path):
    cfg = _load(tmp_path, [], "url: https://x\ninsecure: true\n")
    assert cfg.insecure is True and cfg.verify is False


def test_projects_scalar_becomes_a_single_entry(tmp_path):
    """projects: myproject (a yaml scalar) used to be exploded into
    characters, silently filtering the report down to nothing."""
    cfg = _load(tmp_path, [], "url: https://x\nprojects: myproject\n")
    assert cfg.projects == ["myproject"]


def test_explicit_zero_reaches_validation(tmp_path):
    """--max-rows-per-finding 0 used to read as unset (0 == False) and
    silently became the default instead of failing validation."""
    cfg = _load(tmp_path, ["--max-rows-per-finding", "0"], "url: https://x\nusername: u\n")
    assert cfg.max_rows_per_finding == 0
    assert any("max_rows_per_finding" in e for e in cfg.validate())


def test_redaction_is_off_unless_asked_for(tmp_path):
    cfg = _load(tmp_path, [], "url: https://x\nusername: u\n")
    assert cfg.redact is False
    assert cfg.redact_classes == ["identity", "hosts", "tags"]


def test_redaction_reads_from_the_config_file(tmp_path):
    cfg = _load(
        tmp_path,
        [],
        "url: https://x\nusername: u\nredact: true\n"
        "redact_classes: [names, ids]\nredact_extra: [acmecorp]\n",
    )
    assert cfg.redact is True
    assert cfg.redact_classes == ["names", "ids"]
    assert cfg.redact_extra == ["acmecorp"]


def test_redact_classes_cli_replaces_the_file_list(tmp_path):
    cfg = _load(
        tmp_path,
        ["--redact", "--redact-class", "hosts"],
        "url: https://x\nusername: u\nredact_classes: [names, ids]\n",
    )
    assert cfg.redact_classes == ["hosts"]


def test_an_unusable_redact_class_list_falls_back_to_the_default_set(tmp_path):
    """A typo must not produce a file whose header says redacted and whose
    body is the estate."""
    cfg = _load(tmp_path, [], "url: https://x\nusername: u\nredact_classes: [hostnames]\n")
    assert cfg.redact_classes == ["identity", "hosts", "tags"]


def test_redaction_options_without_redaction_are_an_error(tmp_path):
    cfg = _load(tmp_path, ["--redact-output", "out.html"], "url: https://x\nusername: u\n")
    assert any("redact_output" in e for e in cfg.validate())


def test_two_outputs_at_one_path_are_rejected(tmp_path):
    """The redacted copy landing on the report it was made from would replace
    the internal artifact with the shareable one, silently."""
    cfg = _load(
        tmp_path,
        ["--redact", "--output", "report.html", "--redact-output", "./report.html"],
        "url: https://x\nusername: u\n",
    )
    assert any("must be different files" in e for e in cfg.validate())


def test_distinct_output_paths_validate(tmp_path):
    cfg = _load(
        tmp_path,
        ["--redact", "--output", "report.html", "--redact-output", "shareable.html"],
        "url: https://x\nusername: u\n",
    )
    assert cfg.validate() == []


def test_the_same_file_spelled_two_ways_is_still_one_file():
    """The pairing this guard exists to stop is the redacted copy landing on
    the report it was made from, and that is exactly where somebody types the
    same path two ways."""
    cfg = RunConfig(
        url="https://vra.example.com",
        username="admin",
        redact=True,
        output="reports/assessment.html",
        redact_output="./reports/assessment.html",
    )
    assert any("overwrite" in error for error in cfg.validate())


def test_genuinely_different_outputs_still_validate():
    cfg = RunConfig(
        url="https://vra.example.com",
        username="admin",
        redact=True,
        output="reports/assessment.html",
        redact_output="reports/shareable.html",
        json_path="reports/dump.json",
    )
    assert cfg.validate() == []


def test_a_leftover_aria_env_var_earns_a_warning(tmp_path, monkeypatch, caplog):
    import logging

    from vcf_automation_assessment_tool.cli import build_parser
    from vcf_automation_assessment_tool.config import RunConfig

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARIA_URL", "https://x")
    with caplog.at_level(logging.WARNING):
        cfg = RunConfig.load(build_parser().parse_args([]))
    assert cfg.url == ""  # the old variable is not read
    assert any("ARIA_URL no longer read" in r.message for r in caplog.records)
