"""ignore_findings: keep a check running, keep it out of the HTML report.

The report is the thing handed to stakeholders, so suppression is a rendering
decision, not a collection one: the finding is still computed, still in the
--json dump, and the report header names what it left out.
"""

from vcf_automation_assessment_tool.cli import build_parser
from vcf_automation_assessment_tool.config import RunConfig
from vcf_automation_assessment_tool.report.renderer import render_report


def _cfg(tmp_path, *body, argv=()):
    lines = ["url: https://x.local", "username: someone", *body]
    path = tmp_path / "config.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    args = build_parser().parse_args(["--config", str(path), *argv])
    return RunConfig.load(args)


def test_ids_come_from_the_config_file_and_the_cli(tmp_path):
    assert _cfg(tmp_path).ignore_findings == []
    assert _cfg(tmp_path, "ignore_findings: [TAG-003, DEP-002]").ignore_findings == [
        "DEP-002",
        "TAG-003",
    ]
    # Case and stray whitespace must not decide whether a finding is shown.
    assert _cfg(tmp_path, "ignore_findings: [' dep-002 ']").ignore_findings == ["DEP-002"]
    # A lone scalar is a list of one, not a list of characters.
    assert _cfg(tmp_path, "ignore_findings: TAG-003").ignore_findings == ["TAG-003"]
    # CLI flags win over the file, as everywhere else.
    cfg = _cfg(tmp_path, "ignore_findings: [TAG-003]", argv=["--ignore-finding", "DEP-002"])
    assert cfg.ignore_findings == ["DEP-002"]


def test_ignored_findings_leave_the_report_but_stay_in_the_data(sample_data, tmp_path):
    from vcf_automation_assessment_tool.checks import run_checks
    from vcf_automation_assessment_tool.flows import build_flows

    build_flows(sample_data)
    run_checks(sample_data)
    before = len(sample_data.findings)
    assert any(f.check_id == "TAG-003" for f in sample_data.findings)

    sample_data.meta["ignore_findings"] = ["TAG-003", "DEP-002"]
    out = tmp_path / "ignored.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    assert 'id="TAG-003"' not in html
    assert 'href="#TAG-003"' not in html  # nor the executive summary row
    assert 'id="DEP-002"' not in html
    assert 'id="DEP-003"' in html  # a neighbour is untouched
    # The reader is told what was withheld rather than left to notice a gap.
    assert "Ignored findings<b>DEP-002, TAG-003</b>" in html
    # Nothing was dropped from the data itself: --json still carries them.
    assert len(sample_data.findings) == before
    assert any(f.check_id == "TAG-003" for f in sample_data.findings)


def test_suppressed_findings_leave_the_severity_counts(sample_data, tmp_path):
    from vcf_automation_assessment_tool.checks import run_checks
    from vcf_automation_assessment_tool.flows import build_flows
    from vcf_automation_assessment_tool.models import Severity

    build_flows(sample_data)
    run_checks(sample_data)
    infos = sum(1 for f in sample_data.findings if f.severity is Severity.INFO)

    sample_data.meta["ignore_findings"] = ["tag-003"]  # lower case must match
    out = tmp_path / "counts.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    assert f'<div class="n">{infos - 1}</div><div class="l">Info findings' in html
    # The section rail retallies too, or it contradicts the card list under it.
    infra = html[html.index('id="infrastructure"') : html.index('id="consumption"')]
    assert "Ignored findings" not in infra  # the header row, not a section one
    assert 'id="TAG-003"' not in infra


def test_an_id_matching_nothing_changes_nothing(sample_data, tmp_path):
    from vcf_automation_assessment_tool.checks import run_checks
    from vcf_automation_assessment_tool.flows import build_flows

    build_flows(sample_data)
    run_checks(sample_data)
    sample_data.meta["ignore_findings"] = ["XYZ-999"]
    out = tmp_path / "typo.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    # No header row claiming a suppression that never happened. (The CLI warns
    # about the unmatched id; the report simply says nothing.)
    assert "Ignored findings" not in html
    assert 'id="TAG-003"' in html
