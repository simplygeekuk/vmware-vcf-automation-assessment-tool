"""ignore_sections: hide a report section without touching collection.

The predecessor, --skip, stopped a collector, which made the data incomplete
for every check that read across areas and left holes in the JSON dump. This
one is purely a rendering decision, like ignore_findings.
"""

import pytest

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.cli import build_parser
from vcf_automation_assessment_tool.config import RunConfig
from vcf_automation_assessment_tool.flows import build_flows
from vcf_automation_assessment_tool.report.renderer import render_report


def _cfg(tmp_path, *body, argv=()):
    lines = ["url: https://x.local", "username: someone", *body]
    path = tmp_path / "config.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    args = build_parser().parse_args(["--config", str(path), *argv])
    return RunConfig.load(args)


def test_sections_come_from_the_config_file_and_the_cli(tmp_path):
    assert _cfg(tmp_path).ignore_sections == []
    assert _cfg(tmp_path, "ignore_sections: [replatforming, design]").ignore_sections == [
        "design",
        "replatforming",
    ]
    assert _cfg(tmp_path, "ignore_sections: [' Design ']").ignore_sections == ["design"]
    assert _cfg(tmp_path, "ignore_sections: governance").ignore_sections == ["governance"]
    cfg = _cfg(tmp_path, "ignore_sections: [design]", argv=["--ignore-section", "governance"])
    assert cfg.ignore_sections == ["governance"]


def test_an_unknown_section_is_dropped_with_a_warning(tmp_path, caplog):
    cfg = _cfg(tmp_path, "ignore_sections: [replatforming, nonsense]")
    assert cfg.ignore_sections == ["replatforming"]
    assert "nonsense" in caplog.text


def test_the_retired_keys_say_what_replaced_them(tmp_path, caplog):
    """A config file outlives several tool versions, so a leftover skip or
    replatforming key must explain itself rather than be dropped as unknown."""
    cfg = _cfg(tmp_path, "skip: [governance]", "replatforming: true")
    assert cfg.ignore_sections == []
    assert "collection no longer skips areas" in caplog.text
    assert "always computed now" in caplog.text
    # Neither survives as an attribute anybody could branch on.
    assert not hasattr(cfg, "skip")
    assert not hasattr(cfg, "replatforming")


@pytest.mark.parametrize(
    ("section", "anchor", "gone"),
    [
        ("governance", 'id="governance"', "APR-001"),
        ("design", 'id="design"', "BLU-001"),
        ("consumption", 'id="consumption"', "DEP-001"),
    ],
)
def test_hiding_a_section_removes_its_chapter_pill_and_findings(
    sample_data, tmp_path, section, anchor, gone
):
    build_flows(sample_data)
    run_checks(sample_data)
    assert any(f.check_id == gone for f in sample_data.findings)

    sample_data.meta["ignore_sections"] = [section]
    out = tmp_path / f"hidden-{section}.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    assert anchor not in html
    assert f'href="#{section}"' not in html
    assert f'id="{gone}"' not in html  # the finding card
    assert f'href="#{gone}"' not in html  # and its executive summary row
    assert f"Hidden sections<b>{section}</b>" in html
    # The data is untouched: --json still carries everything.
    assert any(f.check_id == gone for f in sample_data.findings)
    # Neighbouring sections are unaffected.
    assert 'id="infrastructure"' in html


def test_hidden_findings_leave_the_severity_counts(sample_data, tmp_path):
    from vcf_automation_assessment_tool.models import Severity

    build_flows(sample_data)
    run_checks(sample_data)
    criticals = sum(1 for f in sample_data.findings if f.severity is Severity.CRITICAL)
    hidden_criticals = sum(
        1
        for f in sample_data.findings
        if f.severity is Severity.CRITICAL and f.check_id.startswith(("DEP-", "CAT-"))
    )
    assert hidden_criticals

    sample_data.meta["ignore_sections"] = ["consumption"]
    out = tmp_path / "counts.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    assert f'<div class="n">{criticals - hidden_criticals}</div>' in html


def test_the_cli_summary_counts_what_the_report_shows(sample_data):
    """The closing "findings: N critical..." line and the report must agree,
    so both read the same helper."""
    from vcf_automation_assessment_tool.report.renderer import visible_findings

    build_flows(sample_data)
    run_checks(sample_data)
    shown = visible_findings(sample_data.findings, ["INF-001"], ["consumption"])
    ids = {f.check_id for f in shown}
    assert "INF-001" not in ids
    assert not any(i.startswith(("DEP-", "CAT-")) for i in ids)
    assert "INF-002" in ids
