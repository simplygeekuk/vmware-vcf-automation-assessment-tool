"""Regression coverage for evidence, comparison and decision-focused reports."""

from copy import deepcopy

import pytest

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.comparison import compare_runs
from vcf_automation_assessment_tool.coverage import AREA_LABELS, coverage_rows
from vcf_automation_assessment_tool.models import AffectedObject, AssessmentData, Finding, Severity
from vcf_automation_assessment_tool.report.insights import finding_insight
from vcf_automation_assessment_tool.report.renderer import build_html


def snapshots(check_id="CAT-001"):
    before = AssessmentData(
        meta={"url": "https://example.test", "assessment_ruleset": "known-rules"},
        raw={area: {} for area in AREA_LABELS},
        findings=[
            Finding(
                check_id,
                "Review an object",
                Severity.WARNING,
                "Review its use.",
                [AffectedObject("item", "one", "Example")],
            )
        ],
    )
    before.raw["catalog"] = {"items": [{"id": "one"}]}
    before.raw["deployments"] = {"deployments": []}
    current = deepcopy(before)
    current.findings = []
    return before, current


@pytest.mark.parametrize("failed_run", ["previous", "current"])
@pytest.mark.parametrize("area", ["catalog", "deployments", "checks", "analysis"])
def test_collection_or_analysis_gap_never_becomes_resolved(failed_run, area):
    before, current = snapshots()
    target = before if failed_run == "previous" else current
    target.record_error(area, "items", "Permission denied")
    result = compare_runs(current, before.to_json_dict())
    row = result["findings"][0]
    assert row["status"] == "unable_to_reassess"
    assert row["reasons"]
    assert row["resolved_names"] == []
    assert result["summary"]["resolved"] == result["summary"]["objects_resolved"] == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("url", "https://other.test"),
        ("projects_filter", ["Production"]),
        ("pedantic", True),
        ("request_history", True),
        ("request_history_limit", 1),
        ("group_membership", False),
        ("powershell_parser", True),
        ("javascript_parser", True),
        ("assessment_ruleset", "different-rules"),
    ],
)
def test_changed_assessment_settings_do_not_imply_resolution(field, value):
    before, current = snapshots()
    current.meta[field] = value
    result = compare_runs(current, before.to_json_dict())
    assert result["findings"][0]["status"] == "unable_to_reassess"
    assert result["summary"]["objects_resolved"] == 0
    if field in {"url", "projects_filter"}:
        assert result["inventory"] == []


def test_old_dump_requires_a_new_baseline():
    before, current = snapshots()
    before.meta.pop("assessment_ruleset")
    row = compare_runs(current, before.to_json_dict())["findings"][0]
    assert row["status"] == "unable_to_reassess"
    assert any("new baseline" in reason for reason in row["reasons"])


def test_equivalent_project_order_is_comparable():
    before, current = snapshots()
    before.meta["projects_filter"] = ["A", "B"]
    current.meta["projects_filter"] = ["B", "A"]
    assert compare_runs(current, before.to_json_dict())["findings"][0]["status"] == "resolved"


@pytest.mark.parametrize("mutation", ["missing", "limited"])
def test_missing_collection_and_limited_visibility_are_unknown(mutation):
    before, current = snapshots()
    if mutation == "missing":
        del current.raw["catalog"]
    else:
        current.raw["catalog"]["admin_scope"] = False
    result = compare_runs(current, before.to_json_dict())
    assert result["findings"][0]["status"] == "unable_to_reassess"
    assert not any(row["label"] == "Catalog items" for row in result["inventory"])


def test_severity_change_is_visible_without_object_changes():
    before, current = snapshots()
    current.findings = deepcopy(before.findings)
    current.findings[0].severity = Severity.CRITICAL
    result = compare_runs(current, before.to_json_dict())
    assert result["findings"][0]["status"] == "changed"


def test_restored_collection_can_resolve_the_collection_gap_finding():
    before, current = snapshots("SYS-001")
    before.record_error("catalog", "items", "403")
    assert compare_runs(current, before.to_json_dict())["findings"][0]["status"] == "resolved"


@pytest.mark.parametrize(
    "check_id,area,key",
    [
        ("DEP-008", "deployments", "request_history"),
        ("EXT-006", "extensibility", "abx_run_evidence"),
    ],
)
def test_optional_history_must_be_complete_for_comparison(check_id, area, key):
    before, current = snapshots(check_id)
    before.raw[area][key] = {"collected": True, "complete": True}
    current.raw[area][key] = {"collected": False}
    assert (
        compare_runs(current, before.to_json_dict())["findings"][0]["status"]
        == "unable_to_reassess"
    )


def test_coverage_distinguishes_empty_partial_unavailable_and_not_assessed():
    data = AssessmentData(
        raw={
            "catalog": {"items": []},
            "blueprints": {"blueprints": []},
            "infrastructure": {"projects": [{"id": "one"}]},
        }
    )
    data.record_error("blueprints", "blueprints", "403")
    data.record_error("infrastructure", "zones", "403")
    rows = {r["area"]: r for r in coverage_rows(data)}
    assert rows["catalog"]["status"] == "Collected"
    assert rows["infrastructure"]["status"] == "Partial"
    assert rows["blueprints"]["status"] == "Unavailable"
    assert rows["deployments"]["status"] == "Not assessed"
    assert rows["request_history"]["status"] == "Not assessed"
    assert "DEP" in rows["identity"]["checks"]


def test_coverage_includes_limitations_without_api_errors():
    data = AssessmentData(
        raw={
            "identity": {"collected": True, "unresolved": [{"principal": "unknown"}]},
            "catalog": {"items": [], "admin_scope": False},
            "deployments": {"request_history": {"collected": True, "deployments_unread": 2}},
            "vro": {"workflows": [{"resolved": False}]},
        }
    )
    rows = {r["area"]: r for r in coverage_rows(data)}
    for area in ("identity", "catalog", "request_history", "vro"):
        assert rows[area]["status"] == "Partial"


def test_priorities_do_not_reduce_provisioning_blockers_to_cleanup():
    unused = snapshots()[0].findings[0]
    quota = Finding("PRJ-004", "Quota reached", Severity.WARNING, "Review the quota.")
    findings = [unused, quota]
    insights = {f.check_id: finding_insight(f) for f in findings}
    assert insights[quota.check_id]["priority"] == "Investigate first"
    assert insights[unused.check_id]["evidence"] == "Review candidate"


def test_filtered_comparison_and_summary_match_displayed_findings(sample_data):
    run_checks(sample_data)
    before = sample_data.to_json_dict()
    before["findings"] = []
    sample_data.derived["comparison"] = compare_runs(sample_data, before)
    sample_data.meta["ignore_findings"] = ["DEP-001"]
    sample_data.meta["ignore_sections"] = ["replatforming"]
    html = build_html(sample_data)
    summary = html[html.index('<details class="sec" id="summary"') : html.index('id="coverage"')]
    assert 'href="#DEP-001"' not in summary
    assert "REP-001" not in summary and "REP-002" not in summary
    assert "Why it matters:" in html and "Verify:" in html
    assert "<h2>Summary</h2>" in summary
    assert "Executive Summary" not in html
    assert "Recommended actions" not in html
    assert "section-overview" not in html
    assert summary.index('class="estate"') < summary.index('class="tiles"')
    assert summary.index('class="tiles"') < summary.index("Severity describes the concern")
    assert "Never ordered" not in html and "Critical - broken today" not in html


def test_coverage_link_remains_valid_when_system_finding_is_suppressed(sample_data):
    sample_data.record_error("catalog", "items", "403")
    run_checks(sample_data)
    sample_data.meta["ignore_findings"] = ["SYS-001"]
    html = build_html(sample_data)
    assert 'href="#SYS-001"' not in html
    assert 'href="#coverage"' in html and 'id="coverage"' in html
    assert '<details class="sec" id="coverage" open>' in html
    assert "<summary><h2>Assessment Coverage</h2></summary>" in html
