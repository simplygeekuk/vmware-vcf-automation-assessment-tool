"""Replacement planning must distinguish unknown evidence from simple content."""

import pytest

from vcf_automation_assessment_tool.capability_map import build_capability_map
from vcf_automation_assessment_tool.checks.replatforming import (
    rep_001_replatforming_matrix,
    rep_002_content_not_in_git,
)
from vcf_automation_assessment_tool.models import AssessmentData
from vcf_automation_assessment_tool.report.renderer import build_html


def assessment():
    data = AssessmentData()
    data.raw = {
        "blueprints": {
            "blueprints": [{"id": "bp", "name": "Template", "resource_types": ["Cloud.Machine"]}]
        },
        "extensibility": {"subscriptions": []},
        "deployments": {"deployments": []},
    }
    data.derived["flows"] = [
        {
            "item_id": "item",
            "item_name": "<Example>",
            "blueprint_id": "bp",
            "deployment_count": 42,
            "projects": ["Example project"],
        }
    ]
    return data


@pytest.mark.parametrize("gap", ["template", "resources", "subscriptions", "error"])
def test_missing_evidence_is_not_low(gap):
    data = assessment()
    if gap == "template":
        data.raw["blueprints"]["blueprints"] = []
    elif gap == "resources":
        data.raw["blueprints"]["blueprints"][0]["resource_types"] = []
    elif gap == "subscriptions":
        del data.raw["extensibility"]
    else:
        data.errors.append({"area": "extensibility", "item": "subscriptions"})
    finding = rep_001_replatforming_matrix(data)[0]
    assert "difficulty=NEEDS REVIEW" in finding.affected[0].detail


def test_deployment_volume_separate_from_conversion_complexity():
    data = assessment()
    data.findings = rep_001_replatforming_matrix(data)
    assert "difficulty=LOW" in data.findings[0].affected[0].detail
    html = build_html(data)
    section = html.split('id="replatforming"', 1)[1]
    assert "Associated deployments" in section and "<b>42</b>" in section
    assert "Live deployments</th>" in section
    assert "&lt;Example&gt;" in section and "<Example>" not in section
    assert "Standard infrastructure resources" in section


def test_missing_deployment_collection_does_not_report_zero():
    data = assessment()
    del data.raw["deployments"]
    data.findings = rep_001_replatforming_matrix(data)
    assert "deployments: Unknown" in data.findings[0].affected[0].detail
    html = build_html(data)
    assert "<b>Unknown</b><span>Associated deployments" in html


def test_content_source_wording_does_not_claim_no_git_copy():
    finding = rep_002_content_not_in_git(assessment())[0]
    assert finding.title == "Templates without a linked content source"
    assert "external Git copy may exist" in finding.affected[0].detail


@pytest.mark.parametrize(
    ("resource", "rating", "reason"),
    [
        ("Custom.Database", "HIGH", "Orchestrator dependency"),
        ("Unmapped.Resource", "MEDIUM", "Resource mapping needs review"),
    ],
)
def test_complexity_explains_observed_dependency(resource, rating, reason):
    data = assessment()
    data.raw["blueprints"]["blueprints"][0]["resource_types"] = [resource]
    detail = rep_001_replatforming_matrix(data)[0].affected[0].detail
    assert f"difficulty={rating}" in detail and reason in detail


def test_overview_uses_all_rows_but_respects_finding_exclusion():
    data = assessment()
    data.derived["flows"].append(
        {
            "item_id": "second",
            "item_name": "Second item",
            "deployment_count": 3,
        }
    )
    data.findings = rep_001_replatforming_matrix(data)
    data.meta["max_rows_per_finding"] = 1
    html = build_html(data)
    assert "<b>2</b><span>Catalog items assessed" in html
    assert "<b>45</b><span>Associated deployments" in html
    assert "<b>1</b><span>Needs Review" in html
    assert "1 more not shown" in html
    table = html.split('<table class="replacement">', 1)[1].split("</table>", 1)[0]
    assert "Second item" in table and "&lt;Example&gt;" not in table
    data.meta["ignore_findings"] = ["REP-001"]
    html = build_html(data)
    assert '<table class="replacement">' not in html
    assert "Catalog items assessed" not in html


def test_service_management_approvals_and_compact_map(sample_data):
    build_capability_map(sample_data)
    rows = sample_data.derived["capability_map"]
    approvals = next(row for row in rows if row["capability"] == "Approvals")
    assert "ServiceNow or a similar" in approvals["recommended"]
    assert "execution gates separately" in approvals["notes"]
    html = build_html(sample_data)
    assert "iRequest" not in html
    assert "Key migration consideration</th>" in html
    assert "<summary>Alternatives</summary>" in html
    assert "<th>Alternatives</th>" not in html
