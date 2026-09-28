"""Evidence-driven capability map: rows appear only for capabilities in use."""

from vcf_automation_assessment_tool.capability_map import build_capability_map
from vcf_automation_assessment_tool.models import AssessmentData


def caps(data):
    return {r["capability"]: r for r in data.derived["capability_map"]}


def test_map_reflects_fixture_usage(sample_data):
    build_capability_map(sample_data)
    rows = caps(sample_data)

    provisioning = rows["VM & network provisioning (cloud templates)"]
    assert "3 template(s), 8 active deployment(s)" in provisioning["evidence"]
    assert "Terraform" in provisioning["recommended"]

    catalog = rows["Self-service catalog & request UX"]
    assert "3 catalog item(s)" in catalog["evidence"]

    ext = rows["Lifecycle extensibility (event subscriptions)"]
    # Built-in Quota enforcement excluded: 10 custom subs, all ABX.
    assert "10 custom subscription(s): 10 ABX, 0 Orchestrator" in ext["evidence"]

    abx = rows["ABX actions (serverless scripts)"]
    assert "6 action(s)" in abx["evidence"] and "python" in abx["evidence"]

    approvals = rows["Approvals"]
    assert "1 approval polic(ies)" in approvals["evidence"]

    leases = rows["Leases & expiry"]
    assert "terraform destroy" in leases["recommended"]

    assert "Projects (multi-tenancy, RBAC, zone assignment)" in rows
    assert "Property groups (shared configuration)" in rows
    assert "Placement (capability tags, cloud zones, profiles)" in rows
    assert "Image mappings (golden images per region)" in rows
    assert "Flavor mappings (t-shirt sizing)" in rows

    # No vRO content and no custom day-2 actions in the fixture: no rows.
    assert not any("Orchestrator workflows" in c for c in rows)
    assert not any(c.startswith("Day-2") for c in rows)


def test_map_empty_environment():
    data = AssessmentData()
    build_capability_map(data)
    assert data.derived["capability_map"] == []
