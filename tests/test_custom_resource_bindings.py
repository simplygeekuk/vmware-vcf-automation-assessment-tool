"""Custom resource bindings: read from the documented shape, confirmed against
what the run could read, shown in the design tables and checked by EXT-009."""

from vcf_automation_assessment_tool.checks.governance import (
    ext_009_custom_resource_bindings_to_missing_actions,
)
from vcf_automation_assessment_tool.collectors.vro import (
    _confirm_bindings,
    _used_by_map,
    custom_resource_bindings,
)
from vcf_automation_assessment_tool.models import AssessmentData

WF_CREATE = "11111111-0000-0000-0000-000000000001"
WF_DELETE = "11111111-0000-0000-0000-000000000002"
ABX_OK = "22222222-0000-0000-0000-000000000001"
ABX_GONE = "22222222-0000-0000-0000-000000000002"


def _data(abx_gap: bool = False) -> AssessmentData:
    data = AssessmentData()
    data.raw["blueprints"] = {
        "custom_resource_types": [
            {
                "id": "crt1",
                "displayName": "DNS Record",
                "resourceType": "Custom.DNS",
                "mainActions": {
                    "create": {"id": WF_CREATE, "name": "", "type": "vro.workflow"},
                    "delete": {"id": WF_DELETE, "name": "Delete DNS", "type": "vro.workflow"},
                },
                "additionalActions": [
                    {
                        "id": "cra-extra",
                        "displayName": "Rotate",
                        "runnableItem": {"id": ABX_GONE, "type": "abx.action"},
                    }
                ],
            }
        ],
        "custom_resource_actions": [
            {
                "id": "cra1",
                "displayName": "Snapshot",
                "resourceType": "Cloud.vSphere.Machine",
                "runnableItem": {"id": ABX_OK, "type": "abx.action"},
            }
        ],
    }
    data.raw["extensibility"] = {
        "subscriptions": [],
        "abx_actions": [{"id": ABX_OK, "name": "take-snapshot", "runtime": "python"}],
    }
    if abx_gap:
        data.record_error("extensibility", "abx_actions", "403")
    return data


def test_bindings_are_read_from_the_documented_slots():
    bindings = custom_resource_bindings(_data())
    keyed = {(b["owner"], b["action"]): b for b in bindings}
    assert set(keyed) == {
        ("DNS Record", "create"),
        ("DNS Record", "delete"),
        ("DNS Record", "day-2: Rotate"),
        ("Snapshot", "day-2"),
    }
    assert keyed[("DNS Record", "create")]["kind"] == "workflow"
    assert keyed[("DNS Record", "day-2: Rotate")]["kind"] == "abx"
    assert keyed[("Snapshot", "day-2")]["owner_kind"] == "resource action"


def test_workflow_bindings_are_definite_references_for_the_lookup():
    used = _used_by_map(_data())
    assert used[WF_CREATE] == ["custom resource: DNS Record"]
    assert used[WF_DELETE] == ["custom resource: DNS Record"]
    # An ABX binding is not a workflow candidate.
    assert ABX_GONE not in used and ABX_OK not in used


def test_confirmation_claims_only_what_was_read():
    data = _data()
    bindings = custom_resource_bindings(data)
    _confirm_bindings(data, bindings, {WF_CREATE: "Create DNS"})
    keyed = {(b["owner"], b["action"]): b for b in bindings}
    # Resolved workflow: confirmed, and named from the lookup.
    assert keyed[("DNS Record", "create")]["confirmed"] is True
    assert keyed[("DNS Record", "create")]["runnable_name"] == "Create DNS"
    # Unresolved workflow: unknown, never False, keeps the binding's own name.
    assert keyed[("DNS Record", "delete")]["confirmed"] is None
    assert keyed[("DNS Record", "delete")]["runnable_name"] == "Delete DNS"
    # ABX: the inventory is complete, so absence is a real absence.
    assert keyed[("Snapshot", "day-2")]["confirmed"] is True
    assert keyed[("Snapshot", "day-2")]["runnable_name"] == "take-snapshot"
    assert keyed[("DNS Record", "day-2: Rotate")]["confirmed"] is False


def test_an_abx_inventory_gap_withholds_the_absence_claim():
    data = _data(abx_gap=True)
    bindings = custom_resource_bindings(data)
    _confirm_bindings(data, bindings, {})
    keyed = {(b["owner"], b["action"]): b for b in bindings}
    assert keyed[("DNS Record", "day-2: Rotate")]["confirmed"] is None


def test_ext009_names_the_missing_abx_binding_and_nothing_else():
    data = _data()
    bindings = custom_resource_bindings(data)
    _confirm_bindings(data, bindings, {})
    data.raw["vro"] = {"custom_resource_bindings": bindings}
    (finding,) = ext_009_custom_resource_bindings_to_missing_actions(data)
    assert finding.check_id == "EXT-009"
    assert [(o.name, o.kind) for o in finding.affected] == [("DNS Record", "custom-resource")]
    assert "day-2: Rotate runs ABX action" in finding.affected[0].detail
    # Unconfirmed workflows are not a claim.
    assert "delete" not in finding.affected[0].detail


def test_ext009_is_silent_without_bindings():
    data = AssessmentData()
    data.raw["vro"] = {}
    assert ext_009_custom_resource_bindings_to_missing_actions(data) == []


def test_design_tables_show_what_each_step_runs(sample_data, tmp_path):
    from vcf_automation_assessment_tool.report.renderer import render_report

    data = _data()
    bindings = custom_resource_bindings(data)
    _confirm_bindings(data, bindings, {WF_CREATE: "Create DNS"})
    sample_data.raw["blueprints"].update(data.raw["blueprints"])
    sample_data.raw["vro"]["custom_resource_bindings"] = bindings
    out = tmp_path / "report.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    table = html[
        html.index("<summary>Custom Resources ") : html.index("<summary>Resource Actions ")
    ]
    assert "create: Create DNS" in table
    assert "delete: Delete DNS" in table and "not confirmed" in table
    assert "missing" in table
    actions = html[html.index("<summary>Resource Actions ") :]
    actions = actions[: actions.index("</details>")]
    assert "day-2: take-snapshot (ABX)" in actions
