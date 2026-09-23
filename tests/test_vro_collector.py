"""vRO collector: targeted name resolution, no inventory sweep."""

from vcf_automation_assessment_tool.client import ApiError
from vcf_automation_assessment_tool.collectors.vro import collect
from vcf_automation_assessment_tool.models import AssessmentData

WF_AD = "b1c1a70e-4514-4393-a027-ef0ea1efb29e"
WF_EXT = "c30515d4-0a1d-473b-bd65-2fe9e075e59a"
NOT_A_WF = "d2119038-1db3-48ff-afbc-7fc5308c201d"

EMBEDDED = "https://vra.example.test/vco"
EXTERNAL = "https://vro.example.test:443/vco"


class StubClient:
    base_url = "https://vra.example.test"

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, path, params=None):
        self.calls.append(path)
        if path in self.responses:
            result = self.responses[path]
            if isinstance(result, ApiError):
                raise result
            return result
        raise ApiError(f"GET {path} -> HTTP 404", status_code=404)


def make_data(sub_wf=WF_AD, custom_resource_uuids=()):
    data = AssessmentData()
    data.raw["infrastructure"] = {
        "integrations": [
            {
                "id": "int1",
                "name": "vro-external",
                "integrationType": "vro",
                "integrationProperties": {"endpoint": EXTERNAL},
            }
        ]
    }
    data.raw["extensibility"] = {
        "subscriptions": [
            {
                "id": "sub1",
                "name": "AD - Add Computer",
                "runnableType": "extensibility.vco",
                "runnableId": sub_wf,
                "runnableName": "",
                "runnableResolved": None,
                "builtin": False,
            }
        ],
    }
    data.raw["blueprints"] = {
        "custom_resource_types": [
            {"id": "crt1", "displayName": "DNS Record", "properties": list(custom_resource_uuids)}
        ],
        "custom_resource_actions": [],
    }
    return data


def probe(url):
    return f"{url}/api/workflows"


def test_targeted_resolution_across_endpoints():
    client = StubClient(
        {
            probe(EMBEDDED): {"total": 3000},
            probe(EXTERNAL): {"total": 40},
            # Not on the embedded vRO, found on the external one.
            f"{EXTERNAL}/api/workflows/{WF_AD}": {"name": "Active Directory - Add Computer"},
        }
    )
    data = make_data()
    collect(client, data)

    sub = data.raw["extensibility"]["subscriptions"][0]
    assert sub["runnableName"] == "Active Directory - Add Computer"
    assert sub["runnableResolved"] is True

    wf = data.raw["vro"]["workflows"][0]
    assert wf["resolved"] is True and wf["endpoint_source"] == "vro-external"

    totals = {e["source"]: e["workflows_total"] for e in data.raw["vro"]["endpoints"]}
    assert totals == {"embedded": 3000, "vro-external": 40}


def test_unresolved_subscription_reference_kept_and_unverified():
    client = StubClient({probe(EMBEDDED): {"total": 10}, probe(EXTERNAL): {"total": 5}})
    data = make_data()
    collect(client, data)
    wf = data.raw["vro"]["workflows"][0]
    assert wf["resolved"] is False and wf["id"] == WF_AD
    # Never claimed missing - lookups may fail for reachability reasons.
    assert data.raw["extensibility"]["subscriptions"][0]["runnableResolved"] is None


def test_junk_uuids_from_custom_resources_dropped():
    # The custom-resource UUID scan matches non-workflow ids; unresolved ones
    # with no subscription reference must not clutter the table.
    client = StubClient(
        {
            probe(EMBEDDED): {"total": 10},
            probe(EXTERNAL): {"total": 5},
            f"{EMBEDDED}/api/workflows/{WF_EXT}": {"name": "Create DNS Record"},
        }
    )
    data = make_data(custom_resource_uuids=(WF_EXT, NOT_A_WF))
    collect(client, data)
    by_id = {w["id"]: w for w in data.raw["vro"]["workflows"]}
    assert WF_EXT in by_id and by_id[WF_EXT]["resolved"]
    assert "custom resource: DNS Record" in by_id[WF_EXT]["used_by"]
    assert NOT_A_WF not in by_id  # junk dropped


def test_unreachable_endpoints_recorded_as_gaps():
    client = StubClient({})  # everything 404s
    data = make_data()
    collect(client, data)
    assert all(not e["reachable"] for e in data.raw["vro"]["endpoints"])
    assert any(e["area"] == "vro" for e in data.errors)


def action_link(aid, fqn):
    return {
        "attributes": [
            {"name": "id", "value": aid},
            {"name": "fqn", "value": fqn},
            {"name": "name", "value": fqn.rsplit("/", 1)[-1]},
        ]
    }


BAD_PY_ACTION = 'def handler(x):\n    print("http://10.1.2.3")\n    return x\n'


def test_action_inventory_analysis_and_builtin_filter():
    client = StubClient(
        {
            probe(EMBEDDED): {"total": 1},
            probe(EXTERNAL): ApiError("down", status_code=503),
            f"{EMBEDDED}/api/actions": {
                "link": [
                    action_link("a1", "com.simplygeek.ad/addComputer"),
                    action_link("a2", "com.simplygeek.dns/setRecord"),
                    action_link("a3", "com.vmware.library.ad/createComputer"),
                ],
                "total": 3,
            },
            f"{EMBEDDED}/api/actions/a1": {
                "runtime": "python:3.10",
                "script": BAD_PY_ACTION,
            },
            f"{EMBEDDED}/api/actions/a2": {
                # Classic JS action, no runtime field.
                "script": "try { x(); } catch (e) { System.error(e); }",
            },
        }
    )
    data = make_data()
    collect(client, data)
    vro = data.raw["vro"]

    # Built-in com.vmware.* excluded and counted.
    assert vro["builtin_actions_excluded"] == 1
    actions = {a["fqn"]: a for a in vro["actions"]}
    assert set(actions) == {"com.simplygeek.ad/addComputer", "com.simplygeek.dns/setRecord"}

    py = actions["com.simplygeek.ad/addComputer"]
    assert py["runtime"] == "python"
    joined = " | ".join(py["issues"])
    assert "no error handling" not in joined
    assert "10.1.2.3" in joined

    js = actions["com.simplygeek.dns/setRecord"]
    assert js["runtime"] == "javascript"
    assert js["issues"] == []  # try/catch + System.error logging

    assert vro["action_runtimes"] == {"python": 1, "javascript": 1}


def test_action_pagination_guard_when_server_ignores_start_index():
    # Server returns the same full page regardless of startIndex and no total:
    # the new-items guard must terminate the loop.
    same_page = {"link": [action_link("a1", "org.x/one")]}
    client = StubClient(
        {
            probe(EMBEDDED): {"total": 1},
            probe(EXTERNAL): ApiError("down", status_code=503),
            f"{EMBEDDED}/api/actions": same_page,
            f"{EMBEDDED}/api/actions/a1": {"script": "try{a()}catch(e){System.error(e)}"},
        }
    )
    data = make_data()
    collect(client, data)
    assert len(data.raw["vro"]["actions"]) == 1


def test_workflow_structure_and_complexity():
    from vcf_automation_assessment_tool.collectors.vro import (
        _complexity_rating,
        _workflow_structure,
    )

    content = {
        "workflow-item": [
            {"type": "task", "script": {"value": "a()"}},
            {"type": "condition"},
            {"type": "task", "linked-workflow-id": "sub-1"},
            {"type": "input"},
            {"type": "waiting-timer"},
            {"type": "end"},
        ]
    }
    structure = _workflow_structure(content)
    assert structure == {
        "items": 5,
        "scriptable_tasks": 1,
        "decisions": 1,
        "sub_workflows": 1,
        "user_interactions": 1,
        "timers": 1,
    }
    # score = 5 + 2 + 3 + 3 + 2 = 15 -> MEDIUM
    assert _complexity_rating(structure) == "MEDIUM"

    big = {**structure, "items": 20}
    assert _complexity_rating(big) == "HIGH"
    assert (
        _complexity_rating(
            {
                "items": 3,
                "scriptable_tasks": 1,
                "decisions": 0,
                "sub_workflows": 0,
                "user_interactions": 0,
                "timers": 0,
            }
        )
        == "LOW"
    )


def test_resolved_workflow_gets_structure():
    client = StubClient(
        {
            probe(EMBEDDED): {"total": 1},
            probe(EXTERNAL): ApiError("down", status_code=503),
            f"{EMBEDDED}/api/workflows/{WF_AD}": {"name": "AD Add"},
            f"{EMBEDDED}/api/workflows/{WF_AD}/content": {
                "workflow-item": [{"type": "task", "script": {"value": "x()"}}, {"type": "end"}]
            },
        }
    )
    data = make_data()
    collect(client, data)
    wf = data.raw["vro"]["workflows"][0]
    assert wf["structure"]["items"] == 1
    assert wf["complexity"] == "LOW"


def test_link_attribute_response_format_parsed():
    client = StubClient(
        {
            probe(EMBEDDED): {"total": 1},
            probe(EXTERNAL): ApiError("down", status_code=503),
            f"{EMBEDDED}/api/workflows/{WF_AD}": {
                "attributes": [{"name": "name", "value": "AD Add (attr format)"}]
            },
        }
    )
    data = make_data()
    collect(client, data)
    assert data.derived["vro_workflow_names"][WF_AD] == "AD Add (attr format)"


def test_uuid_scan_skips_ids_known_to_be_something_else():
    """The custom-resource UUID scan matches every id in the document; ids
    already inventoried as projects, items, blueprints or the resource's own
    id are never probed as workflow candidates. Unknown ids still are - a
    wasted 404 beats a missed workflow reference. Subscription runnableIds
    are definite references and never filtered."""
    from vcf_automation_assessment_tool.collectors.vro import _used_by_map
    from vcf_automation_assessment_tool.models import AssessmentData

    own_id = "aaaaaaaa-0000-0000-0000-000000000001"
    project_id = "bbbbbbbb-0000-0000-0000-000000000002"
    workflow_id = "cccccccc-0000-0000-0000-000000000003"
    sub_wf_id = "dddddddd-0000-0000-0000-000000000004"

    data = AssessmentData()
    data.derived["project_names"] = {project_id: "Platform"}
    data.raw["extensibility"] = {
        "subscriptions": [
            {
                "id": "s1",
                "name": "hook",
                "runnableType": "extensibility.vco",
                "runnableId": sub_wf_id,
            }
        ],
    }
    data.raw["blueprints"] = {
        "custom_resource_types": [
            {
                "id": own_id,
                "displayName": "MyResource",
                "projectId": project_id,
                "mainWorkflowId": workflow_id,
            }
        ],
        "custom_resource_actions": [],
    }
    used = _used_by_map(data)
    assert workflow_id in used
    assert sub_wf_id in used  # definite reference, never filtered
    assert own_id not in used
    assert project_id not in used
