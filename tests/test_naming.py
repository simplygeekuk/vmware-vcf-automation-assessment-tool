"""Naming inventory: configured evidence, collection gaps and observed examples."""

import pytest

from vcf_automation_assessment_tool.client import ApiError
from vcf_automation_assessment_tool.collectors.infrastructure import _naming_profiles
from vcf_automation_assessment_tool.models import AssessmentData
from vcf_automation_assessment_tool.redaction import Redactor
from vcf_automation_assessment_tool.report.naming import naming_inventory
from vcf_automation_assessment_tool.report.renderer import build_html


def naming_data():
    data = AssessmentData()
    data.raw = {
        "infrastructure": {
            "projects": [
                {"id": "p1", "name": "Engineering", "machineNamingTemplate": "old-${###}"},
                {"id": "p2", "name": "Finance"},
            ],
            "naming_profiles": [
                {
                    "id": "n1",
                    "name": "Production names",
                    "details_collected": True,
                    "projects": [{"projectId": "p1", "active": False}],
                    "templates": [
                        {
                            "resourceType": "COMPUTE",
                            "pattern": "app-${resource.env}-${###}",
                            "startCounter": 0,
                            "incrementStep": 1,
                            "counters": [{"projectId": "p1", "currentCounter": 0, "active": True}],
                        }
                    ],
                }
            ],
        },
        "deployments": {
            "deployments": [
                {
                    "projectId": "p1",
                    "resources": [
                        {
                            "type": "Cloud.Machine",
                            "name": "Blueprint_label",
                            "hostname": "app-prod-001.example.test",
                        },
                        {"type": "Cloud.Network", "hostname": "not-a-machine"},
                    ],
                }
            ]
        },
    }
    return data


def test_inventory_keeps_both_sources_and_unknown_projects():
    view = naming_inventory(naming_data())
    assert view["complete"]
    assert len(view["rows"]) == 3
    profile = next(r for r in view["rows"] if r["profile"])
    assert profile["examples"] == ["app-prod-001.example.test"]
    assert "Assignment active: False" in profile["details"]
    assert "Start counter: 0" in profile["details"]
    assert "Counter (Engineering): 0; active: True" in profile["details"]
    assert "Referenced expressions: resource.env" in profile["details"]
    assert view["rows"][-1]["source"] == "Not determined"


def test_missing_collection_and_failed_collection_are_not_empty_success():
    data = naming_data()
    del data.raw["infrastructure"]["naming_profiles"]
    assert not naming_inventory(data)["complete"]
    data.raw["infrastructure"]["naming_profiles"] = []
    assert naming_inventory(data)["complete"]
    data.record_error("infrastructure", "naming_profiles", "Forbidden")
    assert not naming_inventory(data)["complete"]


def test_hostname_absence_is_distinct_from_no_machines():
    data = naming_data()
    del data.raw["deployments"]["deployments"][0]["resources"][0]["hostname"]
    view = naming_inventory(data)
    assert view["hostnames_missing"]
    assert view["rows"][0]["example_status"] == "Collected machines without hostnames: 1"
    assert view["rows"][-1]["example_status"] == "No machines collected for this project"
    html = build_html(data)
    assert "Machines were collected, but none supplied a hostname" in html
    del data.raw["deployments"]
    assert naming_inventory(data)["rows"][0]["example_status"] == "Deployment data not collected"


def test_unassigned_profile_and_project_scope():
    data = naming_data()
    data.raw["infrastructure"]["naming_profiles"][0]["projects"] = [{"defaultOrg": True}]
    assert naming_inventory(data)["rows"][-1]["project"] == "Organisation default"
    data.meta["projects_filter"] = ["Finance"]
    rows = naming_inventory(data)["rows"]
    assert len(rows) == 1 and rows[0]["project"] == "Finance"
    assert rows[0]["source"] == "Not determined"


def test_naming_html_escapes_patterns_and_preserves_redaction():
    data = naming_data()
    data.raw["infrastructure"]["projects"][0]["machineNamingTemplate"] = "<script>${###}"
    html = build_html(data)
    assert "&lt;script&gt;${###}" in html
    assert "Blueprint_label" not in html.split('id="naming-conventions"')[1].split("</table>")[0]
    redactor = Redactor(classes=("names", "hosts", "ids"))
    redactor.learn(data)
    html = build_html(redactor.redact(data))
    assert "Production names" not in html and "Engineering" not in html
    assert "app-prod-001.example.test" not in html


class NamingClient:
    iaas_api_version = "2021-07-15"

    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def iter_odata(self, path):
        assert path == "/iaas/api/naming"
        if self.error == "list":
            raise ApiError("Forbidden", status_code=403)
        return iter([{"id": "n1", "name": "Profile", "projects": [{"projectId": "p1"}]}])

    def get(self, path, params):
        self.calls.append((path, params))
        if self.error == "detail":
            raise ApiError("Not found", status_code=404)
        return {"templates": [{"pattern": "vm-${###}"}]}


def test_collector_reads_details_with_version():
    data = AssessmentData()
    client = NamingClient()
    profiles = _naming_profiles(client, data)
    assert profiles[0]["templates"][0]["pattern"] == "vm-${###}"
    assert profiles[0]["projects"] == [{"projectId": "p1"}]
    assert client.calls == [("/iaas/api/naming/n1", {"apiVersion": "2021-07-15"})]
    assert not data.errors


@pytest.mark.parametrize("error", ["list", "detail"])
def test_collector_retains_partial_evidence_and_records_gaps(error):
    data = AssessmentData()
    profiles = _naming_profiles(NamingClient(error), data)
    assert data.errors[0]["item"] == "naming_profiles"
    if error == "detail":
        assert profiles[0]["projects"] == [{"projectId": "p1"}]
        assert profiles[0]["details_collected"] is False
    else:
        assert profiles == []
