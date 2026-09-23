"""Deployment labels must not obscure hostnames held by the IaaS inventory."""

import pytest

from vcf_automation_assessment_tool.client import ApiError
from vcf_automation_assessment_tool.collectors.deployments import collect
from vcf_automation_assessment_tool.models import AssessmentData
from vcf_automation_assessment_tool.report.renderer import build_html


class Client:
    def __init__(self, machines=(), hostname=""):
        self.machines = machines
        self.hostname = hostname
        self.lookups = []

    def iter_paged(self, path, params=None, page_size=None):
        if params.get("deleted") == "false":
            yield {
                "id": "deployment-1",
                "name": "AAP Controller",
                "projectId": "p1",
                "resources": [
                    {
                        "id": "machine-1",
                        "name": "Cloud_Machine_1[0]",
                        "type": "Cloud.Machine",
                        "properties": {"hostname": self.hostname, "address": "192.0.2.9"},
                    }
                ],
            }

    def iter_odata(self, path):
        self.lookups.append(path)
        for machine in self.machines:
            if isinstance(machine, ApiError):
                raise machine
            yield machine


def test_missing_embedded_hostname_is_resolved_and_rendered():
    client = Client(
        [{"id": "machine-1", "hostname": "aap-controller-01", "deploymentId": "deployment-1"}]
    )
    data = AssessmentData()
    collect(client, data)
    html = build_html(data)
    table = html.split('id="machines-by-project"', 1)[1].split("</table>", 1)[0]
    assert "<td>aap-controller-01</td>" in table
    assert "Cloud_Machine_1[0]" not in table
    assert client.lookups == ["/iaas/api/machines"]


@pytest.mark.parametrize(
    "machine",
    [
        {"id": "different", "hostname": "wrong-host", "address": "192.0.2.9"},
        {"id": "machine-1", "hostname": "wrong-host", "deploymentId": "different"},
        {"id": "machine-1", "hostname": None},
    ],
)
def test_no_hostname_guessed_from_ip_name_or_other_deployment(machine):
    data = AssessmentData()
    collect(Client([machine]), data)
    assert data.raw["deployments"]["deployments"][0]["resources"][0]["hostname"] == ""


def test_existing_hostname_needs_no_inventory_lookup():
    client = Client(hostname="known-host")
    data = AssessmentData()
    collect(client, data)
    assert client.lookups == []
    assert data.raw["deployments"]["deployments"][0]["resources"][0]["hostname"] == "known-host"


def test_failed_inventory_page_retains_resolved_names_and_records_gap():
    client = Client(
        [{"id": "machine-1", "hostname": "known-host"}, ApiError("Forbidden", status_code=403)]
    )
    data = AssessmentData()
    collect(client, data)
    assert data.raw["deployments"]["deployments"][0]["resources"][0]["hostname"] == "known-host"
    assert data.errors[0]["item"] == "machine hostnames"
