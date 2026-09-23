"""Infrastructure collection: zone membership, and the project constraints
that reach the capability tag map."""

from vcf_automation_assessment_tool.client import ApiError
from vcf_automation_assessment_tool.collectors.infrastructure import (
    _build_capability_tag_map,
    _zone_computes,
)
from vcf_automation_assessment_tool.models import AssessmentData


class StubClient:
    """iter_odata per path, so the paging itself stays the client's business."""

    def __init__(self, pages):
        self.pages = pages  # path -> list of documents, or an ApiError
        self.paths = []

    def iter_odata(self, path, params=None):
        self.paths.append(path)
        result = self.pages.get(path)
        if isinstance(result, ApiError):
            raise result
        return iter(result or [])


ZONES = [{"id": "z1", "name": "prod-zone"}, {"id": "z2", "name": "test-zone"}]


def test_each_zone_keeps_the_computes_in_it():
    client = StubClient(
        {
            "/iaas/api/zones/z1/computes": [{"id": "fc1"}, {"id": "fc2"}],
            "/iaas/api/zones/z2/computes": [{"id": "fc3"}],
        }
    )
    data = AssessmentData()
    membership, counts = _zone_computes(client, data, ZONES)
    assert membership == {"z1": ["fc1", "fc2"], "z2": ["fc3"]}
    assert counts == {"z1": 2, "z2": 1}
    # Paged, not a single $top=1 count: the membership is the point now.
    assert client.paths == ["/iaas/api/zones/z1/computes", "/iaas/api/zones/z2/computes"]
    assert data.errors == []


def test_one_unreadable_zone_does_not_lose_the_others():
    """And it is absent rather than empty. A zone with no computes is a
    finding, so a failed read must not read as one."""
    client = StubClient(
        {
            "/iaas/api/zones/z1/computes": ApiError("GET ... -> HTTP 403", status_code=403),
            "/iaas/api/zones/z2/computes": [{"id": "fc3"}],
        }
    )
    data = AssessmentData()
    membership, counts = _zone_computes(client, data, ZONES)
    assert membership == {"z2": ["fc3"]}
    assert "z1" not in counts
    assert [e["item"] for e in data.errors] == ["zone-computes:prod-zone"]


def test_a_compute_with_no_id_is_counted_but_not_named():
    client = StubClient({"/iaas/api/zones/z1/computes": [{"id": "fc1"}, {"name": "no id"}]})
    data = AssessmentData()
    membership, counts = _zone_computes(client, data, [ZONES[0]])
    assert membership == {"z1": ["fc1"]}
    assert counts == {"z1": 2}


def test_project_constraints_reach_the_map_with_what_they_constrain():
    """The type decides whether a project constraint bears on placement at
    all, so it travels with the entry rather than being re-read later."""
    tag_map = _build_capability_tag_map(
        {
            "projects": [
                {
                    "id": "p1",
                    "name": "Platform",
                    "constraints": {
                        "extensibility": [{"expression": "ca:sigma", "mandatory": True}],
                        "network": [{"expression": "net:dmz:soft", "mandatory": True}],
                    },
                }
            ]
        }
    )
    assert tag_map["ca:sigma"] == [
        {
            "kind": "project",
            "id": "p1",
            "name": "Platform",
            "via": "extensibility constraint",
            "constraint_type": "extensibility",
            "hard": True,
            "negated": False,
        }
    ]
    (dmz,) = tag_map["net:dmz"]
    assert (dmz["constraint_type"], dmz["hard"]) == ("network", False)


def test_a_constraint_object_does_not_become_a_tag_called_conditions():
    """The documented shape is an object holding conditions[]. Reading its
    keys as constraints invents a capability tag from the field name."""
    tag_map = _build_capability_tag_map(
        {
            "projects": [
                {
                    "id": "p1",
                    "name": "Platform",
                    "constraints": {
                        "network": {
                            "conditions": [
                                {
                                    "type": "TAG",
                                    "enforcement": "HARD",
                                    "expression": {"key": "net", "value": "dmz"},
                                }
                            ]
                        }
                    },
                }
            ]
        }
    )
    assert "conditions" not in tag_map
    assert [u["constraint_type"] for u in tag_map["net:dmz"]] == ["network"]
