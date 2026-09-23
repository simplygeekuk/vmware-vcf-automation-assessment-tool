"""Project quotas per cloud zone: the allocation table and PRJ-004/005/006.

The limits and the allocation counters come from the same IaaS ZoneAssignment
document, so the table and the findings must read them through one function -
a table calling a zone full while no finding names it, or the reverse, is the
failure this file exists to prevent.
"""

from vcf_automation_assessment_tool.checks import CHECKS
from vcf_automation_assessment_tool.checks.infrastructure import (
    prj_004_zone_limits_reached,
    prj_005_zone_limits_near,
    prj_006_projects_without_zones,
)
from vcf_automation_assessment_tool.models import AssessmentData, zone_allocations
from vcf_automation_assessment_tool.report.renderer import _zone_allocation_view


def _data(projects, zones=None, errors=()):
    data = AssessmentData()
    data.raw["infrastructure"] = {
        "projects": projects,
        "zones": zones if zones is not None else [{"id": "z1", "name": "prod-zone"}],
    }
    data.errors = [dict(e) for e in errors]
    return data


def _assignment(**kwargs):
    base = {
        "zoneId": "z1",
        "maxNumberInstances": 0,
        "allocatedInstancesCount": 0,
        "memoryLimitMB": 0,
        "allocatedMemoryMB": 0,
        "cpuLimit": 0,
        "allocatedCpu": 0,
        "storageLimitGB": 0,
        "allocatedStorageGB": 0,
    }
    base.update(kwargs)
    return base


def _project(pid="p1", name="Platform", zones=()):
    return {"id": pid, "name": name, "zones": list(zones)}


def test_a_zero_limit_is_no_limit_not_a_limit_of_zero():
    rows = zone_allocations(
        [_project(zones=[_assignment(allocatedInstancesCount=3)])], {"z1": "prod-zone"}
    )
    instances = rows[0]["limits"]["instances"]
    assert instances == {"used": 3.0, "limit": None, "ratio": None}


def test_an_unreadable_counter_is_unknown_never_zero():
    rows = zone_allocations(
        [_project(zones=[_assignment(maxNumberInstances=4, allocatedInstancesCount=None)])],
        {"z1": "prod-zone"},
    )
    instances = rows[0]["limits"]["instances"]
    assert instances["used"] is None and instances["limit"] == 4.0
    # No usage read means no share to report, and no finding either.
    assert instances["ratio"] is None
    assert (
        prj_004_zone_limits_reached(
            _data(
                [_project(zones=[_assignment(maxNumberInstances=4, allocatedInstancesCount=None)])]
            )
        )
        == []
    )


def test_a_zone_the_estate_no_longer_holds_is_labelled_not_dropped():
    rows = zone_allocations([_project(zones=[_assignment(zoneId="gone-1234-5678")])], {})
    assert rows[0]["zone"] == "(unknown zone gone-123)"


def test_the_table_shows_only_the_limits_the_estate_uses():
    data = _data(
        [
            _project(
                zones=[
                    _assignment(
                        maxNumberInstances=4,
                        allocatedInstancesCount=1,
                        memoryLimitMB=16384,
                        allocatedMemoryMB=12288,
                        allocatedStorageGB=110.5,
                    )
                ]
            )
        ]
    )
    rows, columns = _zone_allocation_view(data.raw["infrastructure"])
    # CPU is set nowhere and reports nothing: a column of blanks reads as a
    # collection failure. Storage has no limit but a real allocation, so it
    # stays and says so.
    assert [c["key"] for c in columns] == ["instances", "memory", "storage"]
    assert [c["label"] for c in columns] == ["Instances", "Memory (MB)", "Storage (GB)"]
    assert rows[0]["cells"] == [
        "1 / 4 (25%)",
        "12,288 / 16,384 MB (75%)",
        "110.5 GB used, no limit",
    ]
    assert rows[0]["pressured"] is False


def test_full_and_over_limit_cells_say_so_in_words():
    data = _data(
        [
            _project(zones=[_assignment(maxNumberInstances=6, allocatedInstancesCount=6)]),
            _project(
                "p2",
                "Apps",
                [_assignment(memoryLimitMB=16384, allocatedMemoryMB=20480)],
            ),
        ]
    )
    rows, _columns = _zone_allocation_view(data.raw["infrastructure"])
    cells = {r["project"]: r["cells"] for r in rows}
    assert "6 / 6 (full)" in cells["Platform"]
    assert "20,480 / 16,384 MB (over limit)" in cells["Apps"]
    assert all(r["pressured"] for r in rows)


def test_prj_004_names_the_quota_that_has_run_out():
    data = _data(
        [
            _project(
                zones=[
                    _assignment(
                        maxNumberInstances=4,
                        allocatedInstancesCount=4,
                        memoryLimitMB=16384,
                        allocatedMemoryMB=4096,
                    )
                ]
            )
        ]
    )
    (finding,) = prj_004_zone_limits_reached(data)
    assert finding.severity.value == "warning"
    (affected,) = finding.affected
    assert affected.name == "prod-zone" and affected.project == "Platform"
    # Only the limit that has run out is named; the memory quota with room in
    # it belongs in the table, not in a finding about being full.
    assert affected.detail == "Instances 4 of 4 (full)"


def test_a_limit_lowered_under_what_is_built_reads_as_over_not_as_an_error():
    data = _data([_project(zones=[_assignment(memoryLimitMB=16384, allocatedMemoryMB=20480)])])
    (finding,) = prj_004_zone_limits_reached(data)
    assert finding.affected[0].detail == "Memory 20,480 of 16,384 MB (over limit)"


def test_prj_005_covers_the_tight_ones_and_leaves_the_full_ones_to_prj_004():
    data = _data(
        [
            _project(zones=[_assignment(maxNumberInstances=10, allocatedInstancesCount=9)]),
            _project(
                "p2", "Apps", [_assignment(maxNumberInstances=10, allocatedInstancesCount=10)]
            ),
            _project(
                "p3", "Quiet", [_assignment(maxNumberInstances=10, allocatedInstancesCount=2)]
            ),
        ]
    )
    (near,) = prj_005_zone_limits_near(data)
    assert near.severity.value == "info"
    assert [a.project for a in near.affected] == ["Platform"]
    assert near.affected[0].detail == "Instances 9 of 10 (90%)"
    (full,) = prj_004_zone_limits_reached(data)
    assert [a.project for a in full.affected] == ["Apps"]


def test_the_table_and_the_findings_agree_on_what_is_under_pressure():
    """Whatever the table marks, a finding names - and nothing else does."""
    data = _data(
        [
            _project(zones=[_assignment(maxNumberInstances=10, allocatedInstancesCount=8)]),
            _project("p2", "Apps", [_assignment(memoryLimitMB=1024, allocatedMemoryMB=2048)]),
            _project(
                "p3", "Quiet", [_assignment(maxNumberInstances=10, allocatedInstancesCount=1)]
            ),
            _project("p4", "Free", [_assignment(allocatedInstancesCount=99)]),
        ]
    )
    rows, _columns = _zone_allocation_view(data.raw["infrastructure"])
    marked = {r["project"] for r in rows if r["pressured"]}
    reported = {
        a.project
        for finding in prj_004_zone_limits_reached(data) + prj_005_zone_limits_near(data)
        for a in finding.affected
    }
    assert marked == reported == {"Platform", "Apps"}


def test_prj_006_flags_a_project_that_can_place_nothing():
    data = _data([_project(zones=[_assignment()]), _project("p2", "Nowhere")])
    (finding,) = prj_006_projects_without_zones(data)
    assert [a.name for a in finding.affected] == ["Nowhere"]
    assert finding.affected[0].detail == "no cloud zone assigned"


def test_prj_006_stays_silent_when_the_projects_were_not_read():
    errors = [{"area": "infrastructure", "item": "projects", "error": "403"}]
    data = _data([_project("p2", "Nowhere")], errors=errors)
    assert prj_006_projects_without_zones(data) == []


def test_no_quota_pressure_means_no_finding_at_all():
    data = _data([_project(zones=[_assignment(maxNumberInstances=10, allocatedInstancesCount=1)])])
    assert prj_004_zone_limits_reached(data) == []
    assert prj_005_zone_limits_near(data) == []
    assert prj_006_projects_without_zones(data) == []


def test_the_new_checks_are_registered():
    registered = {fn.__name__ for fn in CHECKS}
    assert {
        "prj_004_zone_limits_reached",
        "prj_005_zone_limits_near",
        "prj_006_projects_without_zones",
    } <= registered
