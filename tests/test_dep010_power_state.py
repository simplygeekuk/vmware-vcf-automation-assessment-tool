"""Power state on a failed deployment's machines (DEP-010).

The state lives in the deployment resource's free-form `properties` map, under
the IaaS Machine document's own spelling. Two rules matter more than the
reading itself: a machine that reports nothing is never called off, and a
deployment that failed without building anything is DEP-001's alone.
"""

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.checks.deployments import (
    dep_010_failed_with_machines,
    power_state,
    power_words,
)
from vcf_automation_assessment_tool.collectors.deployments import _slim_resource
from vcf_automation_assessment_tool.models import AssessmentData, Severity


def _data(deployments):
    data = AssessmentData()
    data.raw["deployments"] = {"deployments": deployments, "deleted": []}
    return data


def _dep(name, status, resources):
    return {
        "id": name,
        "name": name,
        "status": status,
        "projectId": "p1",
        "projectName": "Platform",
        "lastUpdatedAt": "2026-08-01T00:00:00Z",
        "resources": resources,
    }


def _machine(name, power=None, sync="SYNCED"):
    res = {"id": name, "name": name, "type": "Cloud.vSphere.Machine", "syncStatus": sync}
    if power is not None:
        res["powerState"] = power
    return res


def test_the_collector_keeps_the_power_state_out_of_the_properties_map():
    slimmed = _slim_resource(
        {
            "id": "r1",
            "name": "vm-1",
            "type": "Cloud.vSphere.Machine",
            "properties": {"powerState": "ON", "address": "10.0.0.1", "cpuCount": 2},
        }
    )
    assert slimmed["powerState"] == "ON"
    assert slimmed["address"] == "10.0.0.1"
    # Only the fields the IaaS Machine schema documents are lifted out of the
    # provider document. The rest stays out: it is bulk, and some of it is
    # estate detail the report has no use for.
    assert "properties" not in slimmed and "cpuCount" not in slimmed


def test_a_resource_with_no_properties_reports_no_power_state():
    assert _slim_resource({"id": "r1", "name": "d1", "type": "Cloud.Volume"})["powerState"] == ""
    assert _slim_resource({"properties": None})["powerState"] == ""
    # A build that returns properties as something other than a map must not
    # take the collector down with it.
    assert _slim_resource({"properties": ["unexpected"]})["powerState"] == ""


def test_an_unreported_power_state_is_never_read_as_powered_off():
    assert power_state(_machine("vm-1")) == ""
    assert power_words("") == "no power state reported"
    assert power_words("OFF") == "powered off"
    # An enum value this build adds is printed as it arrived, not guessed at.
    assert power_words("PAUSED") == "paused"


def test_only_failed_deployments_that_hold_machines_are_reported():
    data = _data(
        [
            _dep("healthy", "CREATE_SUCCESSFUL", [_machine("vm-ok", "ON")]),
            _dep("failed-empty", "CREATE_FAILED", []),
            _dep("failed-network", "CREATE_FAILED", [{"name": "net", "type": "Cloud.Network"}]),
            _dep("failed-machine", "DELETE_FAILED", [_machine("vm-live", "ON")]),
        ]
    )
    finding = dep_010_failed_with_machines(data)[0]
    assert finding.severity is Severity.WARNING
    assert [a.name for a in finding.affected] == ["failed-machine"]
    assert "1 machine, powered on: vm-live" in finding.affected[0].detail


def test_the_deployments_still_running_machines_sort_to_the_top():
    data = _data(
        [
            _dep("one-on", "CREATE_FAILED", [_machine("a", "ON"), _machine("b", "OFF")]),
            _dep("none-on", "CREATE_FAILED", [_machine("c", "OFF"), _machine("d", "OFF")]),
            _dep("two-on", "CREATE_FAILED", [_machine("e", "ON"), _machine("f", "ON")]),
        ]
    )
    finding = dep_010_failed_with_machines(data)[0]
    assert [a.name for a in finding.affected] == ["two-on", "one-on", "none-on"]
    assert "3 of those machines are powered on" in finding.recommendation
    # Nothing was unreported here, so the report makes no excuse for itself.
    assert "no power state" not in finding.recommendation


def test_the_recommendation_says_how_many_machines_report_nothing():
    data = _data([_dep("half-built", "CREATE_FAILED", [_machine("a", "ON"), _machine("b")])])
    finding = dep_010_failed_with_machines(data)[0]
    assert (
        "One of the machines in these deployments carries no power state" in finding.recommendation
    )
    detail = finding.affected[0].detail
    assert "2 machines" in detail
    assert "powered on (1): a" in detail
    assert "no power state reported (1): b" in detail


def test_a_build_specific_failed_status_still_counts():
    data = _data([_dep("odd", "ROLLBACK_FAILED", [_machine("a", "SUSPEND")])])
    finding = dep_010_failed_with_machines(data)[0]
    assert "1 machine, suspended: a" in finding.affected[0].detail


def test_nothing_is_reported_when_no_failure_holds_a_machine():
    assert dep_010_failed_with_machines(_data([_dep("ok", "CREATE_SUCCESSFUL", [])])) == []


def test_the_check_is_registered_in_the_run(sample_data):
    run_checks(sample_data)
    assert any(f.check_id == "DEP-010" for f in sample_data.findings)


def test_every_machine_is_listed_however_many_the_deployment_holds():
    """No per-deployment cap: this is a work list, and a machine left off it is
    a machine nobody switches off."""
    machines = [_machine(f"vm-{n:02d}", "ON" if n % 2 else "OFF") for n in range(13)]
    data = _data([_dep("big-stack", "CREATE_FAILED", machines)])
    detail = dep_010_failed_with_machines(data)[0].affected[0].detail
    assert "13 machines" in detail
    assert all(m["name"] in detail for m in machines)
    assert "more)" not in detail


def test_a_machine_missing_from_the_endpoint_is_not_counted_as_held():
    """A machine deleted straight in vCenter holds no capacity, so it is not
    part of this work list however its deployment reads. DEP-003 has it."""
    data = _data(
        [
            _dep(
                "part-gone",
                "CREATE_FAILED",
                [_machine("a", "ON"), _machine("b", "ON", sync="MISSING")],
            )
        ]
    )
    finding = dep_010_failed_with_machines(data)[0]
    detail = finding.affected[0].detail
    assert "1 machine, powered on: a" in detail
    assert "b" not in detail.splitlines()[1]
    assert "1 more machine here no longer exists on the endpoint (see DEP-003)" in detail
    # Only the machine that still exists counts towards the running total.
    assert "1 of those machines is powered on" in finding.recommendation


def test_a_deployment_whose_machines_have_all_gone_is_not_listed():
    data = _data(
        [
            _dep("all-gone", "CREATE_FAILED", [_machine("a", "ON", sync="MISSING")]),
            _dep("still-here", "CREATE_FAILED", [_machine("b", "ON")]),
        ]
    )
    finding = dep_010_failed_with_machines(data)[0]
    assert [a.name for a in finding.affected] == ["still-here"]


def test_an_update_that_failed_is_not_a_stranded_build():
    """The machines under an UPDATE_FAILED deployment were built by an earlier
    successful request and are most likely still in service, so the work is on
    the change. DEP-001 still counts it."""
    data = _data(
        [
            _dep("changed", "UPDATE_FAILED", [_machine("a", "ON")]),
            _dep("built", "CREATE_FAILED", [_machine("b", "ON")]),
        ]
    )
    finding = dep_010_failed_with_machines(data)[0]
    assert [a.name for a in finding.affected] == ["built"]
    assert "1 of those machines is powered on" in finding.recommendation


def test_dep_010_is_a_subset_of_dep_001():
    """DEP-010's recommendation tells the reader "every deployment here is
    also counted by DEP-001". That only stays true while one function decides
    what failed, so the two checks are bound here rather than to two copies of
    the same expression - with the one documented narrowing on top of it."""
    from vcf_automation_assessment_tool.checks.deployments import (
        dep_001_failed,
        dep_010_failed_with_machines,
    )

    statuses = [
        "CREATE_SUCCESSFUL",
        "CREATE_FAILED",
        "DELETE_FAILED",
        "ABORTED",
        # A status no released build spells today: the suffix test is what
        # stops an unrecognised state reading as healthy.
        "ROLLBACK_FAILED",
        "UPDATE_INPROGRESS",
        "UPDATE_FAILED",
    ]
    data = _data([_dep(status, status, [_machine(f"vm-{status}", "ON")]) for status in statuses])

    dep001 = {obj.id for obj in dep_001_failed(data)[0].affected}
    dep010 = {obj.id for obj in dep_010_failed_with_machines(data)[0].affected}
    assert dep010 < dep001
    assert dep001 - dep010 == {"UPDATE_FAILED"}
    assert "CREATE_SUCCESSFUL" not in dep001
    assert "ROLLBACK_FAILED" in dep010


def test_a_deployment_with_no_status_is_not_read_as_failed():
    from vcf_automation_assessment_tool.checks.deployments import dep_001_failed

    data = _data([_dep("nameless", None, [_machine("vm1", "ON")])])
    assert dep_001_failed(data) == []
