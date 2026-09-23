"""Deleted-deployment sweep and opt-in request history.

The point of both is that a deployment's current status only says who is
broken now. A failure that was retried, or one somebody deleted rather than
fixed, leaves the live estate looking clean. These tests pin that the history
is read, kept apart from the live estate, and never reported as an all-time
rate when the platform prunes it.
"""

import pytest

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.collectors import deployments as collector
from vcf_automation_assessment_tool.flows import build_flows
from vcf_automation_assessment_tool.models import AssessmentData
from vcf_automation_assessment_tool.report.renderer import (
    render_report,
    request_outcome_summary,
)


class FakeClient:
    """Records every call so the deleted flag can be asserted on, not assumed."""

    def __init__(self, pages: dict):
        self.pages = pages
        self.calls: list[tuple[str, dict]] = []

    def iter_paged(self, path, params=None, page_size=None):
        self.calls.append((path, dict(params or {})))
        key = (path, (params or {}).get("deleted"))
        yield from self.pages.get(key, [])


def _dep(dep_id, name, status="CREATE_SUCCESSFUL"):
    return {
        "id": dep_id,
        "name": name,
        "status": status,
        "projectId": "p1",
        "project": {"name": "Platform"},
        "ownedBy": "alice",
        "resources": [],
    }


def _data(**meta):
    data = AssessmentData()
    data.meta = meta
    return data


def test_the_deleted_sweep_runs_without_being_asked():
    """It is one extra paged call, and without it a deleted failure is simply
    gone from the report."""
    client = FakeClient(
        {
            ("/deployment/api/deployments", "false"): [_dep("d1", "live")],
            ("/deployment/api/deployments", "true"): [_dep("d9", "gone", "DELETE_FAILED")],
        }
    )
    data = _data()
    collector.collect(client, data)

    assert [d["name"] for d in data.raw["deployments"]["deployments"]] == ["live"]
    assert [d["name"] for d in data.raw["deployments"]["deleted"]] == ["gone"]
    # Never merged: every live-estate count would otherwise include history.
    assert data.raw["deployments"]["deleted"][0]["id"] not in {
        d["id"] for d in data.raw["deployments"]["deployments"]
    }


def test_request_history_is_not_read_unless_asked_for():
    client = FakeClient({("/deployment/api/deployments", "false"): [_dep("d1", "live")]})
    data = _data()
    collector.collect(client, data)

    assert data.raw["deployments"]["request_history"] == {"collected": False}
    assert not any("requests" in path for path, _ in client.calls)


def test_a_deleted_deployment_s_history_is_asked_for_with_the_deleted_flag():
    """The plain route answers 404 for a soft-deleted deployment, which reads
    exactly like "no requests ever failed here" if the flag is forgotten."""
    client = FakeClient(
        {
            ("/deployment/api/deployments", "false"): [_dep("d1", "live")],
            ("/deployment/api/deployments", "true"): [_dep("d9", "gone", "DELETE_SUCCESSFUL")],
            ("/deployment/api/deployments/d1/requests", None): [
                {"id": "r1", "status": "SUCCESSFUL", "createdAt": "2025-03-01T00:00:00Z"}
            ],
            ("/deployment/api/deployments/d9/requests", "true"): [
                {"id": "r2", "status": "FAILED", "createdAt": "2025-01-01T00:00:00Z"}
            ],
        }
    )
    data = _data(request_history=True)
    collector.collect(client, data)

    history = data.raw["deployments"]["request_history"]
    assert history["collected"] is True
    assert {r["id"] for r in history["requests"]} == {"r1", "r2"}
    assert history["deployments_scanned"] == 2
    # The window the rate covers, taken from the data rather than assumed.
    assert history["oldest"] == "2025-01-01T00:00:00Z"

    live_call = ("/deployment/api/deployments/d1/requests", {})
    deleted_call = ("/deployment/api/deployments/d9/requests", {"deleted": "true"})
    assert live_call in client.calls
    assert deleted_call in client.calls


def test_request_payloads_are_dropped_not_stored():
    """A request's inputs are whatever the requester typed into the form, which
    on this platform can include credentials."""
    client = FakeClient(
        {
            ("/deployment/api/deployments", "false"): [_dep("d1", "live")],
            ("/deployment/api/deployments/d1/requests", None): [
                {
                    "id": "r1",
                    "status": "SUCCESSFUL",
                    "inputs": {"password": "hunter2"},
                    "outputs": {"address": "10.0.0.1"},
                }
            ],
        }
    )
    data = _data(request_history=True)
    collector.collect(client, data)

    stored = data.raw["deployments"]["request_history"]["requests"][0]
    assert "inputs" not in stored
    assert "outputs" not in stored
    assert "hunter2" not in str(data.raw["deployments"])


def test_an_unreadable_deployment_is_recorded_as_a_gap_not_as_no_failures():
    from vcf_automation_assessment_tool.client import ApiError

    class Failing(FakeClient):
        def iter_paged(self, path, params=None, page_size=None):
            if path.endswith("/requests"):
                raise ApiError("403 Forbidden", status_code=403)
            yield from super().iter_paged(path, params, page_size)

    client = Failing({("/deployment/api/deployments", "false"): [_dep("d1", "live")]})
    data = _data(request_history=True)
    collector.collect(client, data)

    assert data.raw["deployments"]["request_history"]["deployments_unread"] == 1
    assert any(e["item"] == "request history" for e in data.errors)


def test_a_deliberate_limit_is_recorded_rather_than_silently_truncating():
    """A trial run over part of the estate must not read as a whole-estate
    result: what it left out is a collection gap."""
    client = FakeClient(
        {
            ("/deployment/api/deployments", "false"): [_dep("d1", "one"), _dep("d2", "two")],
            ("/deployment/api/deployments/d1/requests", None): [
                {"id": "r1", "status": "SUCCESSFUL"}
            ],
        }
    )
    data = _data(request_history=True, request_history_limit=1)
    collector.collect(client, data)

    history = data.raw["deployments"]["request_history"]
    assert history["deployments_scanned"] == 1
    assert history["deployments_unread"] == 1
    assert any("capped" in e["error"] for e in data.errors)


def test_the_rate_counts_failures_against_requests_that_finished(sample_data):
    """A request somebody cancelled, one an approver refused, and one still
    waiting are all the platform behaving correctly. Counting any of them as a
    failure inflates the rate; counting them in the denominator deflates it."""
    summary = request_outcome_summary(sample_data.raw["deployments"]["request_history"])
    assert summary["total"] == 5
    assert summary["failed"] == 2
    # One SUCCESSFUL plus two FAILED; the ABORTED and APPROVAL_PENDING ones
    # are in neither half.
    assert summary["completed"] == 3
    assert summary["uncounted"] == 2
    assert summary["failed_pct"] == 67
    assert summary["window_from"] == "2024-11-01"


def test_every_status_stays_visible_even_when_it_is_not_in_the_rate(sample_data):
    """Excluding cancellations from the rate is not a reason to hide them."""
    summary = request_outcome_summary(sample_data.raw["deployments"]["request_history"])
    assert dict(summary["by_status"]) == {
        "SUCCESSFUL": 1,
        "FAILED": 2,
        "ABORTED": 1,
        "APPROVAL_PENDING": 1,
    }


def test_failures_are_grouped_by_what_was_requested(sample_data):
    """A single request type failing repeatedly is a defect at its source; the
    grouping is what makes that visible."""
    from vcf_automation_assessment_tool.checks.deployments import content_names

    summary = request_outcome_summary(
        sample_data.raw["deployments"]["request_history"], *content_names(sample_data)
    )
    grouped = {t["what"]: (t["failed"], t["completed"]) for t in summary["failing_targets"]}
    # A provisioning request carries no actionId, so one bucket called
    # "provisioning" would say nothing about which item is failing: the
    # catalog item name is the part somebody can act on.
    assert grouped["Web Server (build)"] == (1, 2)
    assert grouped["Deployment.PowerOff"] == (1, 1)


def test_an_unidentifiable_provisioning_request_says_so(sample_data):
    """Without a resolvable item the label admits it rather than inventing
    one - and never silently drops the row."""
    summary = request_outcome_summary(sample_data.raw["deployments"]["request_history"])
    labels = {t["what"] for t in summary["failing_targets"]}
    assert "build (item not known)" in labels


def test_a_request_that_was_not_provisioning_is_called_what_it_was():
    """Onboarding, lease expiry and API-driven updates carry no actionId and no
    item, and the platform's own name is the only thing that says which they
    were. A live estate had 1,113 of them reading as builds nobody could
    identify, 696 of those onboarding."""
    from vcf_automation_assessment_tool.checks.deployments import request_target_label

    def req(name):
        return {"name": name, "action_id": "", "catalog_item_id": "", "blueprint_id": ""}

    assert request_target_label(req("Onboard"), {}, {}) == "Onboard"
    assert request_target_label(req("Expire"), {}, {}) == "Expire"
    # "Create" is the platform's name for a provisioning request, so it adds
    # nothing the label does not already say and the item is still unknown.
    assert request_target_label(req("Create"), {}, {}) == "build (item not known)"
    assert request_target_label(req(""), {}, {}) == "build (item not known)"


def test_each_failing_target_carries_its_own_rate(sample_data):
    """Ordering is by volume, which is what a fix buys back the most of. Two
    failures out of three and two out of two thousand are different problems,
    and without the rate the reader has to divide."""
    from vcf_automation_assessment_tool.checks.deployments import content_names

    summary = request_outcome_summary(
        sample_data.raw["deployments"]["request_history"], *content_names(sample_data)
    )
    rates = {t["what"]: t["rate"] for t in summary["failing_targets"]}
    assert rates["Deployment.PowerOff"] == 100
    assert rates["Web Server (build)"] == 50


def test_no_history_is_not_a_clean_record():
    assert request_outcome_summary({"collected": False}) is None
    assert request_outcome_summary(None) is None


@pytest.fixture
def findings(sample_data):
    build_flows(sample_data)
    run_checks(sample_data)
    return sample_data.findings


def test_dep_007_reports_only_what_was_deleted_while_broken(findings):
    finding = next(f for f in findings if f.check_id == "DEP-007")
    assert [a.name for a in finding.affected] == ["half-removed"]
    assert "DELETE_FAILED" in finding.affected[0].detail


def test_dep_008_states_the_window_and_refuses_to_call_it_all_time(findings):
    finding = next(f for f in findings if f.check_id == "DEP-008")
    assert "2 of 3 completed request(s) failed (67%)" in finding.recommendation
    assert "back to 2024-11-01" in finding.recommendation
    assert "not an all-time rate" in finding.recommendation
    # The pending approval is neither a failure nor listed as one.
    assert {a.id for a in finding.affected} == {"rq2", "rq3"}
    gone = next(a for a in finding.affected if a.id == "rq3")
    assert "deployment since deleted" in gone.detail


def test_dep_008_is_silent_when_the_history_was_never_read(sample_data):
    sample_data.raw["deployments"]["request_history"] = {"collected": False}
    build_flows(sample_data)
    run_checks(sample_data)
    assert not [f for f in sample_data.findings if f.check_id == "DEP-008"]


def test_the_report_says_so_when_history_was_not_collected(sample_data, tmp_path):
    """Silence would read as "nothing failed" - the one reading the report
    cannot tell a clean estate from an unasked question."""
    sample_data.raw["deployments"]["request_history"] = {"collected": False}
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "nohistory.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    assert "Request history was not collected" in html
    assert "--request-history" in html
    assert "Request Failure Rate" not in html


def test_the_report_renders_the_outcomes_when_it_was(sample_data, tmp_path):
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "history.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    assert "Request Failure Rate" in html
    assert "Recently Deleted Deployments" in html
    assert "is from 2024-11-01" in html.replace("\r\n", "\n")
    assert "Deployment.PowerOff" in html


def test_the_backstop_is_high_enough_not_to_trim_a_real_estate():
    """It exists to stop an unbounded crawl, not to sample. An estate of a few
    thousand deployments must be read in full unless somebody asked otherwise."""
    assert collector.REQUEST_HISTORY_CAP >= 10000
