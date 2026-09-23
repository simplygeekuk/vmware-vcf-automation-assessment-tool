"""Extensibility collector semantics (subscription runnable resolution - only
claim 'missing' on real evidence - and ABX run evidence), plus the governance
collector's policy-definition backfill."""

from vcf_automation_assessment_tool.client import ApiError
from vcf_automation_assessment_tool.collectors.extensibility import (
    _analyze_subscription,
    _is_builtin,
)
from vcf_automation_assessment_tool.collectors.governance import _ensure_policy_definitions
from vcf_automation_assessment_tool.models import AssessmentData


class StubClient:
    def __init__(self, responses):
        self.responses = responses  # path -> dict | ApiError

    def get(self, path, params=None):
        result = self.responses.get(path)
        if isinstance(result, ApiError):
            raise result
        if result is None:
            raise ApiError(f"GET {path} -> HTTP 404", status_code=404)
        return result


ABX_ACTIONS = [{"id": "abx1", "name": "register-cmdb", "selfLink": "/abx/abx1"}]


def sub(runnable_type, runnable_id):
    return {
        "id": "s1",
        "name": "test-sub",
        "eventTopicId": "compute.provision.post",
        "runnableType": runnable_type,
        "runnableId": runnable_id,
        "blocking": False,
        "disabled": False,
        "criteria": "",
    }


def test_abx_found():
    entry = _analyze_subscription(
        sub("extensibility.abx", "abx1"), ABX_ACTIONS, StubClient({}), AssessmentData()
    )
    assert entry["runnableResolved"] is True
    assert entry["runnableName"] == "register-cmdb"


def test_abx_missing_with_evidence():
    entry = _analyze_subscription(
        sub("extensibility.abx", "abx-gone"), ABX_ACTIONS, StubClient({}), AssessmentData()
    )
    assert entry["runnableResolved"] is False


def test_abx_unknown_when_actions_list_empty():
    # Empty ABX list means collection failed/limited: absence proves nothing.
    entry = _analyze_subscription(
        sub("extensibility.abx", "abx-gone"), [], StubClient({}), AssessmentData()
    )
    assert entry["runnableResolved"] is None


def test_vro_resolved_via_embedded_api():
    client = StubClient({"/vco/api/workflows/wf1": {"name": "AD - Add Computer"}})
    entry = _analyze_subscription(
        sub("extensibility.vro", "wf1"), ABX_ACTIONS, client, AssessmentData()
    )
    assert entry["runnableResolved"] is True
    assert entry["runnableName"] == "AD - Add Computer"


def test_vro_404_is_unverified_not_missing():
    # External vRO endpoints and vRO ACL hiding both return 404 from the
    # embedded API - a working subscription must not be reported missing.
    client = StubClient({})  # every path 404s
    entry = _analyze_subscription(
        sub("extensibility.vro", "wf-external"), ABX_ACTIONS, client, AssessmentData()
    )
    assert entry["runnableResolved"] is None


def test_vro_5xx_recorded_as_gap_not_missing():
    data = AssessmentData()
    client = StubClient({"/vco/api/workflows/wf1": ApiError("boom", status_code=503)})
    entry = _analyze_subscription(sub("extensibility.vco", "wf1"), ABX_ACTIONS, client, data)
    assert entry["runnableResolved"] is None
    assert data.errors  # surfaced in SYS-001 instead


def test_criteria_parsing_quote_and_list_forms():
    base = {
        "id": "s1",
        "name": "s",
        "eventTopicId": "compute.provision.pre",
        "runnableType": "extensibility.abx",
        "runnableId": "abx1",
    }
    uuid = "b1c1a70e-4514-4393-a027-ef0ea1efb29e"

    single = _analyze_subscription(
        {**base, "criteria": f"event.data.blueprintId == '{uuid}'"},
        ABX_ACTIONS,
        StubClient({}),
        AssessmentData(),
    )
    assert single["scope"] == "blueprint" and single["criteria_blueprint_ids"] == [uuid]

    double = _analyze_subscription(
        {**base, "criteria": f'event.data.blueprintId == "{uuid}"'},
        ABX_ACTIONS,
        StubClient({}),
        AssessmentData(),
    )
    assert double["scope"] == "blueprint" and double["criteria_blueprint_ids"] == [uuid]

    in_list = _analyze_subscription(
        {**base, "criteria": f"event.data.projectId in ['{uuid}', 'other']"},
        ABX_ACTIONS,
        StubClient({}),
        AssessmentData(),
    )
    assert in_list["scope"] == "project" and uuid in in_list["criteria_project_ids"]

    # Multi-select criteria: EVERY element of the list is captured - a
    # first-element-only read made flows confirmed-exclude items matching
    # the later elements.
    uuid2 = "c2d2b81f-5625-44a4-b138-f01fb2f0c30f"
    multi = _analyze_subscription(
        {**base, "criteria": f"event.data.blueprintId in ['{uuid}', '{uuid2}']"},
        ABX_ACTIONS,
        StubClient({}),
        AssessmentData(),
    )
    assert multi["scope"] == "blueprint"
    assert multi["criteria_blueprint_ids"] == [uuid, uuid2]

    # Exotic form: criteria present but no id extractable -> conditional, so
    # flows show it everywhere but marked as unverified, never as certain.
    exotic = _analyze_subscription(
        {**base, "criteria": "event.data.blueprintId in blueprintList"},
        ABX_ACTIONS,
        StubClient({}),
        AssessmentData(),
    )
    assert exotic["scope"] == "conditional"

    # Criteria on custom properties (typical for vRO subscriptions) is also
    # conditional - it must not present as a criteria-less global.
    custom = _analyze_subscription(
        {**base, "criteria": "event.data.customProperties.env == 'prod'"},
        ABX_ACTIONS,
        StubClient({}),
        AssessmentData(),
    )
    assert custom["scope"] == "conditional"

    empty = _analyze_subscription(
        {**base, "criteria": ""}, ABX_ACTIONS, StubClient({}), AssessmentData()
    )
    assert empty["scope"] == "global"


def test_builtin_patterns():
    assert _is_builtin({"name": "Quota enforcement"})
    assert not _is_builtin(
        {"name": "Active Directory - Add Computer", "runnableType": "extensibility.vco"}
    )


class PerActionStub:
    """get() stub for /abx/api/resources/actions/{id}/action-runs plus the
    global /abx/api/resources/action-runs oldest-record fetch (defaults to an
    empty history, which claims no floor and records no gap)."""

    def __init__(self, pages, oldest_page=None):
        self.pages = pages  # action id -> page dict | ApiError
        self.oldest_page = (
            oldest_page if oldest_page is not None else {"totalElements": 0, "content": []}
        )
        self.paths = []

    def get(self, path, params=None):
        self.paths.append(path)
        if path.startswith("/abx/api/resources/action-runs"):
            if isinstance(self.oldest_page, ApiError):
                raise self.oldest_page
            return self.oldest_page
        for aid, page in self.pages.items():
            if path.startswith(f"/abx/api/resources/actions/{aid}/action-runs"):
                if isinstance(page, ApiError):
                    raise page
                return page
        raise ApiError(f"GET {path} -> HTTP 404", status_code=404)


def test_abx_run_evidence_is_per_action_and_needs_no_join():
    # totalElements per action answers never-run outright; the association is
    # the URL, so name-like run actionIds cannot break the matching.
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    actions = [{"id": "a1", "name": "one"}, {"id": "a2", "name": "two"}]
    stub = PerActionStub(
        {
            "a1": {
                "totalElements": 3,
                "content": [
                    {"id": "r1", "runState": "COMPLETED", "createdMillis": 300},
                    {"id": "r2", "runState": "FAILED", "createdMillis": 200},
                    {"id": "r3", "runState": "COMPLETED", "createdMillis": 100},
                ],
            },
            "a2": {"totalElements": 0, "content": []},
        }
    )
    evidence = _collect_abx_run_evidence(stub, AssessmentData(), actions)
    assert evidence["collected"] and evidence["complete"]
    assert evidence["total_runs"] == 3
    # a2 absent from by_action = sound never-run evidence (totalElements 0)
    assert evidence["by_action"] == {
        "a1": {"count": 3, "last_millis": 300, "last_state": "COMPLETED"}
    }
    assert "$orderby=createdMillis%20desc" in stub.paths[0]


def test_abx_run_evidence_unverified_order_keeps_count_without_latest():
    # Big history whose page does not verify as descending: the count is
    # sound (totalElements), the latest is not claimed - the report shows
    # "N run(s)" instead of a date.
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    stub = PerActionStub(
        {
            "a1": {
                "totalElements": 50,
                "content": [
                    {"id": "r1", "runState": "COMPLETED", "createdMillis": 100},
                    {"id": "r2", "runState": "COMPLETED", "createdMillis": 300},
                ],
            }
        }
    )
    evidence = _collect_abx_run_evidence(stub, AssessmentData(), [{"id": "a1", "name": "x"}])
    assert evidence["by_action"]["a1"] == {"count": 50, "last_millis": 0, "last_state": ""}


def test_abx_run_evidence_unavailable_endpoint_is_a_gap_not_a_claim():
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    data = AssessmentData()
    evidence = _collect_abx_run_evidence(PerActionStub({}), data, [{"id": "a1"}])
    assert evidence["collected"] is False and evidence["complete"] is False
    assert data.errors  # surfaced via SYS-001; run evidence omitted


def test_abx_run_evidence_mid_list_failure_is_partial_with_gap():
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    data = AssessmentData()
    stub = PerActionStub(
        {
            "a1": {"totalElements": 0, "content": []},
            "a2": ApiError("HTTP 500", status_code=500),
        }
    )
    evidence = _collect_abx_run_evidence(
        stub, data, [{"id": "a1", "name": "one"}, {"id": "a2", "name": "two"}]
    )
    assert evidence["collected"] is True and evidence["complete"] is False
    assert data.errors  # aborted lookups surface via SYS-001


def test_abx_run_evidence_orderby_rejection_retries_bare_once():
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    class OrderbyRejectingStub(PerActionStub):
        def get(self, path, params=None):
            if "$orderby" in path:
                raise ApiError('HTTP 500: {"message":"..."}', status_code=500)
            return super().get(path, params)

    stub = OrderbyRejectingStub(
        {
            "a1": {
                "totalElements": 1,
                "content": [{"id": "r1", "runState": "COMPLETED", "createdMillis": 100}],
            }
        }
    )
    evidence = _collect_abx_run_evidence(stub, AssessmentData(), [{"id": "a1", "name": "x"}])
    assert evidence["complete"] is True
    # The whole history fit in the page: the latest is sound even unordered.
    assert evidence["by_action"]["a1"]["last_millis"] == 100


def test_abx_run_evidence_ordered_truncated_history_claims_record_zero():
    # The most common live path: $orderby accepted, page verifies descending,
    # totalElements far beyond the page - record 0 is the claimed latest.
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    stub = PerActionStub(
        {
            "a1": {
                "totalElements": 50,
                "content": [
                    {"id": "r1", "runState": "FAILED", "createdMillis": 900},
                    {"id": "r2", "runState": "COMPLETED", "createdMillis": 800},
                ],
            }
        }
    )
    evidence = _collect_abx_run_evidence(stub, AssessmentData(), [{"id": "a1", "name": "x"}])
    assert evidence["by_action"]["a1"] == {"count": 50, "last_millis": 900, "last_state": "FAILED"}


def test_abx_run_evidence_missing_total_never_claims_a_full_page_max():
    # No usable totalElements: a FULL page may hide newer runs beyond it, so
    # the page max is not claimed as the latest; a SHORT page is provably the
    # whole retained history and its max is sound.
    from vcf_automation_assessment_tool.collectors.extensibility import (
        PER_ACTION_RUN_PAGE,
        _collect_abx_run_evidence,
    )

    full_page = [
        {"id": f"r{i}", "runState": "COMPLETED", "createdMillis": 100 + i}
        for i in range(PER_ACTION_RUN_PAGE)
    ]
    stub = PerActionStub(
        {
            "a1": {"content": full_page},
            "a2": {"content": [{"id": "s1", "runState": "COMPLETED", "createdMillis": 500}]},
        }
    )
    evidence = _collect_abx_run_evidence(
        stub, AssessmentData(), [{"id": "a1", "name": "x"}, {"id": "a2", "name": "y"}]
    )
    assert evidence["by_action"]["a1"]["count"] == PER_ACTION_RUN_PAGE
    assert evidence["by_action"]["a1"]["last_millis"] == 0  # not claimed
    assert evidence["by_action"]["a2"] == {
        "count": 1,
        "last_millis": 500,
        "last_state": "COMPLETED",
    }


def test_abx_oldest_run_record_dates_the_history_floor():
    # One global page ordered ascending: record 0 is the oldest run still
    # retained anywhere - the floor of the window "no recorded runs" covers.
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    stub = PerActionStub(
        {"a1": {"totalElements": 0, "content": []}},
        oldest_page={
            "totalElements": 5000,
            "content": [
                {"id": "o1", "runState": "COMPLETED", "createdMillis": 1000},
                {"id": "o2", "runState": "COMPLETED", "createdMillis": 2000},
                {"id": "o3", "runState": "COMPLETED", "createdMillis": 3000},
            ],
        },
    )
    evidence = _collect_abx_run_evidence(stub, AssessmentData(), [{"id": "a1", "name": "x"}])
    assert evidence["oldest_run_millis"] == 1000
    assert any("action-runs?$orderby=createdMillis%20asc" in p for p in stub.paths)


def test_abx_oldest_run_record_exact_when_whole_history_fits():
    # Tiny estate: the page IS the whole history, so the minimum is exact
    # even without ordering trust.
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    stub = PerActionStub(
        {"a1": {"totalElements": 0, "content": []}},
        oldest_page={
            "totalElements": 2,
            "content": [
                {"id": "o1", "runState": "COMPLETED", "createdMillis": 900},
                {"id": "o2", "runState": "COMPLETED", "createdMillis": 500},
            ],
        },
    )
    evidence = _collect_abx_run_evidence(stub, AssessmentData(), [{"id": "a1", "name": "x"}])
    assert evidence["oldest_run_millis"] == 500


def test_abx_oldest_run_record_not_claimed_without_verified_order():
    # A build that silently ignores $orderby: big total and a page that does
    # not verify ascending - no floor is dated rather than dating it from an
    # arbitrary record.
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    stub = PerActionStub(
        {"a1": {"totalElements": 0, "content": []}},
        oldest_page={
            "totalElements": 5000,
            "content": [
                {"id": "o1", "runState": "COMPLETED", "createdMillis": 3000},
                {"id": "o2", "runState": "COMPLETED", "createdMillis": 1000},
            ],
        },
    )
    evidence = _collect_abx_run_evidence(stub, AssessmentData(), [{"id": "a1", "name": "x"}])
    assert "oldest_run_millis" not in evidence


def test_abx_oldest_run_record_failure_is_a_gap_not_a_claim():
    # The global route erroring costs the floor sentence, never the
    # per-action evidence; the gap surfaces via SYS-001.
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    data = AssessmentData()
    stub = PerActionStub(
        {
            "a1": {
                "totalElements": 1,
                "content": [{"id": "r1", "runState": "COMPLETED", "createdMillis": 100}],
            }
        },
        oldest_page=ApiError("HTTP 500", status_code=500),
    )
    evidence = _collect_abx_run_evidence(stub, data, [{"id": "a1", "name": "x"}])
    assert evidence["collected"] is True and evidence["complete"] is True
    assert evidence["by_action"]["a1"]["last_millis"] == 100
    assert "oldest_run_millis" not in evidence
    assert any(e.get("item") == "abx_run_history_oldest" for e in data.errors)


def test_abx_run_evidence_single_404_is_a_per_action_gap_once_route_proven():
    # A 404 after an earlier 200 means this one action vanished between
    # inventory and lookup - its own gap, not a voided estate. The evidence
    # stays partial so nothing downstream claims the unseen action never ran.
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    data = AssessmentData()
    stub = PerActionStub(
        {
            "a1": {"totalElements": 1, "content": [{"id": "r1", "createdMillis": 100}]},
            "a2": ApiError("HTTP 404", status_code=404),
            "a3": {"totalElements": 0, "content": []},
        }
    )
    evidence = _collect_abx_run_evidence(
        stub, data, [{"id": "a1"}, {"id": "a2", "name": "gone"}, {"id": "a3"}]
    )
    assert evidence["collected"] is True and evidence["complete"] is False
    assert "a1" in evidence["by_action"] and "a2" not in evidence["by_action"]
    assert any("gone" in e["item"] for e in data.errors)
    # a3 was still looked up after the per-action gap.
    assert any("/a3/" in p for p in stub.paths)


def test_abx_run_evidence_orderby_fallback_survives_an_idless_first_action():
    # The bare retry is gated on "first fetch attempted", not list position:
    # an id-less action[0] used to leave the fallback dead and record the
    # whole feature as unavailable on $orderby-rejecting builds.
    from vcf_automation_assessment_tool.collectors.extensibility import (
        _collect_abx_run_evidence,
    )

    class OrderbyRejectingStub(PerActionStub):
        def get(self, path, params=None):
            if "$orderby" in path:
                raise ApiError("HTTP 500", status_code=500)
            return super().get(path, params)

    stub = OrderbyRejectingStub(
        {"a1": {"totalElements": 0, "content": []}},
    )
    evidence = _collect_abx_run_evidence(
        stub, AssessmentData(), [{"name": "no-id"}, {"id": "a1", "name": "x"}]
    )
    assert evidence["collected"] is True
    assert evidence["complete"] is False  # the id-less action was never looked up


def test_abx_run_evidence_lookup_cap_records_a_gap(monkeypatch):
    from vcf_automation_assessment_tool.collectors import extensibility

    monkeypatch.setattr(extensibility, "MAX_RUN_LOOKUPS", 1)
    data = AssessmentData()
    stub = PerActionStub(
        {
            "a1": {"totalElements": 0, "content": []},
            "a2": {"totalElements": 0, "content": []},
        }
    )
    evidence = extensibility._collect_abx_run_evidence(stub, data, [{"id": "a1"}, {"id": "a2"}])
    assert evidence["collected"] is True and evidence["complete"] is False
    assert any("capped" in e["error"] for e in data.errors)


def test_abx_action_analysis_inline_source():
    from vcf_automation_assessment_tool.collectors.extensibility import _analyze_abx_action

    entry = _analyze_abx_action(
        {
            "id": "a1",
            "name": "bad-action",
            "runtime": "python",
            "dependencies": "requests",
            "source": "def handler(c, i):\n    print('x')\n    return i\n",
        }
    )
    assert entry["has_inline_source"] is True
    assert "source" not in entry  # bulky source dropped from the dump
    joined = " | ".join(entry["issues"])
    # Absence of try/except is deliberately not flagged - only actively
    # harmful patterns and literals are.
    assert "no error handling" not in joined
    assert "unpinned" in joined
    # A three-line handler is rated, and rated LOW.
    assert entry["complexity"] == "LOW"


def test_abx_action_analysis_bundled():
    from vcf_automation_assessment_tool.collectors.extensibility import _analyze_abx_action

    entry = _analyze_abx_action({"id": "a2", "name": "zip-action", "runtime": "python"})
    assert entry["has_inline_source"] is False
    assert entry["analysis"] is None
    assert entry["complexity"] is None  # nothing trustworthy to rate
    assert any("not analyzable" in i for i in entry["issues"])


def _upgrade_ps(extensibility, entries, actions):
    """The PowerShell arm of the shared parser-upgrade pass."""
    extensibility._upgrade_analyses(
        entries,
        actions,
        "powershell",
        extensibility.codequality.parse_powershell_batch,
        "PowerShell",
    )


def test_powershell_upgrade_merges_real_metrics(monkeypatch):
    # The batch parser (stubbed here - the real one is exercised in
    # test_codequality) replaces heuristic PowerShell metrics in place and
    # recomputes issues + complexity from the real numbers.
    from vcf_automation_assessment_tool.collectors import extensibility

    actions = [
        {
            "id": "a1",
            "name": "ps-action",
            "runtime": "powershell",
            "dependencies": "",
            "source": "if ($x) { Write-Host $x }",
        }
    ]
    entries = [extensibility._analyze_abx_action(a) for a in actions]
    assert entries[0]["analysis"]["functions"] is None  # heuristic path first

    monkeypatch.setattr(
        extensibility.codequality,
        "parse_powershell_batch",
        lambda sources: [
            {
                "parses": True,
                "functions": 9,
                "branches": 40,
                "has_error_handling": True,
                "bare_excepts": 0,
                "swallowed_excepts": 2,
            }
        ],
    )
    _upgrade_ps(extensibility, entries, actions)
    analysis = entries[0]["analysis"]
    assert analysis["functions"] == 9 and analysis["branches"] == 40
    assert entries[0]["complexity"] == "HIGH"  # 9 functions crosses the line
    assert any("swallow" in i for i in entries[0]["issues"])

    # Parser unavailable: everything stays heuristic, nothing breaks.
    entries2 = [extensibility._analyze_abx_action(a) for a in actions]
    monkeypatch.setattr(extensibility.codequality, "parse_powershell_batch", lambda sources: None)
    _upgrade_ps(extensibility, entries2, actions)
    assert entries2[0]["analysis"]["functions"] is None


def test_abx_flow_not_script_analyzed():
    # ABX flows are YAML orchestrations - script analysis on them produced
    # bogus "no error handling" findings on live data.
    from vcf_automation_assessment_tool.collectors.extensibility import _analyze_abx_action

    flow = _analyze_abx_action(
        {
            "id": "a3",
            "name": "FLOW - Deploy Server",
            "actionType": "FLOW",
            "runtime": "",
            "source": "flow:\n  start:\n    next: step1\n",
        }
    )
    assert flow["issues"] == []
    assert flow["analysis"] is None

    no_runtime = _analyze_abx_action({"id": "a4", "name": "odd", "source": "x"})
    assert no_runtime["issues"] == []


def test_policy_definitions_backfilled_from_detail():
    policies = [
        {"id": "pol1", "name": "lease", "typeId": "t"},  # summary only
        {"id": "pol2", "name": "full", "definition": {"leaseTermMax": 30}},
    ]
    client = StubClient(
        {"/policy/api/policies/pol1": {"id": "pol1", "definition": {"leaseTermMax": 7}}}
    )
    _ensure_policy_definitions(client, AssessmentData(), policies)
    assert policies[0]["definition"] == {"leaseTermMax": 7}
    # Already-complete policies are not re-fetched (no stub entry to serve).
    assert policies[1]["definition"] == {"leaseTermMax": 30}


def test_policy_definition_fetch_failure_recorded_not_fatal():
    policies = [{"id": "pol1", "name": "lease"}]
    data = AssessmentData()
    _ensure_policy_definitions(StubClient({}), data, policies)  # every path 404s
    assert "definition" not in policies[0]
    assert any(e["item"] == "policy:lease" for e in data.errors)


BP = "event.data.blueprintId"
UUID_A = "aaaaaaaa-1111-2222-3333-444444444444"
UUID_B = "bbbbbbbb-1111-2222-3333-444444444444"


def analyze_criteria(criteria):
    entry = sub("extensibility.abx", "abx1")
    entry["criteria"] = criteria
    return _analyze_subscription(entry, ABX_ACTIONS, StubClient({}), AssessmentData())


def test_negated_criteria_reads_as_a_deny_list():
    entry = analyze_criteria(f'{BP} != "inline-blueprint"')
    assert entry["criteria_blueprint_eq"] == []
    assert entry["criteria_blueprint_ne"] == ["inline-blueprint"]
    # Not "conditional": the expression is fully readable, just negated.
    assert entry["scope"] == "blueprint"


def test_non_uuid_literal_survives_but_stays_out_of_the_id_list():
    # The platform stamps "inline-blueprint" for catalog items with no
    # template. The uuid-shaped filter dropped it, so the criteria parsed to
    # nothing and the subscription matched every item.
    entry = analyze_criteria(f'{BP} == "inline-blueprint"')
    assert entry["criteria_blueprint_eq"] == ["inline-blueprint"]
    # EXT-001 reads criteria_blueprint_ids as real object references: a
    # sentinel there would be reported as a missing blueprint.
    assert entry["criteria_blueprint_ids"] == []


def test_mixed_negation_and_equality_keeps_both_halves():
    entry = analyze_criteria(f'{BP} != "inline-blueprint" || {BP} == "{UUID_A}"')
    assert entry["criteria_blueprint_eq"] == [UUID_A]
    assert entry["criteria_blueprint_ne"] == ["inline-blueprint"]
    assert entry["criteria_blueprint_ids"] == [UUID_A]


def test_not_in_list_fills_the_deny_list_and_in_list_the_allow_list():
    denied = analyze_criteria(f"{BP} not in ['{UUID_A}','{UUID_B}']")
    assert denied["criteria_blueprint_eq"] == []
    assert denied["criteria_blueprint_ne"] == [UUID_A, UUID_B]
    allowed = analyze_criteria(f"{BP} in ['{UUID_A}','{UUID_B}']")
    assert allowed["criteria_blueprint_eq"] == [UUID_A, UUID_B]
    assert allowed["criteria_blueprint_ne"] == []
    assert allowed["criteria_blueprint_ids"] == [UUID_A, UUID_B]


def test_project_criteria_reads_negation_too():
    entry = analyze_criteria(f"event.data.projectId != '{UUID_A}'")
    assert entry["scope"] == "project"
    assert entry["criteria_project_ne"] == [UUID_A]
    assert entry["criteria_project_ids"] == []


def test_unreadable_criteria_still_falls_through_to_conditional():
    entry = analyze_criteria("event.data.customProperties.tier == 'gold'")
    assert entry["scope"] == "conditional"
    assert entry["criteria_blueprint_eq"] == []
    assert entry["criteria_blueprint_ne"] == []


# The five criteria shapes a live estate's report actually carried (2026-08-12).
GUARD = 'event.data.blueprintId != "inline-blueprint"'
REAL_CRITERIA = [
    GUARD,
    f"{GUARD} && (event.data.eventType == 'CREATE_DEPLOYMENT' && event.data.status != 'FAILED')",
    f"{GUARD} && (event.data.eventType == 'CREATE_DEPLOYMENT' && event.data.status == 'FINISHED')",
    f"{GUARD} && (event.data.eventType == 'CREATE_DEPLOYMENT'"
    " || event.data.eventType == 'DESTROY_DEPLOYMENT')",
    f"{GUARD} && event.data.eventType == 'CREATE_DEPLOYMENT'",
]


def test_every_live_guard_reads_its_blueprint_clause():
    for criteria in REAL_CRITERIA:
        entry = analyze_criteria(criteria)
        assert entry["criteria_blueprint_ne"] == ["inline-blueprint"], criteria
        assert entry["scope"] == "blueprint", criteria


def test_extra_clauses_mark_the_criteria_as_only_partly_read():
    assert analyze_criteria(REAL_CRITERIA[0])["criteria_fully_read"] is True
    for criteria in REAL_CRITERIA[1:]:
        # eventType / status are not evaluated here, so a match can be ruled
        # out but never ruled in.
        assert analyze_criteria(criteria)["criteria_fully_read"] is False, criteria


def test_a_parenthesised_or_is_not_a_top_level_disjunction():
    # `a && (b || c)`: a false `a` still settles the whole expression.
    for criteria in REAL_CRITERIA:
        assert analyze_criteria(criteria)["criteria_top_level_or"] is False, criteria


def test_top_level_or_is_detected():
    entry = analyze_criteria(f"{GUARD} || event.data.eventType == 'CREATE_DEPLOYMENT'")
    assert entry["criteria_top_level_or"] is True


def test_a_bracket_around_the_whole_expression_is_still_a_top_level_or():
    # Live shape on the aib estate: a disjunction of blueprint ids and custom
    # properties wrapped in one redundant pair. The depth scan read it at
    # depth 1 and called it subordinate, so the unread custom-property half
    # was silently ruled out of every item the ids do not name.
    entry = analyze_criteria(
        f"({GUARD} || event.data.customProperties['onboarded'] == 'TF_Template_PPP')"
    )
    assert entry["criteria_top_level_or"] is True


def test_a_bracket_that_closes_early_is_not_stripped():
    # `(a) && (b || c)` opens and closes before the end: still subordinate.
    entry = analyze_criteria(
        f"({GUARD}) && (event.data.eventType == 'CREATE_DEPLOYMENT'"
        " || event.data.eventType == 'UPDATE_DEPLOYMENT')"
    )
    assert entry["criteria_top_level_or"] is False


def test_quoted_operator_is_not_mistaken_for_a_disjunction():
    entry = analyze_criteria("event.data.blueprintId != 'a||b'")
    assert entry["criteria_top_level_or"] is False
    assert entry["criteria_blueprint_ne"] == ["a||b"]


def test_abx_entry_carries_the_two_issue_tiers_and_a_fingerprint():
    from vcf_automation_assessment_tool.collectors.extensibility import _analyze_abx_action

    entry = _analyze_abx_action(
        {
            "id": "a9",
            "name": "tidy",
            "runtime": "python",
            "entrypoint": "handler",
            "dependencies": "requests==2.31.0",
            "inputs": {"host": "", "unusedOne": ""},
            "source": "def handler(context, inputs):\n    return inputs['host']\n",
        }
    )
    assert entry["issues"] == []  # entrypoint resolves, nothing defect-level
    assert entry["pedantic_issues"] == ["declared input(s) never read: unusedOne"]
    assert entry["declared_inputs"] == ["host", "unusedOne"]
    assert entry["source_fingerprint"] and entry["source_sketch"]


def test_abx_missing_entrypoint_is_a_default_tier_issue():
    from vcf_automation_assessment_tool.collectors.extensibility import _analyze_abx_action

    entry = _analyze_abx_action(
        {
            "id": "a10",
            "name": "broken",
            "runtime": "python",
            "entrypoint": "main",
            "source": "def handler(context, inputs):\n    return 1\n",
        }
    )
    assert any("entrypoint 'main' is not defined" in i for i in entry["issues"])


def test_abx_inputs_of_an_unexpected_shape_leave_the_signal_silent():
    # The declared-inputs read is defensive: a build that does not carry a
    # map here must produce no claim rather than a guess.
    from vcf_automation_assessment_tool.collectors.extensibility import _analyze_abx_action

    entry = _analyze_abx_action(
        {
            "id": "a11",
            "name": "odd-inputs",
            "runtime": "python",
            "inputs": ["host"],
            "source": "def handler(context, inputs):\n    return inputs['host']\n",
        }
    )
    assert entry["declared_inputs"] == []
    assert entry["pedantic_issues"] == []
