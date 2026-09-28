"""Checks against the synthetic environment in conftest."""

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.flows import build_flows, flow_topics
from vcf_automation_assessment_tool.models import Severity


def get(findings, check_id):
    return next((f for f in findings if f.check_id == check_id), None)


def test_full_check_run(sample_data):
    build_flows(sample_data)
    run_checks(sample_data)
    findings = sample_data.findings
    by_id = {f.check_id for f in findings}

    # DEP-001: every failed deployment, whether or not it built anything
    f = get(findings, "DEP-001")
    assert f and f.severity is Severity.CRITICAL
    assert [a.name for a in f.affected] == ["failed-dep", "half-built"]

    # DEP-010: the failures that left machines behind. failed-dep built
    # nothing, so only half-built qualifies, and its two machines are listed
    # with a power state each - the one the API did not report is said to be
    # unreported rather than called off.
    f = get(findings, "DEP-010")
    assert f and f.severity is Severity.WARNING
    assert [a.name for a in f.affected] == ["half-built"]
    detail = f.affected[0].detail
    assert "status=CREATE_FAILED" in detail
    assert "2 machines" in detail
    assert "powered on (1): vm-half-1" in detail
    assert "no power state reported (1): vm-half-2" in detail
    assert "1 of those machines is powered on" in f.recommendation
    assert "One of the machines in these deployments carries no power state" in f.recommendation

    # DEP-002: deployment with only a network resource; in-progress d5
    # excluded, and the machineless run of a vRO workflow item excluded too -
    # workflow/action/pipeline runs are machineless by design. Flagged rows
    # from a known item say where they came from, and the source template is
    # cross-referenced: failed-dep's defines a machine (expected but absent),
    # while lb-net matches its network-only template and is not flagged.
    # The check runs here; the config's ignore list is what keeps it out of a
    # default report, and that is exercised in test_ignore_findings.py.
    f = get(findings, "DEP-002")
    names = [a.name for a in f.affected]
    assert "empty-dep" in names and "failed-dep" in names
    assert "stuck-dep" not in names
    assert "workflow-run" not in names
    assert "lb-net" not in names
    failed = next(a for a in f.affected if a.name == "failed-dep")
    assert "created from 'Web Server' (VCF Automation template)" in failed.detail
    assert "template 'web-server' defines Cloud.vSphere.Machine (expected but absent)" in (
        failed.detail
    )
    empty = next(a for a in f.affected if a.name == "empty-dep")
    assert "template" not in empty.detail  # no blueprint resolvable - no claim
    assert "reported by DEP-003" in f.recommendation

    # DEP-003: MISSING resource
    f = get(findings, "DEP-003")
    assert [a.name for a in f.affected] == ["ghost-dep"]

    # DEP-004: stuck in progress since May 2025
    f = get(findings, "DEP-004")
    assert [a.name for a in f.affected] == ["stuck-dep"]

    # DEP-005: expired lease
    f = get(findings, "DEP-005")
    assert [a.name for a in f.affected] == ["ghost-dep"]

    # DEP-006: only the two-machine stack; single-machine and network-only
    # deployments are not multi-machine
    f = get(findings, "DEP-006")
    assert f and f.severity is Severity.INFO
    assert [a.name for a in f.affected] == ["web-prod", "half-built"]
    assert f.affected[0].detail.startswith("2 machines: vm-1, vm-2")

    # CAT-001: unused catalog item flagged, used one not
    f = get(findings, "CAT-001")
    assert [a.name for a in f.affected] == ["Unused Item"]

    # CAT-002: source with import error and found != imported
    f = get(findings, "CAT-002")
    assert [a.name for a in f.affected] == ["Platform Templates"]

    # CAT-004: item shared with no project; the shared one not flagged
    f = get(findings, "CAT-004")
    assert f and f.severity is Severity.INFO
    assert [a.name for a in f.affected] == ["Unused Item"]
    assert "shared with 0 projects" in f.affected[0].detail

    # TAG-001: hard constraint 'no:such:tag' unmatched; dynamic one not
    # flagged. site:dc1 lives only on the vc-prod cloud account: computes
    # inherit account tags so its resource-context constraint is satisfied,
    # but storage profiles never inherit - only the storage-context use of
    # the same tag is flagged, with the inheritance explained.
    f = get(findings, "TAG-001")
    assert f.severity is Severity.CRITICAL
    details = [a.detail for a in f.affected]
    assert len(details) == 2
    assert any("no:such:tag" in d for d in details)
    storage_gap = next(d for d in details if "site:dc1" in d)
    assert "(storage)" in storage_gap
    assert "storage profiles do not inherit account-level tags" in storage_gap
    assert not any("site:dc1" in d and "(resource)" in d for d in details)

    # TAG-002: soft 'maybe:gone' unmatched; dynamic constraints deliberately
    # not reported (input-driven, not statically verifiable - pure noise).
    f = get(findings, "TAG-002")
    details = " | ".join(a.detail for a in f.affected)
    assert "maybe:gone" in details
    assert "${input.env}" not in details

    # TAG-003: tags assigned but never consumed. cluster:gold is consumed by
    # the zone compute filter (tagsToMatch) so must NOT be flagged; env:prod is
    # consumed by a blueprint constraint; env:qa COULD be selected by the
    # dynamic env:${input.env} constraint so it is excluded (with a note in
    # the recommendation). net:prod/storage:gold/orphan:tag have no consumer
    # anywhere - and the finding is an INFO review list, not a warning: tags
    # can serve automation and external tooling the API cannot see.
    f = get(findings, "TAG-003")
    assert f.severity is Severity.INFO
    assert [a.name for a in f.affected] == ["net:prod", "orphan:tag", "storage:gold"]
    assert "A further 1 assigned tag(s)" in f.recommendation

    # Consumed-by labels for the tag table, which is the tag usage matrix: a
    # tag with no static consumer that a dynamic
    # constraint could select names the template instead of claiming nothing,
    # and an unconsumed tag is stated honestly, not as proof of disuse.
    from vcf_automation_assessment_tool.placement import tag_consumer_labels

    labels = tag_consumer_labels(sample_data)
    assert labels["env:qa"] == "possibly web-server (dynamic constraint)"
    assert labels["orphan:tag"] == "no visible constraint"
    assert "web-server" in labels["site:dc1"]

    # BLU-001 invalid blueprint, BLU-002 draft-only
    assert [a.name for a in get(findings, "BLU-001").affected] == ["draft-only"]
    assert [a.name for a in get(findings, "BLU-002").affected] == ["draft-only"]

    # INF-001: empty zone flagged (0 computes + no project assignment)
    f = get(findings, "INF-001")
    assert [a.name for a in f.affected] == ["empty-zone"]

    # INF-002: broken image mapping
    f = get(findings, "INF-002")
    assert any("images / broken" in a.name for a in f.affected)

    # INF-003: only the account whose own document reports a bad status; the
    # OK account and the status-less integration are never assumed unhealthy.
    # CRITICAL: an unreachable endpoint is broken today, not eventual debt.
    f = get(findings, "INF-003")
    assert f and f.severity is Severity.CRITICAL
    assert [a.name for a in f.affected] == ["vc-broken"]
    assert "status FAILED (vsphere)" in f.affected[0].detail

    # INF-004: untagged cloud account and untagged vRO integration listed;
    # the tagged account is not.
    f = get(findings, "INF-004")
    assert f and f.severity is Severity.INFO
    assert [a.name for a in f.affected] == ["vc-broken", "vro-embedded"]

    # PRJ-001 + PRJ-002: EmptyProject
    assert [a.name for a in get(findings, "PRJ-001").affected] == ["EmptyProject"]
    assert [a.name for a in get(findings, "PRJ-002").affected] == ["EmptyProject"]

    # EXT-001: broken subscription (runnable gone + blueprint gone)
    f = get(findings, "EXT-001")
    assert [a.name for a in f.affected] == ["old-hook"]
    assert "not found" in f.affected[0].detail

    # EXT-002: disabled subscription. A WARNING, not inventory: the behaviour
    # it provided is either silently absent today or dead weight, and both
    # need somebody to decide which.
    f = get(findings, "EXT-002")
    assert [a.name for a in f.affected] == ["old-hook"]
    assert f.severity is Severity.WARNING

    # EXT-005: criteria pinned to a literal blueprint id, resolved against the
    # collected blueprints - bp-gone is absent, so the label says unknown;
    # validate-web-request names bp1, which resolves
    f = get(findings, "EXT-005")
    assert [a.name for a in f.affected] == ["old-hook", "validate-web-request"]
    assert f.affected[0].detail == "blueprint: (unknown blueprint bp-gone)"
    assert f.severity is Severity.INFO

    # EXT-006: run history complete; legacy-dns-update and
    # vm-lifecycle-orchestrator have no runs and nothing references them. The
    # fixture's oldest retained record dates the floor of the window the
    # claims cover.
    f = get(findings, "EXT-006")
    assert f.severity is Severity.INFO
    assert [a.name for a in f.affected] == ["legacy-dns-update", "vm-lifecycle-orchestrator"]
    assert f.affected[0].detail == "no recorded runs and no subscription references it"
    assert "oldest record still held is from 2025-07-01" in f.recommendation

    # APR-001: only the PENDING approval flagged
    f = get(findings, "APR-001")
    assert [a.name for a in f.affected] == ["big-vm"]
    assert "bob" in f.affected[0].detail

    # APR-002 stays quiet: the fixture's approval policy names an approver
    assert get(findings, "APR-002") is None

    # Policy coverage review lists: no day-2 policies exist at all, the
    # approval policy is organization-wide (covers everyone - silent), and
    # content sharing covers only Platform.
    f = get(findings, "POL-004")
    assert f.severity is Severity.INFO
    assert [a.name for a in f.affected] == ["EmptyProject", "Platform"]
    assert "no day-2 action policy applies" in f.affected[0].detail
    assert get(findings, "POL-005") is None
    assert [a.name for a in get(findings, "POL-006").affected] == ["EmptyProject"]

    # POL-001: identical per-project lease copies grouped (key order in the
    # definition normalized away); the differing-definition policy and the
    # same-project twin stay unflagged. The row names every copy with its
    # project and says which move applies (both fixture projects are covered,
    # so: straight swap, no scope criteria).
    f = get(findings, "POL-001")
    assert f and f.severity is Severity.INFO
    assert len(f.affected) == 1
    assert f.affected[0].name == "empty-lease (+1 more names)"
    assert f.affected[0].project == "2 projects"
    assert "2 identical HARD lease policies" in f.affected[0].detail
    assert "They cover every project (2), so one organization-wide policy" in f.affected[0].detail
    assert (
        "Delete these copies once the replacement is in place:\n"
        "\u2022 empty-lease (EmptyProject)\n\u2022 platform-lease (Platform)"
    ) in f.affected[0].detail
    assert "special-lease" not in " ".join(a.name for a in f.affected)
    assert "scope criteria" in f.recommendation

    # POL-002: only the policy scoped to a deleted project; live-project and
    # org-scoped policies stay unflagged.
    f = get(findings, "POL-002")
    assert f and f.severity is Severity.WARNING
    assert [a.name for a in f.affected] == ["orphaned-lease"]
    assert "lease policy scoped to missing project p-deleted" in f.affected[0].detail

    # POL-003: org-scoped prod-lease overlaps with four project-scoped lease
    # policies (pol3-pol6 in p1/p2). No action-comparison line (lease policies
    # lack "actions" definitions).
    f = get(findings, "POL-003")
    assert f and f.severity is Severity.INFO
    assert [a.name for a in f.affected] == ["prod-lease"]
    detail = f.affected[0].detail
    assert "HARD lease policy scoped to the whole organization" in detail
    assert "also covered by 4 project-scoped lease policy(ies)" in detail
    assert "action list is contained" not in detail
    assert "different action sets" not in detail

    # REP-001: every catalog item rated; Web Server is MEDIUM (ABX hooks via
    # the global subscriptions, no vRO)
    f = get(findings, "REP-001")
    assert len(f.affected) == 3
    web = next(a for a in f.affected if a.name == "Web Server")
    assert "difficulty=MEDIUM" in web.detail
    assert "hooks: 9 ABX, 0 Orchestrator" in web.detail
    assert "Terraform" in web.detail

    # REP-002: UI-authored template flagged; git-sourced one not
    f = get(findings, "REP-002")
    assert [a.name for a in f.affected] == ["web-server"]

    # EXT-003: only the action with issues; project id resolved
    # to its name. Absence of try/except is not a signal (user: pure noise on
    # live data).
    f = get(findings, "EXT-003")
    assert [a.name for a in f.affected] == ["legacy-dns-update"]
    assert "no error handling" not in f.affected[0].detail
    assert "10.0.0.53" in f.affected[0].detail
    assert f.affected[0].project == "Platform"

    # EXT-004: only the HIGH-complexity action - an ABX action should stay a
    # short glue script; register-cmdb/legacy-dns-update are LOW and unflagged.
    f = get(findings, "EXT-004")
    assert f and f.severity is Severity.INFO
    assert [a.name for a in f.affected] == ["vm-lifecycle-orchestrator"]
    assert "260 code lines, 12 function(s), 44 branch point(s)" in f.affected[0].detail

    # BLU-003: hardcoded IP
    # in the web-server template
    f = get(findings, "BLU-003")
    assert [a.name for a in f.affected] == ["web-server"]
    assert "192.168.10.5" in f.affected[0].detail

    # REP-003: no vRO-backed content in the fixture
    assert get(findings, "REP-003") is None

    # VRO-001: only the vRO action with issues, module shown as project.
    # The slash already isolates the module in slash-form FQNs; the old
    # extra dot-rsplit collapsed every module to its vendor root.
    f = get(findings, "VRO-001")
    assert [a.name for a in f.affected] == ["com.simplygeek.dns/legacySetRecord"]
    assert "10.0.0.53" in f.affected[0].detail
    assert f.affected[0].project == "com.simplygeek.dns"

    # VRO-002: only the HIGH-complexity workflow, with user-interaction called out
    f = get(findings, "VRO-002")
    assert [a.name for a in f.affected] == ["Active Directory - Add Computer"]
    assert "user-interaction" in f.affected[0].detail
    assert "24 item(s)" in f.affected[0].detail

    # CAT-003 stays: it tallies items per type, which no table computes.
    assert "CAT-003" in by_id

    # Sorted critical-first, check id ascending within each severity band
    # (never by affected count - interleaved ids read as unordered).
    keys = [(f.severity.order, f.check_id) for f in findings]
    assert keys == sorted(keys)


def test_pol_001_uses_ui_type_names():
    # The UI calls the type "content sharing"; the API typeId says
    # "entitlement". The report must speak the UI's language.
    from vcf_automation_assessment_tool.checks.governance import (
        pol_001_per_project_policy_copies,
    )
    from vcf_automation_assessment_tool.models import AssessmentData

    data = AssessmentData()
    data.derived["project_names"] = {"p1": "A", "p2": "B"}
    data.raw["governance"] = {
        "policies": [
            {
                "id": f"pol-{pid}",
                "name": f"{pid} share",
                "typeId": "com.vmware.policy.catalog.entitlement",
                "enforcementType": "HARD",
                "projectId": pid,
                "definition": {"x": 1},
            }
            for pid in ("p1", "p2")
        ]
    }
    findings = pol_001_per_project_policy_copies(data)
    detail = findings[0].affected[0].detail
    assert "2 identical HARD content sharing policies" in detail
    assert "entitlement" not in detail


def test_pol_002_silent_without_a_project_map():
    # No projects collected -> "missing" is indistinguishable from "unread";
    # the check must stay silent rather than flag every scoped policy.
    from vcf_automation_assessment_tool.checks.governance import (
        pol_002_policies_scoped_to_missing_projects,
    )
    from vcf_automation_assessment_tool.models import AssessmentData

    data = AssessmentData()
    data.raw["governance"] = {
        "policies": [
            {
                "id": "stale",
                "name": "WORKGROUP_ContentSharingPolicy",
                "typeId": "com.vmware.policy.catalog.entitlement",
                "enforcementType": "HARD",
                "projectId": "2e89866a-dead",
            }
        ]
    }
    data.derived["project_names"] = {}
    assert pol_002_policies_scoped_to_missing_projects(data) == []

    # With a project map the same policy is flagged, in UI type language.
    data.derived["project_names"] = {"p1": "Platform"}
    findings = pol_002_policies_scoped_to_missing_projects(data)
    detail = findings[0].affected[0].detail
    assert "content sharing policy scoped to missing project 2e89866a-dead" in detail


def test_cat_004_silent_when_no_sharing_mechanism_readable(sample_data):
    # projectIds unpopulated, entitlements not collected AND no content
    # sharing policies visible: zero evidence, so no item may be flagged.
    for i in sample_data.raw["catalog"]["items"]:
        i["projectIds"] = []
    sample_data.raw["governance"]["policies"] = [
        p
        for p in sample_data.raw["governance"]["policies"]
        if not p["typeId"].endswith("catalog.entitlement")
    ]
    build_flows(sample_data)
    run_checks(sample_data)
    assert get(sample_data.findings, "CAT-004") is None


def test_cat_004_uses_policy_resolved_sharing(sample_data):
    # The live regression: projectIds unpopulated, but a content sharing
    # policy grants Web Server to Platform. After access resolution only the
    # genuinely unshared item is flagged.
    from vcf_automation_assessment_tool.access import build_catalog_access

    for i in sample_data.raw["catalog"]["items"]:
        i["projectIds"] = []
    build_catalog_access(sample_data)
    build_flows(sample_data)
    run_checks(sample_data)
    f = get(sample_data.findings, "CAT-004")
    assert [a.name for a in f.affected] == ["Unused Item", "Reset VM Password"]
    web = next(i for i in sample_data.raw["catalog"]["items"] if i["id"] == "ci1")
    assert web["projectIds"] == ["p1"]


def test_cat_004_flags_all_when_entitlements_confirm_unshared(sample_data):
    # Same empty field, but a successful entitlements read makes it evidence.
    for i in sample_data.raw["catalog"]["items"]:
        i["projectIds"] = []
    sample_data.raw["catalog"]["entitlements_collected"] = True
    build_flows(sample_data)
    run_checks(sample_data)
    f = get(sample_data.findings, "CAT-004")
    assert [a.name for a in f.affected] == ["Web Server", "Unused Item", "Reset VM Password"]


def test_flows_builder(sample_data):
    build_flows(sample_data)
    flows = sample_data.derived["flows"]
    assert len(flows) == 3
    web = next(f for f in flows if f["item_name"] == "Web Server")
    # Global blocking subscription matches every item.
    topics = {t["topic"] for t in flow_topics(web)}
    assert "compute.provision.post" in topics
    # Blueprint-scoped sub2 targets bp-gone, so it must NOT match Web Server
    # (whose blueprint resolves to bp1 via the deployment join).
    all_subs = [s["name"] for t in flow_topics(web) for s in t["subscriptions"]]
    assert "add-to-cmdb" in all_subs
    # Web Server's blueprint resolved (bp1), old-hook targets bp-gone: excluded.
    assert "old-hook" not in all_subs
    # Built-in platform subscriptions are excluded from flows by default...
    assert "Quota enforcement" not in all_subs

    # Unused Item has no resolvable blueprint - blueprint-scoped subscriptions
    # cannot be ruled out, so they are shown rather than silently hidden.
    unused = next(f for f in sample_data.derived["flows"] if f["item_name"] == "Unused Item")
    unused_subs = [s["name"] for t in flow_topics(unused) for s in t["subscriptions"]]
    assert "old-hook" in unused_subs


def test_flows_include_system_subscriptions_flag(sample_data):
    sample_data.meta["include_system_subscriptions"] = True
    build_flows(sample_data)
    web = next(f for f in sample_data.derived["flows"] if f["item_name"] == "Web Server")
    all_subs = [s["name"] for t in flow_topics(web) for s in t["subscriptions"]]
    assert "Quota enforcement" in all_subs


def test_builtin_classification():
    from vcf_automation_assessment_tool.collectors.extensibility import _is_builtin

    assert _is_builtin({"name": "Quota enforcement", "system": False})
    assert _is_builtin({"name": "Migration Assessment Subscription"})
    assert _is_builtin({"name": "ABX-CGS-Subscription-1234"})
    assert _is_builtin({"name": "Approval workflow"})
    assert _is_builtin({"name": "anything", "system": True})
    assert not _is_builtin(
        {"name": "add-to-cmdb", "system": False, "runnableType": "extensibility.abx"}
    )
    # Internal service-to-service subscriptions (broker.broadcast.command,
    # cgs-content-update-topic, endpoint.cud...) run service callbacks, not
    # extensibility runnables - internal regardless of name or system flag.
    assert _is_builtin({"name": "content update listener", "system": False})
    assert _is_builtin({"name": "endpoint watcher", "runnableType": "SERVICE"})


def test_builtin_excluded_from_ext_checks(sample_data):
    build_flows(sample_data)
    run_checks(sample_data)
    # sub3 is blocking + has an unresolved runnable, but being built-in it must
    # not surface in EXT-001.
    f = get(sample_data.findings, "EXT-001")
    assert all(a.name != "Quota enforcement" for a in f.affected)


def test_ext_006_evidence_guards():
    from vcf_automation_assessment_tool.checks.governance import (
        ext_006_abx_actions_without_recorded_runs as check_008,
    )
    from vcf_automation_assessment_tool.models import AssessmentData

    def data_with(evidence):
        d = AssessmentData()
        d.raw["extensibility"] = {
            "subscriptions": [],
            "abx_actions": [{"id": "a1", "name": "one", "projectId": ""}],
            "abx_run_evidence": evidence,
        }
        return d

    # Not collected, and collected-but-partial: an action unseen in a
    # truncated sample is not a never-ran action.
    assert check_008(data_with({"collected": False, "complete": False, "by_action": {}})) == []
    assert check_008(data_with({"collected": True, "complete": False, "by_action": {}})) == []
    # Runs exist but none maps onto any inventoried id: the id dialects
    # evidently cannot be compared, so nothing is claimed.
    mismatch = {"collected": True, "complete": True, "by_action": {"other-dialect": {"count": 1}}}
    assert check_008(data_with(mismatch)) == []
    # Complete history with no runs at all: the claim is sound. With no
    # oldest-record floor claimed, the recommendation stays undated.
    (f,) = check_008(data_with({"collected": True, "complete": True, "by_action": {}}))
    assert [a.name for a in f.affected] == ["one"]
    assert "oldest record still held" not in f.recommendation
    # When the floor was dated, the recommendation states it.
    dated = {
        "collected": True,
        "complete": True,
        "by_action": {},
        "oldest_run_millis": 1751328000000,
    }
    (f,) = check_008(data_with(dated))
    assert "oldest record still held is from 2025-07-01" in f.recommendation
    # A referenced-but-never-fired action names its subscription.
    d = data_with({"collected": True, "complete": True, "by_action": {}})
    d.raw["extensibility"]["subscriptions"] = [
        {"name": "hook", "runnableType": "extensibility.abx", "runnableId": "a1"}
    ]
    (f,) = check_008(d)
    assert "referenced by subscription(s): hook" in f.affected[0].detail
    assert "the event or the conditions never matched" in f.affected[0].detail


def test_apr_002_flags_only_readable_user_gates_without_approvers():
    from vcf_automation_assessment_tool.checks.governance import (
        apr_002_approval_policies_without_approvers as check_apr3,
    )
    from vcf_automation_assessment_tool.models import AssessmentData

    def data_with(policies):
        d = AssessmentData()
        d.derived["project_names"] = {"p1": "Platform"}
        d.raw["governance"] = {"approval_policies": policies}
        return d

    base = {
        "id": "ap1",
        "name": "silent-gate",
        "enforcementType": "HARD",
        "projectId": "p1",
        "level": 1,
        "approvalMode": "ANY_OF",
        "approverType": "USER",
        "approvers": [],
        "autoApprovalDecision": "REJECT",
        "autoApprovalExpiry": 7,
        "actions": ["Deployment.Create"],
    }
    (f,) = check_apr3(data_with([base]))
    assert f.check_id == "APR-002"
    row = f.affected[0]
    assert row.name == "silent-gate" and row.project == "Platform"
    assert "HARD gate at level 1 on Deployment.Create" in row.detail
    assert "requests wait 7 day(s), then the platform decides REJECT" in row.detail

    # Org scope labels as organization; unreadable expiry stays honest.
    org = {**base, "projectId": "", "autoApprovalDecision": "", "autoApprovalExpiry": None}
    (f,) = check_apr3(data_with([org]))
    assert f.affected[0].project == "organization"
    assert "auto-expiry outcome could not be read" in f.affected[0].detail

    # Guards: named approvers, a role-resolved audience, and a definition
    # with no readable content (missing vs unread) all stay silent.
    assert check_apr3(data_with([{**base, "approvers": ["USER:manager@x"]}])) == []
    assert check_apr3(data_with([{**base, "approverType": "ROLE"}])) == []
    unread = {
        "id": "ap2",
        "name": "unread",
        "enforcementType": "HARD",
        "projectId": "p1",
        "level": None,
        "approvalMode": "",
        "approverType": "",
        "approvers": [],
        "autoApprovalDecision": "",
        "autoApprovalExpiry": None,
        "actions": [],
    }
    assert check_apr3(data_with([unread])) == []


def test_policy_coverage_absence_guards():
    from vcf_automation_assessment_tool.checks.governance import _projects_without_policy_type
    from vcf_automation_assessment_tool.models import AssessmentData

    def data_with(policies, projects=None):
        d = AssessmentData()
        d.derived["project_names"] = (
            dict(projects) if projects is not None else {"p1": "Platform", "p2": "Empty"}
        )
        d.raw["governance"] = {"policies": policies}
        return d

    day2 = "com.vmware.policy.deployment.action"
    # No project list, or a recorded policies gap: nothing is claimed.
    assert _projects_without_policy_type(data_with([], projects={}), "action") == ([], [], [])
    gapped = data_with([])
    gapped.record_error("governance", "policies", "HTTP 403")
    assert _projects_without_policy_type(gapped, "action") == ([], [], [])
    # --skip governance and a crashed collector never set the policies key;
    # an empty read through that gap must not become an absence claim.
    for item in ("skipped", "collector"):
        absent = AssessmentData()
        absent.derived["project_names"] = {"p1": "Platform"}
        absent.record_error("governance", item, "gap")
        assert _projects_without_policy_type(absent, "action") == ([], [], [])
    # An organization-wide policy (no criteria) covers every project.
    assert _projects_without_policy_type(data_with([{"typeId": day2}]), "action") == ([], [], [])
    # Criteria the walker cannot fully read no longer silence the list (a
    # live estate read that silence as "all covered"): the policy comes back
    # by name so the finding can flag the uncertainty.
    weird = [
        {
            "typeId": day2,
            "name": "Default-Day2",
            "scopeCriteria": {
                "matchExpression": [{"key": "customProp", "operator": "eq", "value": "x"}]
            },
        }
    ]
    uncovered, unresolved, _ = _projects_without_policy_type(data_with(weird), "action")
    assert uncovered == [("p2", "Empty"), ("p1", "Platform")]
    assert unresolved == ["Default-Day2"]
    # Resolvable criteria cover the projects they name (by name or id).
    named = [
        {
            "typeId": day2,
            "scopeCriteria": {
                "matchExpression": [{"key": "project.name", "operator": "eq", "value": "Platform"}]
            },
        }
    ]
    assert _projects_without_policy_type(data_with(named), "action") == ([("p2", "Empty")], [], [])
    # A project-scoped policy covers only its own project.
    scoped = [{"typeId": day2, "projectId": "p1"}]
    assert _projects_without_policy_type(data_with(scoped), "action") == ([("p2", "Empty")], [], [])
    # Partially readable criteria still count what they resolve AND flag the
    # remainder: Platform is covered by the readable clause, Empty is listed
    # with the caveat.
    mixed = [
        {
            "typeId": day2,
            "name": "Default-Day2",
            "scopeCriteria": {
                "matchExpression": [
                    {"key": "project.name", "operator": "eq", "value": "Platform"},
                    {"key": "customProp", "operator": "eq", "value": "x"},
                ]
            },
        }
    ]
    uncovered, unresolved, _ = _projects_without_policy_type(data_with(mixed), "action")
    assert uncovered == [("p2", "Empty")]
    assert unresolved == ["Default-Day2"]


def test_policy_coverage_caveat_names_unevaluable_org_policy():
    from vcf_automation_assessment_tool.checks.governance import (
        pol_004_projects_without_day2_policy,
    )
    from vcf_automation_assessment_tool.models import AssessmentData

    d = AssessmentData()
    d.derived["project_names"] = {"p1": "Platform", "p2": "Empty"}
    d.raw["governance"] = {
        "policies": [
            {
                "typeId": "com.vmware.policy.deployment.action",
                "name": "Default-Day2",
                "scopeCriteria": {
                    "matchExpression": [{"key": "customProp", "operator": "eq", "value": "x"}]
                },
            }
        ]
    }
    (f,) = pol_004_projects_without_day2_policy(d)
    assert "CAVEAT: organization-scoped day-2 action policy(ies) 'Default-Day2'" in f.recommendation
    assert "may cover some or all" in f.recommendation
    assert f.affected[0].detail == (
        "no day-2 action policy visibly applies (project-scoped or resolvable organization scope)"
    )


def test_ext_005_criteria_id_resolution():
    from vcf_automation_assessment_tool.checks.governance import (
        _criteria_id_labels,
        ext_005_id_pinned_criteria,
        subscription_criteria_refs,
    )
    from vcf_automation_assessment_tool.models import AssessmentData

    sub = {
        "criteria_blueprint_ids": ["bp-live", "bp-dead"],
        "criteria_project_ids": ["p-live"],
    }
    labels = _criteria_id_labels(sub, {"bp-live": "Web Server"}, {"p-live": "Platform"})
    assert labels == [
        "blueprint: 'Web Server', (unknown blueprint bp-dead)",
        "project: 'Platform'",
    ]
    # Uncollected object lists show the bare id prefix: missing and unread are
    # indistinguishable, so no "unknown" claim either way.
    labels = _criteria_id_labels(sub, {}, {})
    assert labels == ["blueprint: bp-live, bp-dead", "project: p-live"]

    # The finding skips builtins and subscriptions without pinned ids.
    data = AssessmentData()
    data.raw["extensibility"] = {
        "subscriptions": [
            {"id": "s1", "name": "pinned", "criteria_blueprint_ids": ["bp-x"]},
            {"id": "s2", "name": "global", "criteria_blueprint_ids": []},
            {"id": "s3", "name": "system", "criteria_blueprint_ids": ["bp-x"], "builtin": True},
        ]
    }
    (f,) = ext_005_id_pinned_criteria(data)
    assert [a.name for a in f.affected] == ["pinned"]
    # The criteria column's resolution map keeps builtins - they render when
    # --include-system-subscriptions is set.
    refs = subscription_criteria_refs(data)
    assert refs == {"s1": "blueprint: bp-x", "s3": "blueprint: bp-x"}


def test_tag_003_dedupes_duplicate_assignments(sample_data):
    # Live regression: the same fabric network appears once per collection
    # path, and TAG-003 read "assigned to seg-241, seg-241".
    uses = sample_data.derived["capability_tags"]["net:prod"]
    uses.append(dict(uses[0]))
    build_flows(sample_data)
    run_checks(sample_data)
    f = get(sample_data.findings, "TAG-003")
    net = next(a for a in f.affected if a.name == "net:prod")
    assert net.detail.count(f"'{uses[0]['name']}'") == 1


def test_rep_checks_always_run(sample_data):
    # The REP family used to be gated on meta["replatforming"]. It always
    # runs now, so the data is there whether or not the section is shown;
    # hiding it is the report's job (see the report tests).
    build_flows(sample_data)
    run_checks(sample_data)
    assert any(f.check_id.startswith("REP-") for f in sample_data.findings)
    # The always-on health checks fire in the default assessment too: the
    # hardcoded-values check (BLU-003) and the ABX code-quality check
    # (EXT-003 - the ABX inventory table shows issue counts, so the finding
    # detailing them cannot be hidden away).
    assert get(sample_data.findings, "BLU-003") is not None
    assert get(sample_data.findings, "EXT-003") is not None


def test_rep_003_dedupe_and_detail_labels():
    from vcf_automation_assessment_tool.models import AssessmentData

    data = AssessmentData()
    data.derived["project_names"] = {"p1": "Platform"}
    data.raw["extensibility"] = {
        "subscriptions": [
            {
                "id": "s1",
                "name": "AD - Add Computer",
                "eventTopicId": "compute.provision.pre",
                "runnableType": "extensibility.vco",
                "runnableId": "wf1",
                "runnableName": "AD - Add Computer",
                "builtin": False,
            }
        ],
    }
    data.raw["blueprints"] = {
        "custom_resource_types": [],
        "custom_resource_actions": [
            # Same id twice (form-service can repeat entries) plus a same-name
            # action on a different resource type - 2 real dependencies.
            {
                "id": "cra1",
                "name": "Schedule Deletion",
                "resourceType": "vcVirtualMachine",
                "projectId": "p1",
            },
            {
                "id": "cra1",
                "name": "Schedule Deletion",
                "resourceType": "vcVirtualMachine",
                "projectId": "p1",
            },
            {
                "id": "cra2",
                "name": "Schedule Deletion",
                "resourceType": "vcActiveDirectory",
                "projectId": "p1",
            },
        ],
    }
    run_checks(data)
    f = get(data.findings, "REP-003")
    assert len(f.affected) == 3  # duplicate id collapsed
    # Subscription named after its workflow: the name is not repeated.
    sub = next(a for a in f.affected if a.kind == "subscription")
    assert sub.detail == "subscription on compute.provision.pre"
    actions = [a for a in f.affected if a.kind == "custom-resource-action"]
    assert {a.detail for a in actions} == {
        "custom day-2 action on vcVirtualMachine - backed by an Orchestrator workflow",
        "custom day-2 action on vcActiveDirectory - backed by an Orchestrator workflow",
    }
    assert all(a.project == "Platform" for a in actions)


def test_checks_survive_empty_data():
    from vcf_automation_assessment_tool.models import AssessmentData

    data = AssessmentData()
    build_flows(data)
    run_checks(data)
    assert data.findings == []


def test_pol_001_subset_coverage_and_missing_project_map():
    from vcf_automation_assessment_tool.checks.governance import (
        pol_001_per_project_policy_copies,
    )
    from vcf_automation_assessment_tool.models import AssessmentData

    def _policies():
        return [
            {
                "id": f"c{i}",
                "name": f"share-{i}",
                "typeId": "com.vmware.policy.catalog.entitlement",
                "enforcementType": "HARD",
                "projectId": f"p{i}",
                "definition": {"x": 1},
            }
            for i in (1, 2)
        ]

    # Group covers 2 of 3 known projects: the replacement must carry scope
    # criteria or it would widen to the whole org.
    data = AssessmentData()
    data.raw["governance"] = {"policies": _policies()}
    data.derived["project_names"] = {"p1": "Alpha", "p2": "Beta", "p3": "Gamma"}
    row = pol_001_per_project_policy_copies(data)[0].affected[0]
    assert "They cover 2 of 3 projects, so the replacement needs scope criteria." in row.detail
    assert "\u2022 share-1 (Alpha)\n\u2022 share-2 (Beta)" in row.detail
    assert "content sharing" in row.detail  # UI type words, never "entitlement"

    # Without a project map the coverage claim is withheld - covers-all and
    # covers-some are indistinguishable (same honesty rule as POL-002).
    bare = AssessmentData()
    bare.raw["governance"] = {"policies": _policies()}
    row = pol_001_per_project_policy_copies(bare)[0].affected[0]
    assert "covers" not in row.detail
    assert "• share-1 (p1)\n• share-2 (p2)" in row.detail  # raw ids still listed


def test_inf_003_and_005_evidence_rules():
    from vcf_automation_assessment_tool.checks.infrastructure import (
        inf_003_unhealthy_endpoints,
        inf_004_untagged_endpoints,
    )
    from vcf_automation_assessment_tool.models import AssessmentData

    data = AssessmentData()
    data.raw["infrastructure"] = {
        "cloud_accounts": [{"id": "a1", "name": "no-status", "cloudAccountType": "vsphere"}],
        "integrations": [
            {"id": "i1", "name": "gitlab", "integrationType": "com.gitlab", "tags": []},
            {"id": "i2", "name": "vro-ext", "integrationType": "vro-gateway", "tags": []},
        ],
    }
    # No document exposes a status: stay silent - some builds simply do not
    # return one over the public API, and no status is unknown, not unhealthy.
    assert inf_003_unhealthy_endpoints(data) == []
    # Untagged: the account and the vRO integration; source-control and other
    # non-vRO integrations have no capability-tag mechanism, so never listed.
    names = [a.name for a in inf_004_untagged_endpoints(data)[0].affected]
    assert names == ["no-status", "vro-ext"]

    # A status buried in a properties bag is provider configuration, not the
    # endpoint's own health: never read, so no CRITICAL over a settings key.
    data.raw["infrastructure"]["cloud_accounts"][0]["cloudAccountProperties"] = {
        "status": "UNAVAILABLE"
    }
    assert inf_003_unhealthy_endpoints(data) == []
    # The document's own status field is what counts.
    data.raw["infrastructure"]["cloud_accounts"][0]["status"] = "UNAVAILABLE"
    f = inf_003_unhealthy_endpoints(data)[0]
    assert [a.name for a in f.affected] == ["no-status"]
    assert "status UNAVAILABLE (vsphere)" in f.affected[0].detail


def test_inf_003_does_not_flag_maintenance_status():
    from vcf_automation_assessment_tool.checks.infrastructure import (
        inf_003_unhealthy_endpoints,
    )
    from vcf_automation_assessment_tool.models import OK_ENDPOINT_STATUSES, AssessmentData

    data = AssessmentData()
    data.raw["infrastructure"] = {
        "cloud_accounts": [
            {
                "id": "a1",
                "name": "planned-maintenance",
                "cloudAccountType": "vsphere",
                "status": "MAINTENANCE",
            },
            {
                "id": "a2",
                "name": "broken",
                "cloudAccountType": "vsphere",
                "healthy": False,
            },
        ],
        "integrations": [],
    }

    assert "MAINTENANCE" in OK_ENDPOINT_STATUSES
    finding = inf_003_unhealthy_endpoints(data)[0]
    assert [affected.name for affected in finding.affected] == ["broken"]


def test_capability_map_includes_cloud_account_tags():
    # The fixture hand-builds derived["capability_tags"], so pin the collector
    # side too: account tags land in the map (inherited by the account's
    # computes at placement time); integration tags stay out (vRO capability
    # tags route workflow runs, not placement).
    from vcf_automation_assessment_tool.collectors.infrastructure import (
        _build_capability_tag_map,
    )

    raw = {
        "cloud_accounts": [{"id": "ca1", "name": "vc", "tags": [{"key": "site", "value": "dc1"}]}],
        "integrations": [
            {"id": "i1", "name": "vro", "integrationType": "vro", "tags": [{"key": "x"}]}
        ],
    }
    tag_map = _build_capability_tag_map(raw)
    assert [u["kind"] for u in tag_map["site:dc1"]] == ["cloud-account"]
    assert "inherited" in tag_map["site:dc1"][0]["via"]
    assert "x" not in tag_map


def test_pol_001_order_insensitive_grouping_perf_credit():
    # Live bug: "PERF - Day 2 Action Policy" and "CREDIT - Day 2 Action
    # Policy" are identical day-2 action policies with the same actions list
    # in different order. The old byte-identical grouping key missed them; the
    # new canonical form normalizes element order away and groups them into
    # one finding.
    from vcf_automation_assessment_tool.checks.governance import (
        pol_001_per_project_policy_copies,
    )
    from vcf_automation_assessment_tool.models import AssessmentData

    data = AssessmentData()
    data.derived["project_names"] = {"perf-proj": "PERF", "credit-proj": "CREDIT"}
    actions = [
        "Cloud.vSphere.Machine.Delete",
        "Cloud.vSphere.Machine.Unregister",
        "Deployment.ChangeLease",
    ]
    data.raw["governance"] = {
        "policies": [
            {
                "id": "pol-perf",
                "name": "PERF - Day 2 Action Policy",
                "typeId": "com.vmware.policy.deployment.action",
                "enforcementType": "HARD",
                "projectId": "perf-proj",
                "definition": {"actions": actions},
            },
            {
                "id": "pol-credit",
                "name": "CREDIT - Day 2 Action Policy",
                "typeId": "com.vmware.policy.deployment.action",
                "enforcementType": "HARD",
                "projectId": "credit-proj",
                "definition": {"actions": list(reversed(actions))},  # Same actions, different order
            },
        ]
    }
    findings = pol_001_per_project_policy_copies(data)
    assert len(findings) == 1
    affected = findings[0].affected
    assert len(affected) == 1
    group = affected[0]
    assert group.project == "2 projects"
    assert "2 identical HARD day-2 action policies" in group.detail
    assert "They cover every project (2), so one organization-wide policy" in group.detail
    assert "PERF - Day 2 Action Policy" in group.detail
    assert "CREDIT - Day 2 Action Policy" in group.detail


def test_pol_001_no_grouping_genuinely_different_definitions():
    # Two policies with the same typeId, enforcementType, and projectIds but
    # genuinely different definitions must not group. Difference is legitimate
    # per-project policy configuration.
    from vcf_automation_assessment_tool.checks.governance import (
        pol_001_per_project_policy_copies,
    )
    from vcf_automation_assessment_tool.models import AssessmentData

    data = AssessmentData()
    data.derived["project_names"] = {"p1": "Alpha", "p2": "Beta"}
    data.raw["governance"] = {
        "policies": [
            {
                "id": "pol-1",
                "name": "Quota A",
                "typeId": "com.vmware.policy.resource.quota",
                "enforcementType": "HARD",
                "projectId": "p1",
                "definition": {"cpuLimit": 100},
            },
            {
                "id": "pol-2",
                "name": "Quota B",
                "typeId": "com.vmware.policy.resource.quota",
                "enforcementType": "HARD",
                "projectId": "p2",
                "definition": {"cpuLimit": 200},  # Different value
            },
        ]
    }
    findings = pol_001_per_project_policy_copies(data)
    assert findings == []  # No POL-001 finding


def test_pol_001_mixed_type_list_order_insensitive():
    # A policy definition containing a mixed-type list (strings, ints, None,
    # and a dict) in different orders must group without raising TypeError.
    # The canonical form uses JSON string comparison as the sort key, which
    # handles heterogeneous types by their serialized form.
    from vcf_automation_assessment_tool.checks.governance import (
        pol_001_per_project_policy_copies,
    )
    from vcf_automation_assessment_tool.models import AssessmentData

    data = AssessmentData()
    data.derived["project_names"] = {"p1": "ProjectA", "p2": "ProjectB"}
    mixed_list = ["string-value", 42, None, {"key": "nested-dict"}]
    rotated_list = [42, {"key": "nested-dict"}, "string-value", None]
    data.raw["governance"] = {
        "policies": [
            {
                "id": "pol-1",
                "name": "Mixed Type Policy",
                "typeId": "com.vmware.policy.approval",
                "enforcementType": "SOFT",
                "projectId": "p1",
                "definition": {"elements": mixed_list},
            },
            {
                "id": "pol-2",
                "name": "Mixed Type Policy",
                "typeId": "com.vmware.policy.approval",
                "enforcementType": "SOFT",
                "projectId": "p2",
                "definition": {"elements": rotated_list},
            },
        ]
    }
    # Should not raise TypeError, and should group into one finding
    findings = pol_001_per_project_policy_copies(data)
    assert len(findings) == 1
    assert len(findings[0].affected) == 1
    assert "2 identical SOFT approval policies" in findings[0].affected[0].detail


def test_absence_checks_go_silent_on_collection_gaps(sample_data):
    """CAT-001, PRJ-001 and TAG-001 claim absences over other areas' data;
    a recorded gap in an area each depends on silences the claim, while
    unrelated per-item gaps do not."""
    from vcf_automation_assessment_tool.checks.blueprints import tag_001_unmatched_hard
    from vcf_automation_assessment_tool.checks.catalog import cat_001_unused_items
    from vcf_automation_assessment_tool.checks.infrastructure import prj_001_empty_projects
    from vcf_automation_assessment_tool.models import AssessmentData

    # The fixture genuinely fires CAT-001 and TAG-001 with no gaps recorded.
    assert cat_001_unused_items(sample_data)
    assert tag_001_unmatched_hard(sample_data)
    # A per-deployment resource gap leaves the deployment counter intact.
    sample_data.record_error("deployments", "resources:web-01", "timeout")
    assert cat_001_unused_items(sample_data)
    # The listing itself failing silences the deletion-candidate claim.
    sample_data.record_error("deployments", "deployments", "HTTP 403")
    assert cat_001_unused_items(sample_data) == []
    # Any tag-bearing infrastructure fetch failing silences TAG-001.
    sample_data.record_error("infrastructure", "fabric_computes", "HTTP 403")
    assert tag_001_unmatched_hard(sample_data) == []

    d = AssessmentData()
    d.raw["infrastructure"] = {"projects": [{"id": "p1", "name": "Ghost"}]}
    assert prj_001_empty_projects(d)
    d.record_error("blueprints", "blueprints", "HTTP 500")
    assert prj_001_empty_projects(d) == []
    d2 = AssessmentData()
    d2.raw["infrastructure"] = {"projects": [{"id": "p1", "name": "Ghost"}]}
    d2.record_error("deployments", "skipped", "area skipped via --skip")
    assert prj_001_empty_projects(d2) == []


def test_prj_002_supervisors_count_as_members():
    """The Project model's fourth role (confirmed in the build's swagger):
    a supervisors-only project is administered, not memberless."""
    from vcf_automation_assessment_tool.checks.infrastructure import prj_002_memberless_projects
    from vcf_automation_assessment_tool.models import AssessmentData

    d = AssessmentData()
    d.raw["infrastructure"] = {
        "projects": [
            {"id": "p1", "name": "Supervised", "supervisors": [{"email": "boss@corp"}]},
            {"id": "p2", "name": "Empty"},
        ]
    }
    findings = prj_002_memberless_projects(d)
    assert [a.name for a in findings[0].affected] == ["Empty"]


def test_pedantic_flag_gates_hygiene_signals_only():
    """Hygiene signals reach the report only under --pedantic; defect-level
    ones always do. Both are always present in the collected data."""
    from vcf_automation_assessment_tool.checks.governance import ext_003_abx_code_quality
    from vcf_automation_assessment_tool.checks.vro import vro_001_action_code_quality
    from vcf_automation_assessment_tool.models import AssessmentData

    def build(pedantic):
        data = AssessmentData()
        data.meta["pedantic"] = pedantic
        action = {
            "id": "a1",
            "name": "untidy",
            "runtime": "python",
            "has_inline_source": True,
            "issues": ["2 bare except clause(s)"],
            "pedantic_issues": ["minor code issue: 'from json import *' used (line 1)"],
        }
        data.raw["extensibility"] = {"abx_actions": [action]}
        data.raw["vro"] = {
            "actions": [{**action, "fqn": "com.example/untidy"}],
        }
        return data

    off = build(False)
    ext = ext_003_abx_code_quality(off)[0]
    assert "bare except" in ext.affected[0].detail
    assert "minor code issue" not in ext.affected[0].detail
    assert "minor code issue" not in vro_001_action_code_quality(off)[0].affected[0].detail

    on = build(True)
    assert "minor code issue" in ext_003_abx_code_quality(on)[0].affected[0].detail
    assert "minor code issue" in vro_001_action_code_quality(on)[0].affected[0].detail


def test_pedantic_only_action_is_silent_by_default():
    """An action whose ONLY signals are hygiene-level must not be listed at
    all without the flag - not listed with an empty bullet list."""
    from vcf_automation_assessment_tool.checks.governance import ext_003_abx_code_quality
    from vcf_automation_assessment_tool.models import AssessmentData

    data = AssessmentData()
    data.raw["extensibility"] = {
        "abx_actions": [
            {
                "id": "a1",
                "name": "tidy-enough",
                "runtime": "python",
                "has_inline_source": True,
                "issues": [],
                "pedantic_issues": ["minor code issue: something minor (line 1)"],
            }
        ]
    }
    assert ext_003_abx_code_quality(data) == []
    data.meta["pedantic"] = True
    assert len(ext_003_abx_code_quality(data)[0].affected) == 1
