"""Extensibility, policy and approval checks (EXT-001..009, POL-001..006,
APR-001..002)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from .. import codequality
from ..models import AffectedObject, AssessmentData, Finding, Severity
from . import action_issues, check

# The UI's policy type names, not the API's ("content sharing", never
# "entitlement" - matches POLICY_TYPE_LABELS on the policy tables).
POLICY_TYPE_WORDS = {
    "approval": "approval",
    "entitlement": "content sharing",
    "action": "day-2 action",
    "lease": "lease",
    "limit": "deployment limit",
    "quota": "resource quota",
}


def _policy_type_word(type_id: str | None) -> str:
    raw = (type_id or "").rsplit(".", 1)[-1]
    return POLICY_TYPE_WORDS.get(raw, raw)


def _subs(data: AssessmentData) -> list[dict]:
    return data.raw.get("extensibility", {}).get("subscriptions", [])


def _sub_obj(s: dict, detail: str) -> AffectedObject:
    return AffectedObject(
        kind="subscription", id=s.get("id", ""), name=s.get("name", ""), detail=detail
    )


def _blueprint_names(data: AssessmentData) -> dict[str, str]:
    # The pre-filter snapshot first: under --project the raw list holds only
    # the wanted projects' blueprints, and a criteria pinned to a
    # filtered-out (but existing) blueprint must not be labelled deleted.
    names = dict(data.derived.get("blueprint_names") or {})
    for b in data.raw.get("blueprints", {}).get("blueprints", []):
        if b.get("id"):
            names[b["id"]] = b.get("name", "")
    return names


def _criteria_id_labels(
    sub: dict, blueprint_names: dict[str, str], project_names: dict[str, str]
) -> list[str]:
    """Resolve the id literals a subscription's criteria pins to names.

    One entry per reference kind. A collected list without the id means the
    object was deleted (EXT-001's territory) and says "unknown"; when the
    list was not collected at all, the bare id prefix is shown with no claim
    either way - missing and unread are indistinguishable.
    """

    def label(ref_id: str, names: dict[str, str], kind: str) -> str:
        if not names:
            return ref_id[:8]
        # Membership, not truthiness: an object collected with an empty name
        # exists - only a genuinely absent id earns the deleted-object label.
        if ref_id in names:
            return f"'{names[ref_id]}'" if names[ref_id] else ref_id[:8]
        return f"(unknown {kind} {ref_id[:8]})"

    parts = []
    bp_ids = sub.get("criteria_blueprint_ids") or []
    proj_ids = sub.get("criteria_project_ids") or []
    if bp_ids:
        parts.append(
            "blueprint: " + ", ".join(label(i, blueprint_names, "blueprint") for i in bp_ids)
        )
    if proj_ids:
        parts.append("project: " + ", ".join(label(i, project_names, "project") for i in proj_ids))
    return parts


def subscription_criteria_refs(data: AssessmentData) -> dict[str, str]:
    """Per-subscription resolution line for the report's Criteria column,
    keyed by subscription id: what the id literals in the criteria point at
    on this instance."""
    blueprint_names = _blueprint_names(data)
    project_names = data.derived.get("project_names", {})
    refs = {}
    for s in _subs(data):
        parts = _criteria_id_labels(s, blueprint_names, project_names)
        if parts:
            refs[s.get("id", "")] = "; ".join(parts)
    return refs


@check
def ext_001_broken_subscriptions(data: AssessmentData) -> list[Finding]:
    blueprint_ids = set(_blueprint_names(data))
    project_ids = set(data.derived.get("project_names", {}))
    affected = []
    for s in _subs(data):
        if s.get("builtin"):
            continue
        problems = []
        if s.get("runnableResolved") is False:
            problems.append(
                f"the script or workflow it runs ({s['runnableType']}:"
                f"{s['runnableId']}) was not found"
            )
        if blueprint_ids:
            missing_bps = [b for b in s.get("criteria_blueprint_ids", []) if b not in blueprint_ids]
            if missing_bps:
                problems.append(
                    f"its conditions name {len(missing_bps)} template(s) that no longer exist"
                )
        if project_ids:
            missing_projects = [
                p for p in s.get("criteria_project_ids", []) if p not in project_ids
            ]
            if missing_projects:
                problems.append(
                    f"its conditions name {len(missing_projects)} project(s) that no longer exist"
                )
        if problems:
            affected.append(_sub_obj(s, "; ".join(problems)))
    if not affected:
        return []
    return [
        Finding(
            check_id="EXT-001",
            title="Subscriptions that point at something deleted",
            severity=Severity.WARNING,
            recommendation=(
                "Repair the subscription's missing references, or retire it if no "
                "longer needed.\n"
                "Only ABX actions are checked for existence. An Orchestrator "
                "workflow cannot be checked through the API, because a workflow on "
                "another Orchestrator, and one this account may not see, look the "
                "same as a deleted one."
            ),
            affected=affected,
        )
    ]


@check
def ext_002_disabled_subscriptions(data: AssessmentData) -> list[Finding]:
    affected = [
        _sub_obj(s, f"topic={s['eventTopicId']}")
        for s in _subs(data)
        if s.get("disabled") and not s.get("builtin")
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="EXT-002",
            title="Disabled event subscriptions",
            # A disabled subscription is automation somebody built and
            # switched off: either the behaviour it provided is silently
            # absent today, or it is dead weight nobody has removed. Both
            # want a decision, which is cleanup rather than inventory.
            severity=Severity.WARNING,
            recommendation=(
                "Confirm the intended behaviour with the owner, then re-enable or "
                "retire the subscription.\n"
                "If it is wanted, something has been silently missing since it was "
                "switched off. If it is not, a disabled subscription survives "
                "content imports and can be re-enabled by accident."
            ),
            affected=affected,
        )
    ]


@check
def ext_005_id_pinned_criteria(data: AssessmentData) -> list[Finding]:
    """Subscription criteria comparing against literal blueprint/project ids.

    Ids are minted per instance, so id-pinned criteria stop matching -
    silently, the subscription just never fires - once the content moves to
    another tenant/instance or the referenced object is recreated in place.
    Detection is the collector's best-effort id extraction: criteria pinning
    ids in forms it cannot read are not flagged.
    """
    blueprint_names = _blueprint_names(data)
    project_names = data.derived.get("project_names", {})
    affected = []
    for s in _subs(data):
        if s.get("builtin"):
            continue
        parts = _criteria_id_labels(s, blueprint_names, project_names)
        if parts:
            affected.append(_sub_obj(s, "\n".join(parts)))
    if not affected:
        return []
    return [
        Finding(
            check_id="EXT-005",
            title="Subscription conditions tied to ids from this system",
            severity=Severity.INFO,
            recommendation=(
                "Replace fixed template or project IDs with stable event properties "
                "where possible.\n"
                "Content copied to another system is given new ids, so the "
                "conditions match nothing there and the subscription stops running "
                "without warning. Deleting and recreating the template or project "
                "here has the same effect.\n"
                "If the subscriptions have to move as they are, plan a step that "
                "maps the old ids to the new ones.\n"
                "Each row shows what its ids point at today."
            ),
            affected=affected,
        )
    ]


@check
def ext_006_abx_actions_without_recorded_runs(data: AssessmentData) -> list[Finding]:
    """ABX actions with no run in the platform's retained run history.

    Evidence-guarded: silent when the per-action lookups did not run or did
    not complete (an action not looked up is not a never-ran action), and
    when recorded runs map onto no inventoried action id (defensive - the
    lookups key evidence by inventory id, so a zero overlap means the data
    cannot be trusted).
    """
    ext = data.raw.get("extensibility", {})
    evidence = ext.get("abx_run_evidence") or {}
    actions = ext.get("abx_actions", [])
    if not (evidence.get("collected") and evidence.get("complete") and actions):
        return []
    by_action = evidence.get("by_action") or {}
    action_ids = {a.get("id") for a in actions if a.get("id")}
    if by_action and not (action_ids & set(by_action)):
        return []
    project_names = data.derived.get("project_names", {})
    subs_by_runnable: dict[str, list[str]] = {}
    for s in ext.get("subscriptions", []):
        if "abx" in (s.get("runnableType") or ""):
            subs_by_runnable.setdefault(s.get("runnableId") or "", []).append(s.get("name") or "?")

    def refs_for(action: dict) -> list[str]:
        # Same matching as the collector's runnable resolution (id exact or
        # selfLink suffix): a subscription resolved to this action there must
        # not read "no subscription references it" here.
        aid = action.get("id") or ""
        self_link = action.get("selfLink") or ""
        names = list(subs_by_runnable.get(aid, []))
        for rid, sub_names in subs_by_runnable.items():
            if rid and rid != aid and self_link and self_link.endswith(rid):
                names.extend(sub_names)
        return sorted(set(names))

    affected = []
    for a in actions:
        aid = a.get("id") or ""
        if aid in by_action:
            continue
        refs = refs_for(a)
        if refs:
            detail = (
                "referenced by subscription(s): "
                + ", ".join(refs)
                + ", but the event or the conditions never matched in the run "
                + "history the platform still holds"
            )
        else:
            detail = "no recorded runs and no subscription references it"
        pid = a.get("projectId")
        affected.append(
            AffectedObject(
                kind="abx-action",
                id=aid,
                name=a.get("name", ""),
                project=project_names.get(pid, pid),
                detail=detail,
            )
        )
    if not affected:
        return []
    window = ""
    oldest = evidence.get("oldest_run_millis")
    if oldest:
        day = datetime.fromtimestamp(oldest / 1000, tz=UTC).strftime("%Y-%m-%d")
        window = (
            f" The oldest record still held is from {day}, so this view "
            "reaches back at least that far."
        )
    recommendation = (
        "Confirm each action's intended use with its owner before deleting it.\n"
        "An action nothing references and nothing has run is likely dead config to "
        "confirm with its owner, while one a subscription references but that has "
        "never run suggests the event or the conditions never match.\n"
        "The platform keeps run history for a period and then deletes it, so no "
        f"record means no run in that period, not proof the action never ran.{window}"
    )
    return [
        Finding(
            check_id="EXT-006",
            title="ABX actions with no recorded runs",
            severity=Severity.INFO,
            recommendation=recommendation,
            affected=affected,
        )
    ]


@check
def ext_003_abx_code_quality(data: AssessmentData) -> list[Finding]:
    """ABX actions whose source shows static code-quality signals.

    Always on, not part of the opt-in REP family: scripting hygiene is
    an estate health matter regardless of any replacement plan, and the ABX
    inventory table shows per-action issue counts that this finding details.
    Mirrors VRO-001 for vRO actions.
    """
    actions = data.raw.get("extensibility", {}).get("abx_actions", [])
    project_names = data.derived.get("project_names", {})
    affected = []
    for a in actions:
        issues = action_issues(a, data)
        if not issues or not a.get("has_inline_source", True):
            continue
        # One bullet per issue; the report renders newlines as line breaks.
        detail = "\n".join([f"runtime: {a.get('runtime', '?')}"] + [f"• {i}" for i in issues])
        project_id = a.get("projectId")
        affected.append(
            AffectedObject(
                kind="abx-action",
                id=a.get("id", ""),
                name=a.get("name", ""),
                project=project_names.get(project_id, project_id),
                detail=detail,
            )
        )
    if not affected:
        return []
    return [
        Finding(
            check_id="EXT-003",
            title="ABX actions with code-quality signals",
            severity=Severity.WARNING,
            recommendation=(
                "Review the flagged ABX code and fix confirmed defects.\n"
                "This report reads the code but never runs it. It looks for likely "
                "faults, such as a repeated dictionary key, a test that is always "
                "true, or a named entry point the code never defines. It also looks "
                "for error handling that hides the error, addresses and web links "
                "written into the code, values that look like passwords, and "
                "dependencies with no fixed version.\n"
                "Python is read in full. Actions packaged as zip files could not be "
                "read."
            ),
            affected=affected,
        )
    ]


@check
def ext_004_complex_abx_actions(data: AssessmentData) -> list[Finding]:
    """ABX actions that have outgrown the pattern (user request 2026-08-06).

    An ABX action is meant to be a short glue script at a lifecycle moment;
    one that has grown into an application concentrates logic where it is
    hardest to test, review and debug. Rated structurally by
    codequality.complexity_rating (the ABX analogue of VRO-002); only HIGH
    is flagged - MEDIUM stays a table-column matter.
    """
    project_names = data.derived.get("project_names", {})
    affected = []
    for a in data.raw.get("extensibility", {}).get("abx_actions", []):
        if a.get("complexity") != "HIGH":
            continue
        analysis = a.get("analysis") or {}
        code = analysis.get("code_lines") or 0
        if analysis.get("functions") is None:
            drivers = f"{code} code lines (size-only rating: no parser for this runtime)"
        else:
            drivers = (
                f"{code} code lines, {analysis.get('functions') or 0} function(s), "
                f"{analysis.get('branches') or 0} branch point(s)"
            )
        project_id = a.get("projectId")
        affected.append(
            AffectedObject(
                kind="abx-action",
                id=a.get("id", ""),
                name=a.get("name", ""),
                project=project_names.get(project_id, project_id),
                detail=f"runtime: {a.get('runtime', '?')}\n{drivers}",
            )
        )
    if not affected:
        return []
    return [
        Finding(
            check_id="EXT-004",
            title="ABX actions grown beyond a simple script",
            severity=Severity.INFO,
            recommendation=(
                "Consider splitting complex ABX actions into smaller actions or "
                "moving their logic into a workflow.\n"
                "An action should stay a short script that runs at one point in a "
                "deployment's life, and there is no debugger for one: only the run "
                "logs.\n"
                "The rating comes from the structure of the code. Every action's "
                "rating is in the Complexity column of the table above."
            ),
            affected=affected,
        )
    ]


@check
def ext_007_duplicated_action_source(data: AssessmentData) -> list[Finding]:
    """ABX and Orchestrator actions whose source is a copy of another's.

    Estate sizing rather than a per-action complaint: a cluster of five near
    identical actions is one piece of logic to understand, port or fix, not
    five, and a defect found in one of them is probably live in the other
    four. ABX and Orchestrator are compared together because copy-paste
    crosses that boundary in both directions.

    Works from the fingerprint and similarity sketch the collectors retain -
    the source itself is dropped after analysis to keep the JSON dump lean.
    Short actions are excluded: glue scripts that read an input, call one API
    and return are legitimately alike.
    """
    abx = data.raw.get("extensibility", {}).get("abx_actions", [])
    vro_actions = data.raw.get("vro", {}).get("actions", [])
    labels: dict[str, str] = {}
    entries = []
    for a in abx:
        key = f"abx:{a.get('id', '')}:{a.get('name', '')}"
        labels[key] = f"{a.get('name', '')} (ABX)"
        entries.append(_sketch_entry(key, a))
    for a in vro_actions:
        key = f"vro:{a.get('id', '')}:{a.get('fqn', '')}"
        labels[key] = f"{a.get('fqn') or a.get('name', '')} (Orchestrator)"
        entries.append(_sketch_entry(key, a))

    clusters = codequality.duplicate_clusters([e for e in entries if e])
    if not clusters:
        return []
    affected = []
    for cluster in clusters:
        members = cluster["members"]
        match = (
            "identical source"
            if cluster["exact"]
            else f"{round(cluster['similarity'] * 100)}% or more of the source in common"
        )
        detail = "\n".join(
            [f"{len(members)} actions, {match}:"] + [f"\u2022 {labels[m]}" for m in members]
        )
        affected.append(
            AffectedObject(
                kind="action-copies",
                id=members[0],
                name=labels[members[0]],
                detail=detail,
            )
        )
    return [
        Finding(
            check_id="EXT-007",
            title="Actions copied in several places",
            severity=Severity.INFO,
            recommendation=(
                "Check whether each duplicate group can share one action without losing "
                "differences in behaviour.\n"
                "That matters twice: a fix or a security change has to be applied to "
                "every copy, and any effort estimate that counts actions overstates the "
                "work, because a group ports once.\n"
                "Comments, blank lines and formatting are ignored in the comparison, so "
                "groups listed as identical differ only in layout. Actions under "
                f"{codequality.MIN_DUPLICATE_CODE_LINES} lines of code are not compared, "
                "because short connecting scripts look alike by nature."
            ),
            affected=affected,
        )
    ]


def _sketch_entry(key: str, action: dict) -> dict | None:
    """One action as input to the duplicate clustering, or None when it was
    never analyzed (a flow, a bundle, an unreadable detail)."""
    if not action.get("source_sketch"):
        return None
    return {
        "key": key,
        "fingerprint": action.get("source_fingerprint") or "",
        "sketch": action.get("source_sketch") or [],
        "code_lines": (action.get("analysis") or {}).get("code_lines") or 0,
    }


def _canonical(value: object) -> object:
    """Order-insensitive canonical form of a policy definition: dict key
    order and list element order both normalize away. Live data showed the
    same day-2 policy stamped per project with its action list in a
    different sequence - a list in a policy definition is a set in
    meaning, so element order must not defeat the grouping."""
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return sorted(
            (_canonical(v) for v in value),
            key=lambda v: json.dumps(v, sort_keys=True, default=str),
        )
    return value


# What the platform still runs, from the VMware Aria Automation release notes
# (8.13, 8.14, 8.16.1, 8.16.2, 8.18.1). Keyed by the runtime name the ABX
# Action schema uses and the major.minor of its runtimeVersion. A version not
# listed is unknown, never flagged: a newer runtime than these notes describe
# is not a defect.
#   python:     3.7 removed in 8.14 (grace period expired; AWS FaaS in 8.16.2),
#               3.10 current.
#   nodejs:     14 removed in 8.13, 18 deprecated in 8.16.1, 20 current.
#   powershell: 6.2 (PowerCLI 11) removed in 8.14, 7.2 (PowerCLI 12)
#               deprecated in 8.16.1 and removed in 8.18.1, 7.4 current.
ABX_RUNTIME_SUPPORT: dict[str, dict[str, tuple[str, str]]] = {
    "python": {
        "3.7": ("removed", "removed in 8.14; the supported runtime is 3.10"),
        "3.10": ("current", ""),
    },
    "nodejs": {
        "14": ("removed", "removed in 8.13; scripts were switched to 18"),
        "18": ("deprecated", "deprecated in 8.16.1 and will be removed; 20 is current"),
        "20": ("current", ""),
    },
    "powershell": {
        "6.2": ("removed", "PowerCLI 11 runtime removed in 8.14"),
        "7.2": ("removed", "PowerCLI 12 runtime removed in 8.18.1; scripts run on 7.4"),
        "7.4": ("current", ""),
    },
}


def abx_runtime_support(runtime: str, version: str) -> tuple[str, str]:
    """(state, why) for an action's runtime: removed, deprecated, current or unknown.

    The version is matched on major.minor for python and powershell and on the
    major alone for nodejs, which is how the release notes name them. Anything
    the table does not name is unknown, and unknown is never a finding.
    """
    name = (runtime or "").lower()
    table = ABX_RUNTIME_SUPPORT.get(name)
    parts = (version or "").strip().split(".")
    if not table or not parts or not parts[0]:
        return "unknown", ""
    key = parts[0] if name == "nodejs" else ".".join(parts[:2])
    return table.get(key, ("unknown", ""))


@check
def ext_008_abx_actions_on_unsupported_runtimes(data: AssessmentData) -> list[Finding]:
    """ABX actions declared on a runtime the platform has removed or deprecated.

    A removed runtime is a script that no longer runs as written; a deprecated
    one is a script with a date on it. Both come from the action document's
    own runtime and runtimeVersion fields, so an action carrying no version
    makes no claim either way.
    """
    project_names = data.derived.get("project_names", {})
    rows: list[tuple[int, AffectedObject]] = []
    for a in data.raw.get("extensibility", {}).get("abx_actions", []):
        state, why = abx_runtime_support(a.get("runtime") or "", a.get("runtimeVersion") or "")
        if state not in ("removed", "deprecated"):
            continue
        project_id = a.get("projectId") or ""
        provider = a.get("provider") or ""
        rows.append(
            (
                0 if state == "removed" else 1,
                AffectedObject(
                    kind="abx-action",
                    id=a.get("id", ""),
                    name=a.get("name", ""),
                    project=project_names.get(project_id, project_id),
                    detail=(
                        f"{a.get('runtime')} {a.get('runtimeVersion')}: {state}, {why}"
                        + (f"; provider {provider}" if provider else "")
                    ),
                ),
            )
        )
    if not rows:
        return []
    rows.sort(key=lambda r: (r[0], r[1].name.lower()))
    return [
        Finding(
            check_id="EXT-008",
            title="ABX actions on a runtime the platform has removed or deprecated",
            severity=Severity.WARNING,
            recommendation=(
                "Move each action to a runtime supported by the target platform and "
                "test it.\n"
                "Removed runtimes may be substituted or refused; deprecated "
                "runtimes are due for removal. Actions with no recorded version are "
                "not assessed.\n"
                "The support table comes from the release notes up to 8.18.1; a "
                "runtime newer than those notes describe is not listed either."
            ),
            affected=[r[1] for r in rows],
        )
    ]


@check
def ext_009_custom_resource_bindings_to_missing_actions(data: AssessmentData) -> list[Finding]:
    """Custom resource lifecycle slots and day-2 actions bound to an ABX action
    the inventory does not hold.

    Only the ABX side is a claim: the inventory is complete, so an id absent
    from it is absent. A workflow the Orchestrators did not confirm may be
    external or hidden by an ACL, so it is shown in the design tables as
    unconfirmed and never listed here.
    """
    bindings = data.raw.get("vro", {}).get("custom_resource_bindings") or []
    affected = [
        AffectedObject(
            kind=b["owner_kind"].replace(" ", "-"),
            id=b.get("owner_id", ""),
            name=b.get("owner", ""),
            detail=(
                f"{b['action']} runs ABX action {b.get('runnable_name') or b['runnable_id']} "
                f"({b['runnable_id']}), which is not in the ABX inventory"
            ),
        )
        for b in bindings
        if b.get("kind") == "abx" and b.get("confirmed") is False
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="EXT-009",
            title="Custom resources bound to an ABX action that no longer exists",
            severity=Severity.WARNING,
            recommendation=(
                "Rebind the custom resource operation to its replacement ABX "
                "action, or restore the action under its original ID.\n"
                "Use Design > Custom Resources. Orchestrator workflow bindings are "
                "not judged here; external or ACL-hidden workflows may be "
                "unresolvable."
            ),
            affected=affected,
        )
    ]


@check
def pol_001_per_project_policy_copies(data: AssessmentData) -> list[Finding]:
    """Project-scoped policies duplicated across projects.

    Implementations that pre-date org-level policy scoping stamped the same
    policy out once per project. Only definitions that are identical up to
    ordering (same type, same enforcement, with dict key order and list
    element order normalized away) are grouped - policies that genuinely
    differ per project are legitimately project-scoped and stay unflagged.
    """
    policies = data.raw.get("governance", {}).get("policies", [])
    project_names = data.derived.get("project_names", {})

    groups: dict[tuple, list[dict]] = {}
    for p in policies:
        definition = p.get("definition")
        if not p.get("projectId") or not definition:
            continue
        key = (
            p.get("typeId") or "",
            p.get("enforcementType") or "",
            json.dumps(_canonical(definition), sort_keys=True, default=str),
            # Two copies that grant the same thing are still different
            # policies when one of them only acts on tagged deployments.
            json.dumps(_canonical(p.get("criteria")), sort_keys=True, default=str),
        )
        groups.setdefault(key, []).append(p)

    affected = []
    for (type_id, enforcement, _, _criteria_key), plist in sorted(groups.items()):
        projects = {p["projectId"] for p in plist}
        if len(plist) < 2 or len(projects) < 2:
            continue
        names = sorted({p.get("name") or "?" for p in plist})
        display = names[0] if len(names) == 1 else f"{names[0]} (+{len(names) - 1} more names)"
        # Coverage decides the reader's move: a group present in every project
        # swaps straight for one unrestricted org-scoped policy, while a
        # subset needs scope criteria naming its projects (an unrestricted
        # replacement would widen the policy to the whole org). No claim when
        # the project list could not be read - covers-all and covers-some are
        # then indistinguishable.
        if not project_names:
            coverage = ""
        elif set(project_names) <= projects:
            coverage = (
                f" They cover every project ({len(project_names)}), so one "
                "organization-wide policy replaces them directly."
            )
        else:
            coverage = (
                f" They cover {len(projects)} of {len(project_names)} projects, so the "
                "replacement needs scope criteria."
            )
        members = sorted(
            (project_names.get(p.get("projectId"), p.get("projectId") or "?"), p.get("name") or "?")
            for p in plist
        )
        # One copy per line: the report folds a long list behind its count,
        # and a semicolon-separated run of seventeen names does not read.
        shown = "\n".join(f"\u2022 {name} ({proj})" for proj, name in members[:12])
        # Outside the bullet run, so the count on the fold stays a count of
        # copies named.
        more = f"\nand {len(members) - 12} more." if len(members) > 12 else ""
        affected.append(
            AffectedObject(
                kind="policy-group",
                id=plist[0].get("id", ""),
                name=display,
                project=f"{len(projects)} projects",
                detail=(
                    f"{len(plist)} identical {enforcement or '?'} "
                    f"{_policy_type_word(type_id)} policies, one per project.{coverage}\n"
                    f"Delete these copies once the replacement is in place:\n"
                    f"{shown}{more}"
                ),
            )
        )
    if not affected:
        return []
    return [
        Finding(
            check_id="POL-001",
            title="Per-project policy copies that could be one organization-wide policy",
            severity=Severity.INFO,
            recommendation=(
                "Consolidate duplicate policies while preserving their scope and permissions.\n"
                "1. Create an organization-scoped policy with the same definition in "
                "Service Broker > Content & Policies > Policies > Definitions.\n"
                "2. Add scope criteria for the original projects unless the copies "
                "already cover every project.\n"
                "3. Verify the replacement applies correctly before deleting the copies."
            ),
            affected=affected,
        )
    ]


@check
def pol_002_policies_scoped_to_missing_projects(data: AssessmentData) -> list[Finding]:
    """Policies whose project no longer exists.

    Live lesson (2026-08-05, second environment): three content sharing
    policies outlived the project they were scoped to - each still renders
    in every policy review while governing or sharing nothing. Silent when
    the projects list could not be collected: with no project map, "missing"
    is indistinguishable from "unread" (same honesty rule as the catalog
    sharing evidence).
    """
    project_names = data.derived.get("project_names", {})
    if not project_names:
        return []
    affected = []
    for p in data.raw.get("governance", {}).get("policies", []):
        pid = p.get("projectId")
        if not pid or pid in project_names:
            continue
        affected.append(
            AffectedObject(
                kind="policy",
                id=p.get("id", ""),
                name=p.get("name") or "?",
                detail=(
                    f"{p.get('enforcementType') or '?'} {_policy_type_word(p.get('typeId'))} "
                    f"policy scoped to missing project {pid}"
                ),
            )
        )
    if not affected:
        return []
    return [
        Finding(
            check_id="POL-002",
            title="Policies scoped to a project that no longer exists",
            severity=Severity.WARNING,
            recommendation=(
                "Verify the project is gone, then delete the policy or retarget it "
                "if its content moved.\n"
                "A project this account cannot read would also appear here. To be "
                "certain, run the report with read access across the whole "
                "organization."
            ),
            affected=affected,
        )
    ]


_PROJECT_CRITERIA_KEYS = {"project.name", "projectName", "project.id", "projectId"}
_CRITERIA_EQUALITY_OPERATORS = {"eq", "equals"}
_CRITERIA_MEMBERSHIP_OPERATORS = {"in"}
# Containers whose branches are alternatives, and the one whose branches must
# all hold. Compared lowercased: the API spells the outer one matchExpression.
_CRITERIA_ANY_CONTAINERS = {"matchexpression", "or"}
_CRITERIA_ALL_CONTAINERS = {"and"}


def _criteria_tag_keys(criteria: dict | None) -> tuple[list[str], list[str], list[str], bool]:
    """What a policy's own `criteria` block narrows it to, and whether it read cleanly.

    `criteria` is not `scopeCriteria`. scopeCriteria picks the projects a policy
    is scoped to; `criteria` picks the deployments and resources it acts on.
    This build uses two vocabularies inside it, both confirmed from the live
    documents: a hasAny match on properties.tags nested under resources, and a
    test on requestedBy. Clauses are wrapped in and/or groups. Anything else
    marks the walk as incomplete rather than being guessed at.

    Returns the tag keys, the requester tests in plain words, the catalog item
    ids named, and whether every clause was understood.
    """
    keys: list[str] = []
    requesters: list[str] = []
    items: list[str] = []
    fully = True

    def walk(node, under_tags: bool = False) -> None:
        nonlocal fully
        if isinstance(node, list):
            for item in node:
                walk(item, under_tags)
            return
        if not isinstance(node, dict):
            return
        if "matchExpression" in node:
            walk(node["matchExpression"], under_tags)
            return
        for joiner in ("and", "or"):
            if joiner in node:
                walk(node[joiner], under_tags)
                return
        key, value = node.get("key"), node.get("value")
        operator = node.get("operator")
        if key == "properties.tags":
            walk(value, True)
            return
        if key == "resources":
            walk(value, under_tags)
            return
        if key == "catalogItemId" and isinstance(value, str):
            if operator in ("eq", "equals"):
                items.append(value)
            else:
                fully = False
            return
        if key == "requestedBy" and isinstance(value, str):
            if operator in ("eq", "equals"):
                requesters.append(f"the requester is {value}")
            elif operator in ("notEq", "notEquals"):
                requesters.append(f"the requester is not {value}")
            else:
                fully = False
            return
        if under_tags and key == "key" and operator in ("eq", "equals"):
            if isinstance(value, str):
                keys.append(value)
            else:
                fully = False
            return
        if under_tags and key == "value":
            # The tag's value narrows it further; the key alone names the tag.
            return
        fully = False

    walk(criteria)
    return sorted(set(keys)), sorted(set(requesters)), sorted(set(items)), fully


def _criteria_summary(policy: dict, item_names: dict | None = None) -> str:
    """Plain words for what a policy's own criteria narrow it to, or "".

    A narrowed policy governs only what matches, so it never covers everything
    in a project and cannot be compared with a policy that does.
    """
    criteria = policy.get("criteria")
    if not criteria:
        return ""
    keys, requesters, items, fully = _criteria_tag_keys(criteria)
    parts = []
    if len(keys) == 1:
        parts.append(f"the deployment carries the tag {keys[0]}")
    elif keys:
        parts.append("the deployment carries one of the tags " + ", ".join(keys))
    if items:
        named = [(item_names or {}).get(i) for i in items]
        if all(named):
            parts.append("the catalog item is " + ", ".join(sorted(n for n in named if n)))
        else:
            parts.append(f"the catalog item is one of {len(items)} named in the policy")
    parts.extend(requesters)
    if parts and fully:
        return "applies only where " + ", and ".join(parts)
    if parts:
        return (
            "applies only where " + ", and ".join(parts) + ", and where more of its criteria match"
        )
    return "applies only to the deployments its own criteria match"


def _grant_authorities(policy: dict) -> set[str] | None:
    """Who a day-2 policy's grants name, or None when that cannot be read.

    None covers both an unreadable definition and the plain shape that carries
    no authorities at all: an audience nobody can read is not an audience
    anybody can compare.
    """
    definition = policy.get("definition")
    if not isinstance(definition, dict):
        return None
    entries = definition.get("allowedActions")
    if not entries:
        return None
    authorities: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("authorities"):
            return None
        for authority in entry["authorities"]:
            if not isinstance(authority, str):
                return None
            authorities.add(authority)
    return authorities


def _audiences_meet(org: dict, copies: list[dict]) -> bool:
    """True unless the organization policy entitles named accounts that no copy names.

    Day-2 grants accumulate per audience. A policy granting to one service
    account and a project policy granting to that project's members never
    decide the same request between them, so listing the pair as an overlap
    asks the reader to resolve a conflict that does not exist. A role is not
    treated this way: whoever holds it may hold the other one too.
    """
    org_authorities = _grant_authorities(org)
    if not org_authorities:
        return True
    if any(a.upper().startswith("ROLE:") for a in org_authorities):
        return True
    seen: set[str] = set()
    for copy in copies:
        authorities = _grant_authorities(copy)
        if authorities is None:
            return True  # unreadable audience: claim nothing
        seen |= authorities
    return bool(org_authorities & seen)


def _grant_audience_words(policy: dict) -> str:
    """Who a day-2 policy grants to, when it names accounts rather than a role.

    A policy that entitles one service account governs that account's actions.
    Reporting it as governing a project alongside the project's own policy reads
    as a duplicate when the two do not touch the same people.
    """
    definition = policy.get("definition")
    if not isinstance(definition, dict):
        return ""
    named: list[str] = []
    for entry in definition.get("allowedActions") or []:
        if not isinstance(entry, dict):
            return ""
        authorities = entry.get("authorities")
        if not authorities:
            return ""
        for authority in authorities:
            if not isinstance(authority, str) or ":" not in authority:
                return ""
            kind, _, who = authority.partition(":")
            if kind.upper() == "ROLE":
                # A role covers everybody who holds it, so the policy is not
                # narrowed to particular people.
                return ""
            named.append(f"{who} ({kind.lower()})")
    if not named:
        return ""
    unique = sorted(set(named))
    listed = ", ".join(unique[:3])
    more = f", and {len(unique) - 3} more" if len(unique) > 3 else ""
    return f"grants only to {listed}{more}"


def _criteria_project_refs(scope: object) -> tuple[set[str], bool]:
    """Projects an org-scoped policy's scopeCriteria names outright.

    Returns the references found (project names or ids, as written) and
    whether every clause was understood. Anything not understood sets the
    flag false instead of being guessed past, because a wrong coverage set
    produces a wrong overlap claim.

    What is read, and the assumptions behind it:

    * A clause is any dict carrying a "key". Only a project name/id key
      resolves to projects, and only through "equals" against a string or
      "in" against a list of strings. Every other field, operator or value
      shape (a negated operator, a substring match, a non-string value)
      resolves to nothing and marks the walk partly evaluated.
    * List members, and the branches of "or"/"matchExpression", are treated
      as ALTERNATIVES and unioned, matching the OR the UI renders for a
      multi-clause scope.
    * An "and" group is not a union. Where more than one of its branches
      names projects, the group is a contradiction or an intersection rather
      than a wider scope, so those refs are dropped and the walk is marked
      partly evaluated; a single project-bearing branch (project equals X
      AND some other condition) passes through.
    * Any other container key, negation forms such as "not" above all, is
      NOT descended into: a reference inside a negation names a project the
      policy excludes, and collecting it would invert the finding.

    The live encoding has NOT been confirmed against a --json dump. If
    POL-003 stays silent on an estate visibly running a criteria-scoped
    org policy, dump one policy's scopeCriteria and extend this walker to
    the shape it shows.
    """

    def walk(node: object) -> tuple[set[str], bool]:
        if node is None:
            return set(), True
        if isinstance(node, list):
            refs: set[str] = set()
            fully = True
            for item in node:
                item_refs, item_fully = walk(item)
                refs |= item_refs
                fully = fully and item_fully
            return refs, fully
        if isinstance(node, dict):
            if "key" in node:
                key = node["key"]
                if not isinstance(key, str) or key not in _PROJECT_CRITERIA_KEYS:
                    return set(), False
                operator = str(node.get("operator") or "").lower()
                value = node.get("value")
                if operator in _CRITERIA_EQUALITY_OPERATORS and isinstance(value, str):
                    return {value}, True
                if (
                    operator in _CRITERIA_MEMBERSHIP_OPERATORS
                    and isinstance(value, list)
                    and all(isinstance(v, str) for v in value)
                ):
                    return set(value), True
                # The right field in a shape this cannot read: a missing or
                # non-string value, or a list where equality was expected.
                return set(), False
            refs = set()
            fully = True
            for name, value in node.items():
                lowered = str(name).lower()
                if lowered in _CRITERIA_ANY_CONTAINERS:
                    branch_refs, branch_fully = walk(value)
                    refs |= branch_refs
                    fully = fully and branch_fully
                elif lowered in _CRITERIA_ALL_CONTAINERS:
                    branches = value if isinstance(value, list) else [value]
                    bearing: list[set[str]] = []
                    for branch in branches:
                        branch_refs, branch_fully = walk(branch)
                        fully = fully and branch_fully
                        if branch_refs:
                            bearing.append(branch_refs)
                    if len(bearing) == 1:
                        refs |= bearing[0]
                    elif bearing:
                        fully = False
                else:
                    fully = False
            return refs, fully
        return set(), False

    return walk(scope)


def _is_day2_action_policy(type_id: str | None) -> bool:
    """Day-2 action policies only, by the type id's tail ("action").

    Approval policies also carry an actions list in their definition, but it
    names the actions that REQUIRE approval rather than the ones a user is
    granted, so nothing below may be applied to them.
    """
    return (type_id or "").rsplit(".", 1)[-1] == "action"


def _policy_grants(policy: dict) -> list[tuple[frozenset[str], frozenset[str]]] | None:
    """What a policy's definition grants, as (authorities, actions) pairs.

    A day-2 action policy carries its grants as
    definition.allowedActions = [{"actions": [...], "authorities": [...]}],
    where an authority is a string such as "USER:admin" or
    "GROUP:vraadmins@". Evidence grade: DOCUMENTED, not confirmed on this
    build. The shape is taken from VMware's own terraform-provider-vra
    (the JSON tags in vra/policies_helper.go, used by
    resource_policy_day2_action.go), which reads and writes the same
    /policy/api/policies documents this tool collects. It has NOT yet been
    checked against this build's own /policy/api/policyTypes
    definitionSchema, which is the confirming probe; until it has been, the
    plain top-level {"actions": [...]} reading is kept for builds and
    fixtures that carry that instead.

    None means "not comparable", never "grants nothing". Any deviation from
    the two known shapes returns None for the whole policy rather than a
    partial reading. An empty list counts as a deviation on purpose, whether
    it is an entry's actions, the plain actions list or allowedActions
    itself: each could mean "grants nothing" or "every action" depending on
    the build. Read as "grants nothing" an empty project policy becomes a
    false delete candidate, and an empty organization policy covers nothing,
    which would push every copy under it into the "deleting would revoke it"
    bucket.
    """
    definition = policy.get("definition")
    if not isinstance(definition, dict):
        return None

    allowed = definition.get("allowedActions")
    if allowed is not None:
        if not isinstance(allowed, list) or not allowed:
            return None
        grants: list[tuple[frozenset[str], frozenset[str]]] = []
        for entry in allowed:
            if not isinstance(entry, dict):
                return None
            actions = entry.get("actions")
            if not isinstance(actions, list) or not actions:
                return None
            if not all(isinstance(a, str) for a in actions):
                return None
            authorities = entry.get("authorities")
            if authorities is None:
                authorities = []
            if not isinstance(authorities, list) or not all(
                isinstance(a, str) for a in authorities
            ):
                return None
            grants.append((frozenset(authorities), frozenset(actions)))
        return grants

    # The plain shape, held to the same non-empty rule for the same reason.
    plain = definition.get("actions")
    if not isinstance(plain, list) or not plain or not all(isinstance(a, str) for a in plain):
        return None
    return [(frozenset(), frozenset(plain))]


def _grants_covered(
    project_grants: list[tuple[frozenset[str], frozenset[str]]],
    org_grants: list[tuple[frozenset[str], frozenset[str]]],
) -> tuple[bool, set[str]]:
    """Whether the organization policy already grants everything a project
    policy grants, and which actions it does not.

    Containment is per audience, not per action list: the same action given
    to a different user or group is a different grant, so an action counts as
    covered only where the organization policy gives it to that same
    authority. The returned set names the actions that would be revoked, for
    at least one of their authorities, if the project policy were deleted.

    A grant carrying no authorities (the plain shape above, or an entry that
    recorded none) is matched ONLY against organization grants that also
    carry none. Whether an empty authorities list means "every user" is not
    documented anywhere this tool can cite, and symmetric matching is the
    only reading that cannot produce a false delete recommendation: it
    claims coverage in fewer cases, never in more. Callers compare only
    policies written the same way (see _grant_shape), so that symmetry is
    the backstop rather than the first guard.
    """
    by_authority: dict[str, set[str]] = {}
    unattributed: set[str] = set()
    for authorities, actions in org_grants:
        if not authorities:
            unattributed |= set(actions)
            continue
        for authority in authorities:
            by_authority.setdefault(authority, set()).update(actions)

    uncovered: set[str] = set()
    for authorities, actions in project_grants:
        if not authorities:
            uncovered |= set(actions) - unattributed
            continue
        for authority in authorities:
            uncovered |= set(actions) - by_authority.get(authority, set())
    return not uncovered, uncovered


def _grant_shape(grants: list[tuple[frozenset[str], frozenset[str]]]) -> str | None:
    """How a policy names its audiences: "plain", "attributed" or None (mixed).

    "plain" is a definition where no grant names an authority, "attributed"
    one where every grant does. Coverage is only comparable between policies
    written the same way. A plain grant states no audience at all, so under
    the symmetric matching in _grants_covered it can never be covered by an
    attributed grant nor cover one, and comparing the two would read as a
    confident "deleting would revoke it" when the truth is that the audiences
    are not comparable. A definition that mixes the shapes has no single
    audience reading either, so it is not compared.
    """
    if all(authorities for authorities, _ in grants):
        return "attributed"
    if not any(authorities for authorities, _ in grants):
        return "plain"
    return None


def _listed(members: list[tuple[str, str]], cap: int = 8) -> str:
    """The house listing style for policy members: one "Name (Project)" a line,
    ordered by project name, with a plain tail when the list is capped.

    One a line rather than one long comma run: the report folds a run of these
    behind its count, and twenty-five names in a table cell read as noise.
    """
    shown = "\n".join(f"\u2022 {name} ({proj})" for proj, name in sorted(members)[:cap])
    more = f"\nand {len(members) - cap} more." if len(members) > cap else ""
    return f"\n{shown}{more}"


def _day2_overlap_lines(org: dict, overlaps: list[dict], project_names: dict) -> list[str]:
    """One verdict per overlapping day-2 action policy, bucketed.

    Broadcom's "How are Automation Service Broker policies processed"
    (Automation 8.18) documents the merge this reads against: "If there are
    hard and soft policies, then only the hard policies are considered and
    ranked"; organizational policies rank above project policies and older
    above newer; and day-2 merging is a UNION, where the highest-ranking
    policy is the baseline, each lower one is applied on top, and a
    lower-ranked policy already covered by the ones above it is discarded.

    So a project-scoped copy of equal enforcement whose grants the
    organization policy already carries changes nothing and can be deleted;
    a SOFT copy under a HARD organization policy is inert whatever it
    grants; and a HARD copy under a SOFT organization policy displaces the
    organization policy for its project, which is not a redundancy claim.

    Evidence grade: DOCUMENTED (vendor documentation for 8.18), not observed
    on this build. The enforcement verdicts follow from the hard-over-soft
    rule alone, so they stand whether or not either definition can be read.
    Comparing grants needs both sides shaped alike, so a policy whose grants
    cannot be read, an organization policy whose own grants cannot be read,
    and a pair that names its audiences differently all end up listed as not
    compared rather than given a verdict.
    """
    org_grants = _policy_grants(org)
    org_shape = _grant_shape(org_grants) if org_grants is not None else None

    org_enforcement = org.get("enforcementType")
    adds_nothing: list[tuple[str, str]] = []
    superseded: list[tuple[str, str]] = []
    displaces: list[tuple[str, str]] = []
    unreadable: list[tuple[str, str]] = []
    org_unreadable: list[tuple[str, str]] = []
    incomparable_audiences: list[tuple[str, str]] = []
    incomparable_enforcement: list[tuple[str, str]] = []
    still_grants: list[tuple[str, str, list[str]]] = []

    for q in overlaps:
        member = (project_names.get(q["projectId"], q["projectId"]), q.get("name") or "?")
        enforcement = q.get("enforcementType")
        if enforcement != org_enforcement:
            if org_enforcement == "HARD" and enforcement == "SOFT":
                superseded.append(member)
            elif org_enforcement == "SOFT" and enforcement == "HARD":
                displaces.append(member)
            else:
                # Enforcement outside the documented HARD/SOFT pair: which one
                # wins is not something the documentation answers.
                incomparable_enforcement.append(member)
            continue
        # Only equal enforcement needs the definitions: everything above this
        # point is decided by the hard-over-soft rule alone.
        if org_grants is None:
            org_unreadable.append(member)
            continue
        grants = _policy_grants(q)
        if grants is None:
            unreadable.append(member)
            continue
        # Same enforcement, both definitions read: containment is still only
        # meaningful when the two name their audiences the same way.
        if org_shape is None or _grant_shape(grants) != org_shape:
            incomparable_audiences.append(member)
            continue
        covered, uncovered = _grants_covered(grants, org_grants)
        if covered:
            adds_nothing.append(member)
        else:
            still_grants.append((*member, sorted(uncovered)))

    lines = []
    if adds_nothing:
        lines.append(
            "grant nothing this policy does not already grant, delete candidates under "
            f"the platform's union merging:{_listed(adds_nothing)}"
        )
    if still_grants:
        parts = []
        for proj, name, missing in sorted(still_grants, key=lambda m: (m[0], m[1]))[:8]:
            parts.append(f"\u2022 {name} ({proj}): {len(missing)} action(s)")
        tail = f"\nand {len(still_grants) - 8} more." if len(still_grants) > 8 else ""
        lines.append(
            "still grant something this policy does not, so deleting one revokes "
            "what it grants:\n" + "\n".join(parts) + tail
        )
    if superseded:
        lines.append(
            "SOFT copies made inert by this HARD policy (hard supersedes soft):"
            f"{_listed(superseded)}"
        )
    if displaces:
        lines.append(
            f"HARD copies that displace this SOFT policy for their project:{_listed(displaces)}"
        )
    if unreadable:
        lines.append(f"not compared (definition shape not readable):{_listed(unreadable)}")
    if org_unreadable:
        lines.append(
            "not compared (this policy's own definition shape is not readable):"
            f"{_listed(org_unreadable)}"
        )
    if incomparable_audiences:
        lines.append(
            "not compared (one policy names the users and groups it grants to and the "
            f"other does not):{_listed(incomparable_audiences)}"
        )
    if incomparable_enforcement:
        lines.append(
            "not compared (enforcement types differ outside the documented HARD/SOFT pair):"
            f"{_listed(incomparable_enforcement)}"
        )
    return lines


@check
def pol_003_overlapping_policies(data: AssessmentData) -> list[Finding]:
    """Projects governed by an org-scoped and a project-scoped policy at once.

    Live estate: an organization-scoped HARD day-2 action policy whose scope
    criteria name some 40 projects sits alongside 25 per-project HARD day-2
    policies carrying a subset of its actions. Each of those projects is
    governed by two policies of the same type and neither one states the
    result. This is the half-finished consolidation POL-001 recommends: the
    org-scoped replacement was created, the copies were never deleted.
    Silent when the projects list could not be collected, since missing and
    unread are then indistinguishable (same honesty rule as POL-002).

    Day-2 action overlaps go further: because the platform documents how
    day-2 policies merge, each project-scoped copy is classified against the
    organization policy on its own (see _day2_overlap_lines) rather than the
    overlap being summarized in one line. The reader gets the copies that are
    safe to delete separated from the ones whose deletion would revoke
    something. Every other policy type keeps the plain overlap report.
    """
    project_names = data.derived.get("project_names", {})
    if not project_names:
        return []
    policies = data.raw.get("governance", {}).get("policies", [])

    item_names = {
        i.get("id"): i.get("name")
        for i in data.raw.get("catalog", {}).get("items") or []
        if i.get("id") and i.get("name")
    }

    project_scoped: dict[str, list[dict]] = {}
    for p in policies:
        if p.get("projectId"):
            project_scoped.setdefault(p.get("typeId") or "", []).append(p)

    rows: list[tuple[int, AffectedObject]] = []
    not_compared: list[str] = []
    for p in policies:
        if p.get("projectId"):
            continue
        narrowing = _criteria_summary(p, item_names)
        if narrowing:
            # It governs what its criteria match, not every deployment in a
            # project, so an overlap with a project-scoped policy cannot be
            # claimed from the two documents.
            not_compared.append(f"{p.get('name') or p.get('id') or '?'} ({narrowing})")
            continue
        scope = p.get("scopeCriteria")
        if not scope:
            # An org-scoped policy with no criteria applies to every project.
            coverage = set(project_names)
            scope_desc = "the whole organization"
        else:
            refs, fully_resolved = _criteria_project_refs(scope)
            coverage = {pid for pid, name in project_names.items() if pid in refs or name in refs}
            if not coverage and not fully_resolved:
                # Criteria this walk could not read: claiming no coverage is
                # as much a guess as claiming any, so the policy is left alone.
                continue
            scope_desc = f"{len(coverage)} project(s) via scope criteria"
            if not fully_resolved:
                scope_desc += ", criteria only partly evaluated"

        overlaps = [
            q for q in project_scoped.get(p.get("typeId") or "", []) if q["projectId"] in coverage
        ]
        if not overlaps:
            continue

        word = _policy_type_word(p.get("typeId"))
        audience = _grant_audience_words(p) if _is_day2_action_policy(p.get("typeId")) else ""
        if _is_day2_action_policy(p.get("typeId")) and not _audiences_meet(p, overlaps):
            not_compared.append(f"{p.get('name') or p.get('id') or '?'} ({audience})")
            continue
        lines = [
            f"{p.get('enforcementType') or '?'} {word} policy scoped to {scope_desc}"
            + (f", {audience}" if audience else ""),
            f"also covered by {len(overlaps)} project-scoped {word} policy(ies)",
        ]
        if _is_day2_action_policy(p.get("typeId")):
            # Day-2 grants merge by a documented rule, so each copy gets its own
            # verdict instead of one aggregate claim over the whole overlap.
            lines.extend(_day2_overlap_lines(p, overlaps, project_names))
        elif any(q.get("enforcementType") != p.get("enforcementType") for q in overlaps):
            # Every other policy type: no comparable grant semantics to read,
            # so the overlap and the enforcement difference are all that can
            # be said (an approval policy's actions list is not a grant).
            lines.append(
                "enforcement differs between the overlapping policies, which changes how they merge"
            )
        rows.append(
            (
                len(overlaps),
                AffectedObject(
                    kind="policy",
                    id=p.get("id", ""),
                    name=p.get("name") or "?",
                    detail="\n".join(lines),
                ),
            )
        )
    if not rows:
        return []
    # Widest overlap first: that is the policy pair to decide about first.
    rows.sort(key=lambda row: (-row[0], row[1].name))
    caveat = ""
    if not_compared:
        listed = "; ".join(sorted(not_compared)[:4])
        more = f"; and {len(not_compared) - 4} more" if len(not_compared) > 4 else ""
        caveat = (
            f" NOT COMPARED: {len(not_compared)} organization-wide policy(ies) do not "
            f"govern the same thing as a project's own policy, so they are left out "
            f"here ({listed}{more})."
        )
    return [
        Finding(
            check_id="POL-003",
            title="Projects covered by overlapping policies of the same type",
            severity=Severity.INFO,
            recommendation=(
                "Remove redundant policies only after confirming the intended scope and access.\n"
                "Day-2 policies: preserve required actions for each user and group. "
                "Grants are compared per audience; hard policies supersede soft ones.\n"
                "Other policies: confirm which should apply and document intentional overlaps.\n"
                "Review partly evaluated scope criteria before making changes." + caveat
            ),
            affected=[obj for _, obj in rows],
        )
    ]


def _projects_without_policy_type(
    data: AssessmentData, type_tail: str
) -> tuple[list[tuple[str, str]], list[str]]:
    """(uncovered (project id, name) pairs, org policies with unevaluable
    scope criteria).

    Coverage: a project-scoped policy covers its project; an organization-
    scoped policy with no scope criteria covers every project (nothing is
    returned then); resolvable scope criteria cover the projects they name
    by name or id (POL-003's matching). Criteria that cannot be fully read
    cover whatever they resolvably name, and the policy is returned BY NAME
    so the finding can say the listed projects may still be covered -
    visible uncertainty, not silent withholding, which on a live estate
    read as "every project is covered" when the truth was "could not
    tell". Empty likewise when the project list is missing or the policies
    collection recorded a gap: absence and unread are then
    indistinguishable, so nothing is claimed.
    """
    project_names = data.derived.get("project_names", {})
    if not project_names:
        return [], [], []
    if any(e.get("area") == "governance" and e.get("item") == "policies" for e in data.errors):
        return [], [], []
    # The collector always sets the policies key, even when the fetch failed;
    # its absence means governance was skipped or the collector crashed, and
    # an empty policy list read through that gap must not become "no policy
    # covers any project".
    if "policies" not in data.raw.get("governance", {}):
        return [], [], []
    covered: set[str] = set()
    unresolved: list[str] = []
    narrowed: list[str] = []
    for p in data.raw.get("governance", {}).get("policies", []):
        if (p.get("typeId") or "").rsplit(".", 1)[-1] != type_tail:
            continue
        pid = p.get("projectId")
        if pid:
            covered.add(pid)
            continue
        if _criteria_summary(p):
            # It acts on part of what a project holds, so it does not answer
            # "this project has a policy of this type" for the project at large.
            narrowed.append(p.get("name") or p.get("id") or "?")
            continue
        scope = p.get("scopeCriteria")
        if not scope:
            return [], [], []  # organization-wide policy: every project is covered
        refs, fully_resolved = _criteria_project_refs(scope)
        covered |= {i for i, name in project_names.items() if i in refs or name in refs}
        if not fully_resolved:
            unresolved.append(p.get("name") or p.get("id") or "?")
    uncovered = sorted(
        ((i, name) for i, name in project_names.items() if i not in covered),
        key=lambda pair: (pair[1] or "").casefold(),
    )
    return uncovered, unresolved, narrowed


def _policy_coverage_finding(
    data: AssessmentData, type_tail: str, check_id: str, title: str, recommendation: str
) -> list[Finding]:
    uncovered, unresolved, narrowed = _projects_without_policy_type(data, type_tail)
    if not uncovered:
        return []
    word = POLICY_TYPE_WORDS[type_tail]
    detail = (
        f"no {word} policy visibly applies (project-scoped or resolvable organization scope)"
        if unresolved
        else f"no {word} policy applies (project-scoped or organization-scoped)"
    )
    affected = [
        AffectedObject(kind="project", id=pid, name=name, detail=detail) for pid, name in uncovered
    ]
    if unresolved:
        names = ", ".join(f"'{n}'" for n in sorted(unresolved)[:4])
        more = f" (+{len(unresolved) - 4} more)" if len(unresolved) > 4 else ""
        # Keep qualifications visible beneath the short action. The report
        # only folds numbered procedures, never these unnumbered caveats.
        lead, sep, rest = recommendation.partition("\n")
        recommendation = (
            f"{lead}\nCAVEAT: organization-scoped {word} policy(ies) {names}{more} "
            "carry scope criteria this tool could not fully evaluate, so they may "
            f"cover some or all of the projects listed.{sep}{rest}"
        )
    if narrowed:
        listed = ", ".join(f"'{n}'" for n in sorted(narrowed)[:4])
        more = f" (+{len(narrowed) - 4} more)" if len(narrowed) > 4 else ""
        lead, sep, rest = recommendation.partition("\n")
        recommendation = (
            f"{lead}\nOrganization-wide {word} policy(ies) {listed}{more} act only on "
            f"part of what a project holds, so they do not count as covering "
            f"one.{sep}{rest}"
        )
    return [
        Finding(
            check_id=check_id,
            title=title,
            severity=Severity.INFO,
            recommendation=recommendation,
            affected=affected,
        )
    ]


@check
def pol_004_projects_without_day2_policy(data: AssessmentData) -> list[Finding]:
    return _policy_coverage_finding(
        data,
        "action",
        check_id="POL-004",
        title="Projects with no day-2 action policy",
        recommendation=(
            "Confirm whether these projects need day-2 action restrictions.\n"
            "Without a day-2 action policy, members can run the actions their "
            "project role permits.\n"
            "Day-2 actions are the things people do to a machine after it is "
            "built, such as power it off, resize it or delete it.\n"
            "Where that is intended, nothing needs to change. This list exists "
            "to spot the projects that missed a standard.\n"
            "Organization scope conditions are read where the report can read "
            "them. A policy whose conditions it cannot read is named in a "
            "caveat rather than left out of this list in silence."
        ),
    )


@check
def pol_005_projects_without_approval_policy(data: AssessmentData) -> list[Finding]:
    return _policy_coverage_finding(
        data,
        "approval",
        check_id="POL-005",
        title="Projects with no approval policy",
        recommendation=(
            "Check whether these projects should require approval for "
            "deployments or controlled actions.\n"
            "Development projects may intentionally omit approval. Check against "
            "the environments that are meant to need it.\n"
            "Organization scope conditions are read where the report can read "
            "them. A policy whose conditions it cannot read is named in a "
            "caveat rather than left out of this list in silence."
        ),
    )


@check
def pol_006_projects_without_content_sharing_policy(data: AssessmentData) -> list[Finding]:
    return _policy_coverage_finding(
        data,
        "entitlement",
        check_id="POL-006",
        title="Projects with no content sharing policy",
        recommendation=(
            "Check the catalog access table and add content sharing only where "
            "required.\n"
            "Content can still reach them another way: an item assigned to the "
            "project directly, or an older entitlement.\n"
            "Organization scope conditions are read where the report can read "
            "them. A policy whose conditions it cannot read is named in a "
            "caveat rather than left out of this list in silence."
        ),
    )


# Younger pending approvals are governance working as designed; a request
# waiting longer than this is the one nobody is going to answer. Mirrors
# DEP-004's stuck-window approach.
PENDING_APPROVAL_HOURS = 24


@check
def apr_001_pending_approvals(data: AssessmentData) -> list[Finding]:
    from .deployments import _parse_ts

    now = datetime.now(UTC)
    threshold = timedelta(hours=PENDING_APPROVAL_HOURS)
    affected = []
    for a in data.raw.get("governance", {}).get("approval_requests", []):
        if a.get("status") != "PENDING":
            continue
        created = _parse_ts(a.get("createdAt"))
        if created is not None and now - created <= threshold:
            # An hour-old approval is in-flight governance, not limbo; only
            # unparseable or old timestamps make the list.
            continue
        affected.append(
            AffectedObject(
                kind="approval-request",
                id=a.get("id", ""),
                name=a.get("deploymentName") or a.get("id", ""),
                detail=f"requested by {a.get('requestedBy') or '?'} on "
                f"{(a.get('createdAt') or '?')[:10]}"
                f"{', policy ' + a['policyName'] if a.get('policyName') else ''}"
                f"{', action ' + a['actionName'] if a.get('actionName') else ''}",
            )
        )
    if not affected:
        return []
    return [
        Finding(
            check_id="APR-001",
            title="Approval requests pending",
            severity=Severity.WARNING,
            recommendation=(
                "Review each pending request in Service Broker and approve, reject or "
                "cancel it as appropriate.\n"
                f"A request that has waited less than {PENDING_APPROVAL_HOURS} hours "
                "counts as still moving and is not listed here. The approval requests "
                "table above shows every request."
            ),
            affected=affected,
        )
    ]


@check
def apr_002_approval_policies_without_approvers(data: AssessmentData) -> list[Finding]:
    """Approval policies whose definition names no approvers.

    Nobody is asked to answer the gate: requests sit until the policy's
    auto-expiry decides for them. Two honesty guards: a policy whose slim
    definition shows no other content is treated as unread, never flagged
    (the POL-002 missing-vs-unread rule), and an approverType other than
    USER may resolve its audience at request time (role-based), so only
    USER-typed or untyped definitions are flagged.
    """
    project_names = data.derived.get("project_names", {})
    affected = []
    for p in data.raw.get("governance", {}).get("approval_policies", []):
        if [a for a in p.get("approvers") or [] if a]:
            continue
        approver_type = (p.get("approverType") or "").strip().upper()
        if approver_type and approver_type != "USER":
            continue
        definition_read = (
            p.get("level") is not None
            or p.get("approvalMode")
            or p.get("autoApprovalDecision")
            or p.get("actions")
        )
        if not definition_read:
            continue
        actions = [a for a in p.get("actions") or [] if a]
        gate = f"{p.get('enforcementType') or '?'} gate"
        if p.get("level") is not None:
            gate += f" at level {p['level']}"
        if actions:
            shown = ", ".join(actions[:4])
            more = f" +{len(actions) - 4} more" if len(actions) > 4 else ""
            gate += f" on {shown}{more}"
        decision = p.get("autoApprovalDecision") or ""
        expiry = p.get("autoApprovalExpiry")
        if decision and expiry is not None:
            outcome = f"requests wait {expiry} day(s), then the platform decides {decision}"
        elif decision:
            outcome = f"requests wait until auto-expiry decides {decision}"
        else:
            outcome = "the auto-expiry outcome could not be read from the definition"
        pid = p.get("projectId") or ""
        affected.append(
            AffectedObject(
                kind="policy",
                id=p.get("id", ""),
                name=p.get("name", ""),
                project=project_names.get(pid, pid) or "organization",
                detail=f"{gate}: no approvers defined - {outcome}",
            )
        )
    if not affected:
        return []
    return [
        Finding(
            check_id="APR-002",
            title="Approval policies with no approvers defined",
            severity=Severity.WARNING,
            recommendation=(
                "Assign approvers to each gate, or retire the policy if approval is "
                "no longer required.\n"
                "Without approvers, requests wait for auto-expiry: REJECT refuses "
                "them and APPROVE allows them through. Role-resolved approvers are "
                "not flagged."
            ),
            affected=affected,
        )
    ]


# ---------------------------------------------------------------------------
# Inventory findings. Each restates a table the report already renders, which
# is why they ship in the example config's ignore_findings list. They are kept
# so an estate that wants the flat, exportable list can switch them back on.
