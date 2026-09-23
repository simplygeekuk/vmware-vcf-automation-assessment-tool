"""Deployment health checks (DEP-001..011)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ..models import ITEM_TYPE_LABELS, AffectedObject, AssessmentData, Finding, Severity
from . import check

FAILED_STATUSES = {
    "CREATE_FAILED",
    "UPDATE_FAILED",
    "DELETE_FAILED",
    "ABORTED",
    "FAILED",
    "PROVISIONING_FAILED",
}
STUCK_HOURS = 24

# Failed statuses DEP-010 stays out of, though DEP-001 reports them all. An
# update that failed did not create the deployment's machines: they were built
# by an earlier, successful request and are almost certainly still in service,
# so nothing here is stranded capacity and the work is on the change instead.
NOT_STRANDING_STATUSES = {"UPDATE_FAILED"}

# What the platform calls a provisioning request in the request history. Every
# other name there (Onboard, Update, Expire, and the friendly day-2 names) says
# the request was something else, which is what makes the name worth reading
# when no catalog item or template identifies what was asked for.
PROVISIONING_REQUEST_NAME = "create"

# Resource types that count as a "machine" for DEP-002/006, the flow builder
# and the deployment tables. Suffix .Machine also
# matches so provider-specific types are covered without listing them all.
MACHINE_TYPES = {
    "Cloud.Machine",
    "Cloud.vSphere.Machine",
    "Cloud.AWS.EC2.Instance",
    "Cloud.Azure.Machine",
    "Cloud.GCP.Machine",
    "VMware.vSphere.VM",
}


def _deployments(data: AssessmentData) -> list[dict]:
    return data.raw.get("deployments", {}).get("deployments", [])


def _deleted_deployments(data: AssessmentData) -> list[dict]:
    """Soft-deleted deployments: history, deliberately kept out of _deployments
    so no live-estate check ever counts them."""
    return data.raw.get("deployments", {}).get("deleted", [])


def _request_history(data: AssessmentData) -> dict:
    return data.raw.get("deployments", {}).get("request_history") or {}


def _is_failed(status: str) -> bool:
    """The suffix test matters as much as the named set: builds add statuses,
    and a state this does not recognise must not read as healthy."""
    return status in FAILED_STATUSES or status.endswith("_FAILED")


def _obj(dep: dict, detail: str) -> AffectedObject:
    return AffectedObject(
        kind="deployment",
        id=dep["id"],
        name=dep["name"],
        project=dep.get("projectName") or dep.get("projectId"),
        detail=detail,
    )


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # A zone-less timestamp reads as UTC: comparing naive against the aware
    # "now" raises TypeError, which would cost the whole check.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def is_machine(resource_type: str) -> bool:
    return resource_type in MACHINE_TYPES or resource_type.endswith(".Machine")


@check
def dep_001_failed(data: AssessmentData) -> list[Finding]:
    affected = [
        _obj(d, f"status={d['status']}, last updated {(d.get('lastUpdatedAt') or '?')[:10]}")
        for d in _deployments(data)
        # Through the shared helper, not a second copy of the same test:
        # DEP-010 tells the reader "every deployment here is also counted by
        # DEP-001", and that only stays true while one function decides it.
        if _is_failed(d.get("status") or "")
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="DEP-001",
            title="Deployments in a failed state",
            severity=Severity.CRITICAL,
            recommendation=(
                "Fix or delete each failed deployment.\n"
                "A DELETE_FAILED deployment usually leaves objects behind. Try the delete "
                "again, or use the forceDelete option once you have confirmed in vCenter "
                "that the resources have gone."
            ),
            affected=affected,
        )
    ]


# What the platform's power states mean, said plainly. The five names are the
# IaaS Machine document's own enum (ON, OFF, GUEST_OFF, UNKNOWN, SUSPEND); an
# unlisted one is printed as it arrived rather than guessed at.
POWER_STATE_WORDS = {
    "ON": "powered on",
    "OFF": "powered off",
    "GUEST_OFF": "shut down from inside the guest",
    "SUSPEND": "suspended",
    "UNKNOWN": "power state unknown to the platform",
}

# Every machine is listed, with no per-deployment cap. DEP-006 caps its list at
# eight because it is an overview of stack size; this is a work list, and a
# machine left off it is a machine nobody switches off.


def power_state(resource: dict) -> str:
    """The machine's power state, or "" where the document did not carry one.

    Absent is not off: a provider that reports no power state, or a resource
    the deployment service never enriched, must not read as a stopped machine.
    """
    return (resource.get("powerState") or "").strip().upper()


def power_words(state: str) -> str:
    return POWER_STATE_WORDS.get(state) or (state.lower() if state else "no power state reported")


# The order the power states are listed in on a row: running first, because a
# running machine out of a broken build is the one worth dealing with today.
# A state this build spells and the report does not know follows them, and
# "the API said nothing" is last.
_POWER_ORDER = ["ON", "SUSPEND", "GUEST_OFF", "OFF", "UNKNOWN"]


def _power_sort_key(state: str) -> tuple[int, str]:
    if state in _POWER_ORDER:
        return (_POWER_ORDER.index(state), "")
    return (len(_POWER_ORDER) + (1 if not state else 0), state)


def is_missing(resource: dict) -> bool:
    """The resource is in the deployment but no longer on the endpoint.

    That is DEP-003's territory, and it is the line DEP-010 stops at: a machine
    deleted straight in vCenter holds no capacity and runs no operating system,
    so listing it as compute left behind would send the reader after something
    that does not exist.
    """
    return (resource.get("syncStatus") or "").upper() == "MISSING"


def _machine_lines(machines: list[dict]) -> list[str]:
    """The machines of one deployment, grouped by power state.

    Grouped rather than listed one by one with a state in brackets after each
    name: the live estate has deployments holding thirteen machines, and
    thirteen repetitions of "(powered on)" buried the names they belonged to.
    """
    groups: dict[str, list[str]] = {}
    for machine in machines:
        groups.setdefault(power_state(machine), []).append(machine.get("name") or "?")
    ordered = [
        (power_words(state), sorted(names))
        for state, names in sorted(groups.items(), key=lambda kv: _power_sort_key(kv[0]))
    ]
    count = f"{len(machines)} machine" + ("" if len(machines) == 1 else "s")
    if len(ordered) == 1:
        words, names = ordered[0]
        return [f"{count}, {words}: {', '.join(names)}"]
    return [count] + [f"{words} ({len(names)}): {', '.join(names)}" for words, names in ordered]


@check
def dep_010_failed_with_machines(data: AssessmentData) -> list[Finding]:
    """Failed deployments that nonetheless own machines that still exist.

    DEP-001 reports every failed deployment. This is the part of that list
    where the failure left real compute behind, which is the part worth working
    through first: a build that failed after creating its machines is still
    holding capacity, and a machine that is powered on is still running an
    operating system nobody signed off. The power state is what separates
    "wasted disk" from "a live server out of a broken build", so it is on
    every row.

    Two of DEP-001's rows are deliberately not here, because neither leaves
    anything to reclaim. A machine marked MISSING has already gone from the
    endpoint, so it is not counted and a deployment whose machines have all
    gone drops out entirely - that deployment is DEP-003's. An UPDATE_FAILED
    deployment did not build its machines either: they were in service before
    the change was attempted and almost certainly still are, so the work is on
    the failed change, not on the compute.

    That leaves the two lifecycle failures that do strand infrastructure: a
    create that stopped part way, and a delete the platform could not finish.
    Confirmed against the live estate: of 412 deployments in a failed state,
    the failing request was a build (335), a delete (75) or an update/onboard
    (5), while 25 failed power, reboot, resize and disk actions left their
    deployment reading as successful - a failed day-2 action does not put the
    deployment into a failed state, and is DEP-008's to report from the request
    history.

    Deliberately WARNING rather than CRITICAL: these deployments are already
    counted once by DEP-001, and raising the same objects twice at the top
    severity would double the estate's critical tally without adding an
    estate-wide fault.
    """
    affected = []
    unreported = 0
    for dep in _deployments(data):
        status = (dep.get("status") or "").upper()
        if not _is_failed(status) or status in NOT_STRANDING_STATUSES:
            continue
        machines = [r for r in dep.get("resources", []) if is_machine(r.get("type", ""))]
        held = [m for m in machines if not is_missing(m)]
        if not held:
            continue
        gone = len(machines) - len(held)
        running = sum(1 for m in held if power_state(m) == "ON")
        unreported += sum(1 for m in held if not power_state(m))
        lines = [
            f"status={dep.get('status')}, last updated {(dep.get('lastUpdatedAt') or '?')[:10]}",
            *_machine_lines(held),
        ]
        if gone == 1:
            lines.append("1 more machine here no longer exists on the endpoint (see DEP-003)")
        elif gone:
            lines.append(f"{gone} more machines here no longer exist on the endpoint (see DEP-003)")
        # Sort key rides on the object so the worst rows surface first without
        # re-parsing the detail text the way DEP-006 does.
        affected.append((running, len(held), _obj(dep, "\n".join(lines))))
    if not affected:
        return []
    affected.sort(key=lambda row: (-row[0], -row[1]))
    objects = [row[2] for row in affected]
    powered_on = sum(row[0] for row in affected)
    caveat = ""
    if unreported == 1:
        caveat = (
            "\nOne of the machines in these deployments carries no power state in the "
            "API, so this report does not say whether it is running. Check it in vCenter."
        )
    elif unreported:
        caveat = (
            f"\n{unreported} of the machines in these deployments carry no power state "
            "in the API, so this report does not say whether they are running. Check "
            "them in vCenter."
        )
    return [
        Finding(
            check_id="DEP-010",
            title="Failed deployments that still hold machines",
            severity=Severity.WARNING,
            recommendation=(
                "Confirm which machines are needed before retrying operations "
                "or reclaiming resources.\n"
                "These deployments still hold machines; "
                f"{powered_on} of those machines {'is' if powered_on == 1 else 'are'} powered on.\n"
                "CREATE_FAILED: retry needed builds; remove unwanted ones after owner review.\n"
                "DELETE_FAILED: check the endpoint and retry deletion. Use forceDelete "
                "only after confirming the machines are gone.\n"
                "Missing resources (DEP-003) and failed updates are excluded. "
                "Every deployment here is also counted by DEP-001." + caveat
            ),
            affected=objects,
        )
    ]


# Catalog item types that run automation rather than provision workloads -
# a deployment created from one of these never contains machines by design,
# so "no machine resources" is their normal state, not a finding.
NON_WORKLOAD_ITEM_TYPES = {
    "com.vmw.vro.workflow",
    "com.vmw.abx.action",
    "com.vmw.codestream.pipeline",
}


@check
def dep_002_no_machines(data: AssessmentData) -> list[Finding]:
    """Deployments holding no compute. Needs two carve-outs to stay usable
    and still overlaps DEP-003's territory in its own wording, which is why
    it ships in the example config's ignore list."""
    items = {i["id"]: i for i in data.raw.get("catalog", {}).get("items", [])}
    blueprints = {b["id"]: b for b in data.raw.get("blueprints", {}).get("blueprints", [])}
    # Not every deployment carries blueprintId; learn the catalog item ->
    # blueprint join from deployments that carry both ids (same trick as
    # flows.build_flows) so those still resolve to a template.
    item_to_bp: dict[str, str] = {}
    for d in _deployments(data):
        if d.get("catalogItemId") and d.get("blueprintId"):
            item_to_bp.setdefault(d["catalogItemId"], d["blueprintId"])
    affected = []
    for d in _deployments(data):
        if (d.get("status") or "").endswith("_INPROGRESS"):
            continue  # transient state, resources may not exist yet
        item = items.get(d.get("catalogItemId") or "")
        if item and (item.get("type") or "") in NON_WORKLOAD_ITEM_TYPES:
            continue  # a workflow/action/pipeline run - machineless by design
        machines = [r for r in d.get("resources", []) if is_machine(r.get("type", ""))]
        if machines:
            continue
        # Cross-reference the source template: it defines what the deployment
        # should hold. Comparison is against the template's CURRENT content -
        # the version actually deployed is not fetched.
        bp = blueprints.get(
            d.get("blueprintId") or item_to_bp.get(d.get("catalogItemId") or "", "")
        )
        expected = [t for t in (bp or {}).get("resource_types") or [] if is_machine(t)]
        if bp and bp.get("resource_types") and not expected:
            continue  # template defines no machines - machineless by design
        kinds = sorted({r.get("type", "?") for r in d.get("resources", [])}) or ["none"]
        detail = f"resources: {', '.join(kinds)[:120]}"
        if expected:
            detail = (
                f"template '{bp.get('name', '?')}' defines "
                f"{', '.join(expected)} (expected but absent)\n{detail}"
            )
        # Say where the deployment came from - it is what lets a reader
        # judge whether "no machines" is really unexpected here.
        if item:
            label = ITEM_TYPE_LABELS.get(item.get("type") or "", item.get("type") or "?")
            detail = f"created from '{item.get('name', '?')}' ({label})\n{detail}"
        affected.append(_obj(d, detail))
    if not affected:
        return []
    return [
        Finding(
            check_id="DEP-002",
            title="Deployments with no machine/compute resources",
            severity=Severity.WARNING,
            recommendation=(
                "Confirm with owners that these deployments are no longer needed "
                "before removing them.\n"
                "The comparison uses today's template, which may differ from "
                "the deployed version.\n"
                "Workflow, action, pipeline and machine-free template deployments are excluded. "
                "Resources marked MISSING are reported by DEP-003."
            ),
            affected=affected,
        )
    ]


@check
def dep_006_multi_machine_deployments(data: AssessmentData) -> list[Finding]:
    """Deployments containing more than one machine. Disks and networks are
    deliberately not counted - only actual compute."""
    affected = []
    for d in _deployments(data):
        machines = [r for r in d.get("resources", []) if is_machine(r.get("type", ""))]
        if len(machines) < 2:
            continue
        names = ", ".join(sorted(m.get("name") or "?" for m in machines[:8]))
        more = f" (+{len(machines) - 8} more)" if len(machines) > 8 else ""
        affected.append(_obj(d, f"{len(machines)} machines: {names}{more}"))
    if not affected:
        return []
    affected.sort(key=lambda a: -int(a.detail.split(" ")[0]))
    return [
        Finding(
            check_id="DEP-006",
            title="Deployments with multiple machines",
            severity=Severity.INFO,
            recommendation=(
                "Check the impact on every machine before changing or deleting a "
                "multi-machine deployment.\n"
                "A lease that ends, a later change, or a deletion applies to every "
                "machine in the deployment at once."
            ),
            affected=affected,
        )
    ]


@check
def dep_003_missing_resources(data: AssessmentData) -> list[Finding]:
    affected = []
    for d in _deployments(data):
        missing = [
            r for r in d.get("resources", []) if (r.get("syncStatus") or "").upper() == "MISSING"
        ]
        if missing:
            names = ", ".join(r.get("name", "?") for r in missing[:5])
            affected.append(_obj(d, f"{len(missing)} missing resource(s): {names}"))
    if not affected:
        return []
    return [
        Finding(
            check_id="DEP-003",
            title="Deployments with MISSING resources",
            severity=Severity.CRITICAL,
            recommendation=(
                "Confirm the resources are missing, then remove stale resources or "
                "deployments from the platform.\n"
                "Until then the platform shows these as if they were still there, "
                "so its view does not match what exists."
            ),
            affected=affected,
        )
    ]


@check
def dep_004_stuck(data: AssessmentData) -> list[Finding]:
    now = datetime.now(UTC)
    threshold = timedelta(hours=STUCK_HOURS)
    affected = []
    for d in _deployments(data):
        status = d.get("status", "")
        req_status = d.get("lastRequestStatus", "")
        in_flight = status.endswith("_INPROGRESS") or req_status in (
            "PENDING",
            "INITIALIZATION",
            "APPROVAL_PENDING",
            "INPROGRESS",
        )
        if not in_flight:
            continue
        updated = _parse_ts(d.get("lastUpdatedAt"))
        if updated and now - updated > threshold:
            affected.append(
                _obj(
                    d, f"status={status or req_status}, no progress since {d['lastUpdatedAt'][:16]}"
                )
            )
    if not affected:
        return []
    return [
        Finding(
            check_id="DEP-004",
            title=f"Deployments stuck in progress for over {STUCK_HOURS} hours",
            severity=Severity.WARNING,
            recommendation=(
                "Review the stalled request in Service Broker; resolve its approval "
                "or cancel it, then recheck the deployment."
            ),
            affected=affected,
        )
    ]


@check
def dep_005_expired_leases(data: AssessmentData) -> list[Finding]:
    now = datetime.now(UTC)
    affected = []
    for d in _deployments(data):
        lease = _parse_ts(d.get("leaseExpireAt"))
        if lease and lease < now:
            affected.append(_obj(d, f"lease expired {d['leaseExpireAt'][:10]}"))
    if not affected:
        return []
    return [
        Finding(
            check_id="DEP-005",
            title="Deployments with expired leases still present",
            severity=Severity.INFO,
            recommendation=(
                "Check lease enforcement and remove deployments their owners no "
                "longer need.\n"
                "Expired leases normally enter a grace period before deletion."
            ),
            affected=affected,
        )
    ]


@check
def dep_007_deleted_while_failed(data: AssessmentData) -> list[Finding]:
    """A failed deployment that was deleted instead of fixed.

    Deleting one takes it out of the live list, so the estate's failure count
    drops without anything having been repaired. DELETE_FAILED is the sharp
    case: the platform could not remove the underlying objects, so they are
    very likely still on the endpoint with nothing left in the platform
    pointing at them.
    """
    affected = [
        _obj(
            d,
            f"status={d['status']}, deleted around {(d.get('lastUpdatedAt') or '?')[:10]}",
        )
        for d in _deleted_deployments(data)
        if _is_failed(d.get("status") or "")
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="DEP-007",
            title="Deployments deleted while in a failed state",
            severity=Severity.WARNING,
            recommendation=(
                "Check vCenter or the cloud provider for resources left behind by "
                "these deleted deployments.\n"
                "A DELETE_FAILED deployment usually means the platform gave up part "
                "way, and nothing now records what it left.\n"
                "The platform still holds these records for a short time. Once it "
                "removes them for good, this list goes with them."
            ),
            affected=affected,
        )
    ]


# Request statuses that mean the work completed as asked.
REQUEST_OK_STATUSES = {"SUCCESSFUL", "FINISHED", "COMPLETED"}


def request_failed(status: str | None) -> bool:
    """Only a failure counts as one.

    ABORTED is somebody cancelling, APPROVAL_REJECTED is an approver saying no,
    and both are the platform doing exactly as it was told. Counting either
    inflates the failure rate with governance working correctly. The suffix
    test covers the build-specific spellings (CREATE_FAILED, ROLLBACK_FAILED)
    without guessing at names.
    """
    return (status or "").upper().endswith("FAILED")


def request_completed(status: str | None) -> bool:
    """Whether a request finished one way or the other, and so belongs in the
    denominator. Anything else - cancelled, rejected, still in flight - is
    counted nowhere: it neither succeeded nor failed."""
    return request_failed(status) or (status or "").upper() in REQUEST_OK_STATUSES


def content_names(data: AssessmentData) -> tuple[dict[str, str], dict[str, str]]:
    """Catalog item and template names by id, for labelling requests.

    Both ids arrive on a request as 'UUID:version', so the version is trimmed
    before matching.
    """

    def by_id(rows, *keys):
        out = {}
        for row in rows or []:
            ident = (row.get("id") or "").split(":")[0]
            name = next((row.get(k) for k in keys if row.get(k)), "")
            if ident and name:
                out[ident] = name
        return out

    return (
        by_id(data.raw.get("catalog", {}).get("items"), "name"),
        by_id(data.raw.get("blueprints", {}).get("blueprints"), "name"),
    )


def request_target_label(
    req: dict, item_names: dict[str, str], blueprint_names: dict[str, str]
) -> str:
    """What was asked for, as a person would name it.

    Day-2 requests carry an actionId and are self-describing. A provisioning
    request carries none, so all of them collapse into one "provisioning" row
    that says nothing about which item is failing - the catalog item or
    template name is the answer somebody can act on.

    Not everything without an actionId is provisioning, though: onboarding,
    lease expiry and API-driven updates carry neither an action nor an item,
    and the platform's own name for the request is the only thing that says
    which it was. On a live estate that was 1,113 requests, 696 of them
    onboarding, all of them reading as builds that could not be identified.
    """
    if req.get("action_id"):
        return req["action_id"]
    for field, names in (("catalog_item_id", item_names), ("blueprint_id", blueprint_names)):
        name = names.get((req.get(field) or "").split(":")[0])
        if name:
            return f"{name} (build)"
    named = (req.get("name") or "").strip()
    if named and named.lower() != PROVISIONING_REQUEST_NAME:
        return named
    return "build (item not known)"


@check
def dep_008_failed_requests(data: AssessmentData) -> list[Finding]:
    """Requests that failed, across the history the platform still holds.

    Deployment status answers "what is broken now". This answers "what has
    actually been failing", which survives a retry and survives the deployment
    being deleted - as long as the platform has not purged the request. Silent
    unless the history was collected: no history is not a clean record.
    """
    history = _request_history(data)
    if not history.get("collected"):
        return []
    requests = history.get("requests") or []
    failed = [r for r in requests if request_failed(r.get("status"))]
    if not failed:
        return []
    item_names, blueprint_names = content_names(data)
    failed.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    affected = []
    # Every failure, not a slice of them: Finding.count is len(affected), so a
    # cap here would report 40 of 507 as though 40 were all there was. The
    # renderer's max_rows_per_finding does the truncating, and says so.
    for req in failed:
        what = request_target_label(req, item_names, blueprint_names)
        when = (req.get("created_at") or "?")[:10]
        gone = " (deployment since deleted)" if req.get("deployment_deleted") else ""
        who = req.get("requested_by") or "?"
        detail = f"{what} {req.get('status')} on {when}, requested by {who}{gone}"
        if req.get("details"):
            detail += f" - {req['details']}"
        affected.append(
            AffectedObject(
                kind="request",
                id=req.get("id") or "",
                name=req.get("deployment_name") or req.get("id") or "",
                project=req.get("project_name"),
                detail=detail,
            )
        )
    # Cancelled, rejected and in-flight requests are in neither half of the
    # rate: a request an approver refused did not fail.
    completed = sum(1 for r in requests if request_completed(r.get("status")))
    rate = round(len(failed) * 100 / completed) if completed else 0
    window = (history.get("oldest") or "")[:10]
    since = f"back to {window}" if window else "over an unknown window"
    return [
        Finding(
            check_id="DEP-008",
            title="Requests that failed in the retained history",
            severity=Severity.WARNING,
            recommendation=(
                "Investigate recurring request failures and correct their underlying causes.\n"
                f"{len(failed)} of {completed} completed request(s) failed ({rate}%), "
                f"against the history the platform still holds ({since}).\n"
                "A template or catalog item that fails repeatedly is a defect to fix at "
                "the source, while failures spread thinly across many usually point at "
                "capacity, or to a connection that is not healthy.\n"
                "Cancelled and rejected requests, and requests that are still "
                "running, are counted in neither half of that. This is not an "
                "all-time rate: the platform deletes old requests, and anything "
                "already deleted is missing."
            ),
            affected=affected,
        )
    ]


# Accounts that own deployments as machinery rather than as people. The
# assessment's own identity owns whatever it created, and reporting it as a
# departed user is both wrong and slightly absurd.
SERVICE_ACCOUNT_HINTS = ("configurationadmin", "configadmin", "svc-", "svc_", "service-account")


def _is_service_account(owner: str) -> bool:
    local = (owner or "").split("@")[0].lower()
    return any(hint in local for hint in SERVICE_ACCOUNT_HINTS)


@check
def dep_009_owners_without_access(data: AssessmentData) -> list[Finding]:
    """Owners the platform grants nothing to, in the projects they own things in.

    Not a claim that anybody left the organization - nothing in this API says
    whether a directory account still exists. It says these owners hold
    deployments they can no longer act on, which needs a handover either way.

    Silent unless group membership was expanded: on an AD estate most access
    arrives through groups, and without them this would flag nearly everybody.
    Owners whose own project grants to a group that could not be read are left
    out for the same reason.
    """
    from ..identity_map import UNKNOWN_OWNER, has_evidence, owner_access, principal_index

    projects = data.raw.get("infrastructure", {}).get("projects") or []
    identity = data.raw.get("identity", {})
    if not identity.get("collected"):
        return []
    index = principal_index(projects, identity)
    if not has_evidence(index):
        return []

    by_owner: dict[str, dict] = {}
    for dep in _deployments(data):
        owner = dep.get("ownedBy") or UNKNOWN_OWNER
        if owner == UNKNOWN_OWNER or _is_service_account(owner):
            continue
        entry = by_owner.setdefault(owner, {"count": 0, "projects": set(), "names": []})
        entry["count"] += 1
        entry["projects"].add(dep.get("projectId") or "")
        if len(entry["names"]) < 3:
            entry["names"].append(dep.get("projectName") or "")

    affected = []
    for owner, entry in sorted(by_owner.items(), key=lambda kv: -kv[1]["count"]):
        _, state = owner_access(owner, entry["projects"], index)
        if state != "none":
            continue
        where = ", ".join(sorted({n for n in entry["names"] if n})) or "unnamed project(s)"
        affected.append(
            AffectedObject(
                kind="owner",
                id=owner,
                name=owner,
                project=where,
                detail=(
                    f"{entry['count']} deployment(s), no grant in "
                    f"{len(entry['projects'])} project(s)"
                ),
            )
        )
    if not affected:
        return []
    unreadable = len(index.get("unreadable_groups") or [])
    caveat = (
        f" {unreadable} group grant(s) could not be expanded, and owners whose projects "
        "use those groups are left out of this list rather than guessed at."
        if unreadable
        else ""
    )
    return [
        Finding(
            check_id="DEP-009",
            title="Deployment owners with no access to their own projects",
            severity=Severity.WARNING,
            recommendation=(
                "Verify each owner in the identity source before restoring access, "
                "reassigning deployments or decommissioning them.\n"
                "These owners have no visible project grant, directly or through a "
                "group." + caveat + "\n"
                "An account that has left needs its deployments reassigned or "
                "decommissioned, and one still in post needs its project membership "
                "restored.\n"
                "This is not evidence an account was deleted: the platform holds "
                "grants, not the directory."
            ),
            affected=affected,
        )
    ]
