"""Deployments collector: all deployments with expanded resources."""

from __future__ import annotations

import logging

from ..checks.deployments import is_machine
from ..client import DEPLOYMENT_MAX_PAGE_SIZE, ApiClient, ApiError
from ..models import AssessmentData

log = logging.getLogger(__name__)

AREA = "deployments"

# Deployments whose request history is fetched in one run, unless
# request_history_limit says otherwise. History costs one call per deployment,
# so this is the backstop that keeps a read-only assessment from turning into
# an unbounded API crawl - set high enough not to bite a real estate, since a
# cap that silently trims coverage is worse than a long run. Whatever it does
# drop is recorded as a gap, never left to look like an absence of failures.
REQUEST_HISTORY_CAP = 10000

# The expand=resources parameter caps embedded resources at ~100 per deployment;
# at or beyond this we re-fetch the full list from the per-deployment endpoint.
EXPAND_RESOURCE_CAP = 100


def collect(client: ApiClient, data: AssessmentData) -> None:
    deployments: list[dict] = []
    try:
        for dep in client.iter_paged(
            "/deployment/api/deployments",
            params={"expand": "resources,project,lastRequest", "deleted": "false"},
            page_size=DEPLOYMENT_MAX_PAGE_SIZE,
        ):
            deployments.append(_slim(dep))
            if len(deployments) % 500 == 0:
                log.info("%s: fetched %d so far...", AREA, len(deployments))
    except ApiError as exc:
        log.error("%s: collection failed: %s", AREA, exc)
        data.record_error(AREA, "deployments", str(exc))
        data.raw[AREA] = {
            "deployments": deployments,
            "deleted": [],
            "request_history": {"collected": False},
        }
        return

    # Re-fetch resources where the expand cap may have truncated them.
    for dep in deployments:
        if len(dep["resources"]) >= EXPAND_RESOURCE_CAP:
            try:
                full = list(client.iter_paged(f"/deployment/api/deployments/{dep['id']}/resources"))
                dep["resources"] = [_slim_resource(r) for r in full]
            except ApiError as exc:
                log.warning("%s: resource re-fetch for %s failed: %s", AREA, dep["name"], exc)
                data.record_error(AREA, f"resources:{dep['name']}", str(exc))

    _enrich_hostnames(client, data, deployments)
    log.info("%s: %d deployments", AREA, len(deployments))
    deleted = _collect_deleted(client, data)
    data.raw[AREA] = {
        "deployments": deployments,
        "deleted": deleted,
        # Read from meta rather than a collector argument: every collector is
        # called as collect(client, data), and meta is populated before the
        # collection loop runs.
        "request_history": (
            _collect_request_history(client, data, deployments, deleted)
            if data.meta.get("request_history")
            else {"collected": False}
        ),
    }


def _enrich_hostnames(client: ApiClient, data: AssessmentData, deployments: list[dict]) -> None:
    """Resolve absent deployment-property hostnames from the typed IaaS inventory.

    One paginated sweep, with exact resource IDs and a deployment-ID guard.
    Names and addresses are not safe join keys across projects.
    """
    pending = {}
    for dep in deployments:
        for resource in dep.get("resources", []):
            if is_machine(resource.get("type", "")) and not resource.get("hostname"):
                if resource.get("id"):
                    pending.setdefault(resource["id"], []).append((dep.get("id"), resource))
    if not pending:
        return
    try:
        for machine in client.iter_odata("/iaas/api/machines"):
            hostname = machine.get("hostname")
            if not isinstance(hostname, str) or not hostname.strip():
                continue
            for deployment_id, resource in pending.get(machine.get("id"), []):
                if machine.get("deploymentId") and machine["deploymentId"] != deployment_id:
                    continue
                resource["hostname"] = hostname.strip()
    except ApiError as exc:
        log.warning("%s: machine hostname lookup failed: %s", AREA, exc)
        data.record_error(AREA, "machine hostnames", str(exc))


def _collect_deleted(client: ApiClient, data: AssessmentData) -> list[dict]:
    """Soft-deleted deployments the platform has not yet purged.

    A deployment that was deleted rather than fixed leaves no trace in the live
    list, so failures can be made to disappear by removing them. These are kept
    apart from the live population and never merged into its counts: they are
    history, not estate. Resources are not expanded - the deleted view is a
    record of what went, not an inventory of what runs.
    """
    try:
        deleted = [
            _slim(d)
            for d in client.iter_paged(
                "/deployment/api/deployments",
                params={"expand": "project", "deleted": "true"},
                page_size=DEPLOYMENT_MAX_PAGE_SIZE,
            )
        ]
    except ApiError as exc:
        log.warning("%s: deleted deployment sweep failed: %s", AREA, exc)
        data.record_error(AREA, "deleted deployments", str(exc))
        return []
    log.info("%s: %d soft-deleted deployments", AREA, len(deleted))
    return deleted


def _collect_request_history(
    client: ApiClient,
    data: AssessmentData,
    live: list[dict],
    deleted: list[dict],
) -> dict:
    """Every request each deployment carries, live and soft-deleted alike.

    The current status of a deployment says who is broken now; this says what
    actually failed. It costs one call per deployment, which is why it is
    opt-in. The store is pruned by the platform, so the oldest request seen is
    recorded with it - a failure rate over an unstated window is a number
    nobody can act on.
    """
    targets = [(d, False) for d in live] + [(d, True) for d in deleted]
    limit = data.meta.get("request_history_limit") or REQUEST_HISTORY_CAP
    capped = max(0, len(targets) - limit)
    if capped:
        log.warning("%s: request history capped at %d deployments", AREA, limit)
        data.record_error(
            AREA,
            "request history",
            f"capped at {limit} deployments; {capped} not read",
        )
    requests: list[dict] = []
    scanned = 0
    failures: list[str] = []
    for dep, was_deleted in targets[:limit]:
        # A soft-deleted deployment answers 404 "No value present" on the plain
        # route - its history is only reachable with deleted=true, and without
        # the flag that 404 reads exactly like "this one never failed".
        params = {"deleted": "true"} if was_deleted else None
        try:
            rows = list(
                client.iter_paged(
                    f"/deployment/api/deployments/{dep['id']}/requests",
                    params=params,
                    page_size=DEPLOYMENT_MAX_PAGE_SIZE,
                )
            )
        except ApiError as exc:
            failures.append(f"{dep.get('name') or dep.get('id')}: {exc}")
            continue
        scanned += 1
        requests.extend(_slim_request(r, dep, was_deleted) for r in rows)
        if scanned % 200 == 0:
            log.info("%s: request history read for %d deployments...", AREA, scanned)
    if failures:
        log.warning("%s: request history unreadable for %d deployment(s)", AREA, len(failures))
        data.record_error(
            AREA,
            "request history",
            f"unreadable for {len(failures)} deployment(s); first: {failures[0]}",
        )
    log.info("%s: %d request(s) across %d deployments", AREA, len(requests), scanned)
    return {
        "collected": True,
        "requests": requests,
        "deployments_scanned": scanned,
        "deployments_unread": len(failures) + capped,
        # The window the rate applies to. Empty when nothing was returned.
        "oldest": min((r["created_at"] for r in requests if r["created_at"]), default=""),
    }


def _slim_request(req: dict, dep: dict, was_deleted: bool) -> dict:
    """One request, without its payloads.

    inputs and outputs are dropped rather than slimmed: request inputs carry
    whatever the requester typed into the form, which on this platform can
    include credentials.
    """
    return {
        "id": req.get("id") or "",
        "name": req.get("name") or "",
        # A provisioning request has no actionId; only day-2 requests do.
        "action_id": req.get("actionId") or "",
        "status": req.get("status") or "",
        "requested_by": req.get("requestedBy") or "",
        "created_at": req.get("createdAt") or "",
        "completed_at": req.get("completedAt") or req.get("updatedAt") or "",
        "total_tasks": req.get("totalTasks"),
        "completed_tasks": req.get("completedTasks"),
        # Where a request failed, details holds the error the platform showed.
        "details": (req.get("details") or "")[:300],
        "catalog_item_id": req.get("catalogItemId") or "",
        "blueprint_id": req.get("blueprintId") or "",
        "deployment_id": dep.get("id") or "",
        "deployment_name": dep.get("name") or "",
        "project_name": dep.get("projectName") or "",
        "deployment_deleted": was_deleted,
    }


def _slim(dep: dict) -> dict:
    """Keep the fields the checks and report need; drop bulky expand payloads."""
    project = dep.get("project") or {}
    last_request = dep.get("lastRequest") or {}
    # `or ""` not a .get default: an explicit JSON null in the document
    # bypasses the default and used to crash DEP-001/002/004 and the report's
    # by-status rollup downstream.
    return {
        "id": dep.get("id") or "",
        "name": dep.get("name") or "",
        "status": dep.get("status") or "",
        # Both spellings, because expand=project moves the answer: this build
        # returns the project nested and leaves the top-level projectId empty,
        # which silently emptied every project-scoped comparison downstream -
        # ownership access, PRJ-001, the deployment project count. projectName
        # was read from the expanded object all along, which is why the report
        # looked right while the ids did not.
        "projectId": dep.get("projectId") or project.get("id") or "",
        "projectName": project.get("name") or dep.get("projectName") or "",
        "catalogItemId": dep.get("catalogItemId"),
        "catalogItemVersion": dep.get("catalogItemVersion"),
        "blueprintId": dep.get("blueprintId"),
        "createdAt": dep.get("createdAt") or "",
        "lastUpdatedAt": dep.get("lastUpdatedAt") or "",
        "leaseExpireAt": dep.get("leaseExpireAt"),
        "ownedBy": dep.get("ownedBy") or "",
        "lastRequestStatus": last_request.get("status") or "",
        "resources": [_slim_resource(r) for r in dep.get("resources") or []],
    }


def _slim_resource(res: dict) -> dict:
    props = res.get("properties")
    return {
        "id": res.get("id", ""),
        "name": res.get("name", ""),
        "type": res.get("type", ""),
        "state": res.get("state", ""),
        "syncStatus": res.get("syncStatus", ""),
        "origin": res.get("origin", ""),
        # The one field kept out of the provider document: whether a machine is
        # running. DEP-010 needs it, and everything else in properties is bulk.
        # powerState is the IaaS Machine document's own spelling (confirmed from
        # this build's /iaas-api swagger, enum ON/OFF/GUEST_OFF/UNKNOWN/SUSPEND);
        # the deployment service embeds that document under properties. Absent
        # is left absent - a machine with no reported state is never called off.
        "powerState": (props.get("powerState") or "") if isinstance(props, dict) else "",
        # Two more fields the IaaS Machine schema documents on the same
        # embedded document. Sizing and placement (CPU, memory, zone) are
        # not documented there and are deliberately not guessed at.
        "address": (props.get("address") or "") if isinstance(props, dict) else "",
        "hostname": (props.get("hostname") or "") if isinstance(props, dict) else "",
    }
