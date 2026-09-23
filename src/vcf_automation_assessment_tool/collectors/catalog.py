"""Catalog collector: catalog items (admin scope with entitlement-scoped
fallback), content sources, and per-item deployment counts."""

from __future__ import annotations

import logging
from collections import Counter

from ..client import ApiClient, ApiError
from ..models import AssessmentData

log = logging.getLogger(__name__)

AREA = "catalog"


def collect(client: ApiClient, data: AssessmentData) -> None:
    raw: dict = {"admin_scope": True, "items": [], "sources": []}

    try:
        items = list(client.iter_paged("/catalog/api/admin/items"))
    except ApiError as exc:
        if exc.status_code in (401, 403):
            log.warning(
                "%s: no admin access to catalog; falling back to "
                "entitlement-scoped /catalog/api/items",
                AREA,
            )
            data.record_error(
                AREA,
                "admin-items",
                "403 on /catalog/api/admin/items - results are scoped "
                "to the caller's entitlements, not the whole org",
            )
            raw["admin_scope"] = False
            try:
                items = list(client.iter_paged("/catalog/api/items"))
            except ApiError as exc2:
                log.error("%s: fallback collection failed: %s", AREA, exc2)
                data.record_error(AREA, "items", str(exc2))
                items = []
        else:
            log.error("%s: collection failed: %s", AREA, exc)
            data.record_error(AREA, "items", str(exc))
            items = []

    deployments = data.raw.get("deployments", {}).get("deployments", [])
    counts, success, failed, adhoc = _deployment_counters(deployments)

    raw["items"] = [
        {
            "id": item.get("id", ""),
            "name": item.get("name", ""),
            "type": (item.get("type") or {}).get("id", ""),
            "sourceId": item.get("sourceId", ""),
            "sourceName": item.get("sourceName", ""),
            "projectIds": item.get("projectIds") or [],
            "createdAt": item.get("createdAt", ""),
            "lastUpdatedAt": item.get("lastUpdatedAt", ""),
            "deployment_count": counts.get(item.get("id"), 0),
            "deployment_success_count": success.get(item.get("id"), 0),
            "deployment_failed_count": failed.get(item.get("id"), 0),
        }
        for item in items
    ]
    raw["adhoc_deployment_count"] = adhoc
    log.info(
        "%s: %d catalog items (%d ad-hoc deployments not from catalog)",
        AREA,
        len(raw["items"]),
        adhoc,
    )

    _apply_entitlements(client, data, raw)
    _fetch_custom_forms(client, data, raw)

    try:
        sources = list(client.iter_paged("/catalog/api/admin/sources"))
        raw["sources"] = [
            {
                "id": s.get("id", ""),
                "name": s.get("name", ""),
                "typeId": s.get("typeId", ""),
                "itemsImported": s.get("itemsImported", 0),
                "itemsFound": s.get("itemsFound", 0),
                "lastImportErrors": s.get("lastImportErrors") or [],
                "lastImportCompletedAt": s.get("lastImportCompletedAt", ""),
            }
            for s in sources
        ]
        log.info("%s: %d content sources", AREA, len(raw["sources"]))
    except ApiError as exc:
        log.warning("%s: content sources failed: %s", AREA, exc)
        data.record_error(AREA, "sources", str(exc))

    data.raw[AREA] = raw


def _deployment_counters(deployments: list[dict]) -> tuple[Counter, Counter, Counter, int]:
    """Per-catalog-item deployment totals split by outcome.

    A deployment counts as successful/failed from its current status suffix
    (CREATE_SUCCESSFUL, UPDATE_FAILED, ...); in-progress and other states
    count toward the total only. Deployments without a catalogItemId are the
    ad-hoc tally.
    """
    total: Counter = Counter()
    success: Counter = Counter()
    failed: Counter = Counter()
    adhoc = 0
    for d in deployments:
        item_id = d.get("catalogItemId")
        if not item_id:
            adhoc += 1
            continue
        total[item_id] += 1
        status = (d.get("status") or "").upper()
        if status.endswith("_SUCCESSFUL"):
            success[item_id] += 1
        elif status.endswith("_FAILED"):
            failed[item_id] += 1
    return total, success, failed, adhoc


# Form lookups are one request per item; past this many the check is cut off
# and recorded as a gap rather than dragging the run out.
MAX_FORM_LOOKUPS = 500


def _fetch_custom_forms(client: ApiClient, data: AssessmentData, raw: dict) -> None:
    """Flag items carrying a custom request form (the Service Broker Content
    view's "Custom Request Form" column).

    Custom forms are hand-built request UX per item - their presence belongs
    in the inventory (and they map to the request front door in any platform
    change). Primary path is one paged list of all forms, mapped to items
    by sourceId - the live build answers per-item fetchBySourceAndType with
    404 even for items whose forms exist, so per-item lookups are only the
    fallback for builds without the list route.
    """
    items = raw["items"]
    for item in items:
        item["custom_form"] = ""
    if not items:
        return
    try:
        forms = list(client.iter_paged("/form-service/api/forms"))
    except ApiError as exc:
        if exc.status_code in (401, 403):
            data.record_error(
                AREA, "custom-forms", f"{exc} - custom request forms could not be checked"
            )
            return
        _fetch_custom_forms_per_item(client, data, items)
        return

    by_source: dict[str, str] = {}
    for form in forms:
        if not isinstance(form, dict):
            continue
        # Field name varies by build; skip forms of other types (day-2
        # action dialogs etc.) but keep forms that state no type at all.
        form_type = (form.get("formType") or form.get("type") or "").lower()
        if form_type and "request" not in form_type:
            continue
        status = "enabled" if (form.get("status") or "").upper() == "ON" else "disabled"
        source_id = form.get("sourceId") or ""

        def keep(key: str, value: str) -> None:
            # An item with both a disabled and an enabled form has a live
            # form: enabled wins over list order, which is not guaranteed.
            if by_source.get(key) != "enabled":
                by_source[key] = value

        keep(source_id, status)
        # Forms keyed by a versioned source ("<id>/<version>") still belong
        # to the base object.
        if "/" in source_id:
            keep(source_id.split("/")[0], status)

    found = 0
    for item in items:
        item["custom_form"] = by_source.get(item["id"], "")
        found += bool(item["custom_form"])
    log.info("%s: %d item(s) carry a custom request form", AREA, found)


def _fetch_custom_forms_per_item(client: ApiClient, data: AssessmentData, items: list) -> None:
    """Fallback for builds without the forms list route: one lookup per item.

    A 404 means no custom form; a 401/403 aborts the sweep (every remaining
    call would fail identically).
    """
    if len(items) > MAX_FORM_LOOKUPS:
        data.record_error(
            AREA,
            "custom-forms",
            f"only the first {MAX_FORM_LOOKUPS} of {len(items)} items were "
            "checked for custom request forms",
        )
    found = 0
    for item in items[:MAX_FORM_LOOKUPS]:
        try:
            form = client.get(
                "/form-service/api/forms/fetchBySourceAndType",
                {
                    "sourceId": item["id"],
                    "sourceType": item.get("type") or "",
                    "formType": "requestForm",
                },
            )
        except ApiError as exc:
            if exc.status_code in (401, 403):
                data.record_error(
                    AREA,
                    "custom-forms",
                    f"{exc} - custom request forms could not be checked",
                )
                return
            continue  # 404 = no custom form for this item
        status = (form.get("status") or "").upper() if isinstance(form, dict) else ""
        item["custom_form"] = "enabled" if status == "ON" else "disabled"
        found += 1
    log.info("%s: %d item(s) carry a custom request form", AREA, found)


def _apply_entitlements(client: ApiClient, data: AssessmentData, raw: dict) -> None:
    """Union each item's projectIds with what the entitlements API reports.

    Some builds do not populate projectIds on the admin items list at all, so
    the field alone cannot distinguish "shared with nobody" from "not
    reported". Entitlements are the authoritative sharing mechanism: one call
    per project, each returning item-level shares and whole-source shares
    (which entitle every item imported from that source).

    entitlements_collected records whether at least one call succeeded - the
    evidence downstream consumers (access map, CAT-004) need before treating
    an empty projectIds as a real "shared with nobody".
    """
    raw["entitlements_collected"] = False
    projects = data.raw.get("infrastructure", {}).get("projects", [])
    if not projects or not raw["items"]:
        return
    shared: dict[str, set] = {i["id"]: set(i.get("projectIds") or []) for i in raw["items"]}
    by_source: dict[str, list[str]] = {}
    for i in raw["items"]:
        by_source.setdefault(i.get("sourceId") or "", []).append(i["id"])

    for proj in projects:
        pid = proj.get("id") or ""
        try:
            body = client.get("/catalog/api/admin/entitlements", {"projectId": pid})
        except ApiError as exc:
            if exc.status_code in (401, 403):
                # No admin read on entitlements: every remaining call will
                # fail the same way - record one gap and leave projectIds
                # exactly as the items API reported them.
                data.record_error(
                    AREA,
                    "entitlements",
                    f"{exc} - per-item project sharing could not be resolved",
                )
                return
            data.record_error(AREA, f"entitlements:{proj.get('name') or pid}", str(exc))
            continue
        raw["entitlements_collected"] = True
        entitlements = body.get("content", body) if isinstance(body, dict) else body
        for ent in entitlements or []:
            definition = ent.get("definition") or {}
            if "SourceIdentifier" in (definition.get("type") or ""):
                for item_id in by_source.get(definition.get("id") or "", []):
                    shared[item_id].add(pid)
            elif definition.get("id") in shared:
                shared[definition["id"]].add(pid)

    for i in raw["items"]:
        i["projectIds"] = sorted(shared[i["id"]])
    log.info(
        "%s: entitlements resolved - %d of %d item(s) shared with at least one project",
        AREA,
        sum(1 for s in shared.values() if s),
        len(shared),
    )
