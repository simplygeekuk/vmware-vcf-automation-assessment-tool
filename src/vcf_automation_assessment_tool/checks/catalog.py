"""Catalog checks (CAT-001..004)."""

from __future__ import annotations

from collections import Counter

from ..access import has_sharing_evidence
from ..models import AffectedObject, AssessmentData, Finding, Severity, area_gap
from . import check


def _items(data: AssessmentData) -> list[dict]:
    return data.raw.get("catalog", {}).get("items", [])


@check
def cat_001_unused_items(data: AssessmentData) -> list[Finding]:
    # deployment_count comes from counting the collected deployments; when
    # that listing failed or was skipped, every item reads 0 and the whole
    # catalog would be called deletion candidates. Silent instead: zero and
    # unread are indistinguishable then. Per-deployment resource gaps do not
    # affect the counter, so only the listing itself is consulted.
    if area_gap(data, "deployments", {"deployments"}):
        return []
    affected = [
        AffectedObject(
            kind="catalog-item",
            id=i["id"],
            name=i["name"],
            detail=f"type={i['type'] or '?'}, source={i['sourceName'] or '?'}, 0 deployments",
        )
        for i in _items(data)
        if i.get("deployment_count", 0) == 0
    ]
    if not affected:
        return []
    scope_note = ""
    if not data.raw.get("catalog", {}).get("admin_scope", True):
        scope_note = (
            " This report read the catalog with limited access rather than "
            "administrator access, so the list may be incomplete."
        )
    return [
        Finding(
            check_id="CAT-001",
            title="Catalog items with no deployments in the collected inventory",
            severity=Severity.WARNING,
            recommendation=(
                "Review these items with their service owners before deciding "
                "whether to retire them.\n"
                "No deployment in the collected inventory references these items. "
                "This snapshot does not establish that they have never been used; "
                "previous deployments may have been deleted. Confirm planned, seasonal and "
                "recovery use before removing an item. Review other items before removing "
                "a shared content source." + scope_note
            ),
            affected=affected,
        )
    ]


@check
def cat_002_unsynced_sources(data: AssessmentData) -> list[Finding]:
    affected = []
    for s in data.raw.get("catalog", {}).get("sources", []):
        problems = []
        if s.get("lastImportErrors"):
            problems.append(f"{len(s['lastImportErrors'])} import error(s)")
        found, imported = s.get("itemsFound"), s.get("itemsImported")
        # Compared only when both counters are real: a build omitting one
        # would otherwise flag every source ("found N but imported None").
        if isinstance(found, int) and isinstance(imported, int) and found != imported:
            problems.append(f"found {found} but imported {imported}")
        if problems:
            affected.append(
                AffectedObject(
                    kind="content-source",
                    id=s["id"],
                    name=s["name"],
                    detail=f"type={s['typeId']}: " + "; ".join(problems),
                )
            )
    if not affected:
        return []
    return [
        Finding(
            check_id="CAT-002",
            title="Content sources with import errors or incomplete imports",
            severity=Severity.WARNING,
            recommendation=(
                "Correct the content source errors, then rerun the import.\n"
                "A source that cannot import cleanly means the catalog no longer "
                "matches the content it came from."
            ),
            affected=affected,
        )
    ]


@check
def cat_004_unshared_items(data: AssessmentData) -> list[Finding]:
    items = _items(data)
    # Only trust an empty projectIds as "not shared" when the field is
    # demonstrably populated on this build or the entitlements API confirmed
    # it - otherwise an API that omits the field would flag every item.
    if not has_sharing_evidence(data):
        return []
    affected = [
        AffectedObject(
            kind="catalog-item",
            id=i["id"],
            name=i["name"],
            detail=f"type={i['type'] or '?'}, source={i['sourceName'] or '?'}, "
            "shared with 0 projects",
        )
        for i in items
        if not i.get("projectIds")
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="CAT-004",
            title="Catalog items not shared with any project",
            severity=Severity.INFO,
            recommendation=(
                "Share required items with the intended projects; retire unwanted "
                "items after owner review.\n"
                "Cross-check CAT-001 and confirm planned use before retiring an item."
            ),
            affected=affected,
        )
    ]


@check
def cat_003_item_type_inventory(data: AssessmentData) -> list[Finding]:
    items = _items(data)
    if not items:
        return []
    by_type = Counter(i.get("type") or "unknown" for i in items)
    affected = [
        AffectedObject(kind="catalog-item-type", id=t, name=t, detail=f"{count} item(s)")
        for t, count in by_type.most_common()
    ]
    return [
        Finding(
            check_id="CAT-003",
            title="Catalog item types in use",
            severity=Severity.INFO,
            recommendation=(
                "Include each catalog item type's supporting service in operational "
                "and migration planning.\n"
                "Each of those services is one more thing to run, to secure and to "
                "account for in any platform change."
            ),
            affected=affected,
        )
    ]
