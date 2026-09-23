"""Catalog access map: which projects can request which catalog items.

Sharing truth is the union of three mechanisms, oldest to newest: the
projectIds the items API may report per item, the legacy per-project
entitlements API (resolved by the catalog collector), and content sharing
policies (com.vmware.policy.catalog.entitlement - the mechanism current 8.x
builds actually use; parsed here from the already-collected policies, no
extra API calls). Items shared with an identical set of projects fold into
one "sharing pattern": even a large catalog usually collapses to a handful
of patterns, which is what keeps the access diagram readable when a single
item is shared with 40+ projects.
"""

from __future__ import annotations

from .models import AssessmentData


def _project_label(pid: str, project_names: dict) -> str:
    """Readable name for a project id, honest when it cannot be resolved.

    A sharing grant or item projectId can point at a project that was since
    deleted (or one this identity cannot read) - a live estate surfaced a
    bare UUID in the access map. Label it as unknown instead of leaking the
    raw id; the stale grant itself is worth a reader's attention.
    """
    return project_names.get(pid) or f"(unknown project {pid[:8]})"


def _sharing_policies(data: AssessmentData) -> list[dict]:
    return [
        p
        for p in data.raw.get("governance", {}).get("policies", [])
        if (p.get("typeId") or "").endswith("catalog.entitlement")
    ]


def has_sharing_evidence(data: AssessmentData) -> bool:
    """True when an empty projectIds is a trustable "shared with nobody".

    Some builds never populate projectIds on the admin items list; without a
    populated field somewhere, a successful entitlements read, or at least
    one content sharing policy to parse, "not shared with any project" is
    indistinguishable from "not reported".
    """
    # An org-scoped sharing policy grants to every project, which cannot be
    # expanded when the project list was never read: an empty projectIds is
    # then unresolvable rather than "shared with nobody", whatever the other
    # mechanisms said.
    if not data.derived.get("project_names") and any(
        not p.get("projectId") for p in _sharing_policies(data)
    ):
        return False
    catalog = data.raw.get("catalog", {})
    if catalog.get("entitlements_collected"):
        return True
    if any(i.get("projectIds") for i in catalog.get("items", [])):
        return True
    return bool(_sharing_policies(data))


def _apply_policy_shares(data: AssessmentData, items: list[dict], project_names: dict) -> None:
    """Union content-sharing-policy grants into each item's projectIds and
    derive a readable per-policy table (derived["content_sharing"]).

    A policy scoped to a project grants to that project; an org-scoped policy
    grants to every project. Grants are item-level (CATALOG_ITEM_IDENTIFIER)
    or whole-source (CATALOG_SOURCE_IDENTIFIER, expanded via item.sourceId).
    """
    sources = {s.get("id"): s.get("name") for s in data.raw.get("catalog", {}).get("sources", [])}
    items_by_id = {i["id"]: i for i in items}
    by_source: dict[str, list[dict]] = {}
    for i in items:
        by_source.setdefault(i.get("sourceId") or "", []).append(i)
    shared: dict[str, set] = {i["id"]: set(i.get("projectIds") or []) for i in items}

    rows = []
    for policy in _sharing_policies(data):
        pid = policy.get("projectId") or ""
        grant_projects = [pid] if pid else list(project_names)
        shares = []
        # Live policy documents vary in shape (list endpoints can serve
        # summaries); a string or null where a dict is expected must degrade
        # to "no shares readable", never crash the whole analysis phase.
        definition = policy.get("definition")
        entitled_users = definition.get("entitledUsers") if isinstance(definition, dict) else None
        for entitled in entitled_users or []:
            if not isinstance(entitled, dict):
                continue
            for content in entitled.get("items") or []:
                if not isinstance(content, dict):
                    continue
                ctype = (content.get("type") or "").upper()
                cid = content.get("id") or ""
                if "SOURCE" in ctype:
                    shares.append(f"source: {sources.get(cid) or content.get('name') or cid}")
                    for item in by_source.get(cid, []):
                        shared[item["id"]].update(grant_projects)
                elif "ITEM" in ctype:
                    name = (items_by_id.get(cid) or {}).get("name") or content.get("name") or cid
                    shares.append(f"item: {name}")
                    if cid in shared:
                        shared[cid].update(grant_projects)
        rows.append(
            {
                "name": policy.get("name") or "?",
                "scope": _project_label(pid, project_names) if pid else "organization",
                "enforcement": policy.get("enforcementType") or "",
                "shares": sorted(set(shares)),
            }
        )
    for i in items:
        i["projectIds"] = sorted(shared[i["id"]])
    data.derived["content_sharing"] = sorted(rows, key=lambda r: r["name"].lower())


def build_catalog_access(data: AssessmentData) -> None:
    items = data.raw.get("catalog", {}).get("items", [])
    project_names = data.derived.get("project_names", {})
    total_projects = len(project_names)

    _apply_policy_shares(data, items, project_names)

    if items and not has_sharing_evidence(data):
        # No sharing mechanism could be read on this build - a map built
        # from the bare field would claim every single item is unrequestable.
        data.derived["catalog_access"] = []
        return

    groups: dict[frozenset, list[dict]] = {}
    for item in items:
        groups.setdefault(frozenset(item.get("projectIds") or []), []).append(item)

    patterns = []
    for project_ids, members in groups.items():
        names = sorted(_project_label(p, project_names) for p in project_ids)
        patterns.append(
            {
                "project_ids": sorted(project_ids),
                "project_names": names,
                "all_projects": total_projects > 0 and len(project_ids) == total_projects,
                "items": sorted(
                    (
                        {
                            "id": m.get("id", ""),
                            "name": m.get("name", ""),
                            "sourceName": m.get("sourceName", ""),
                        }
                        for m in members
                    ),
                    key=lambda m: m["name"].lower(),
                ),
            }
        )
    # Widest sharing first; the unshared group (no projects) sinks to the end.
    patterns.sort(key=lambda g: (-len(g["project_ids"]), -len(g["items"])))
    data.derived["catalog_access"] = patterns
