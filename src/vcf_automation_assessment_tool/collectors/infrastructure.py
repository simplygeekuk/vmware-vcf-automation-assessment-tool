"""Infrastructure collector: cloud accounts, zones, fabric, profiles, mappings,
tags, integrations, projects. Also builds the capability-tag map."""

from __future__ import annotations

import logging
from urllib.parse import quote

from ..client import ApiClient, ApiError
from ..models import AssessmentData
from ..tagutil import extract_project_constraints, normalize_tag

log = logging.getLogger(__name__)

AREA = "infrastructure"


def collect(client: ApiClient, data: AssessmentData) -> None:
    raw: dict = {}

    def fetch(key: str, path: str, params: dict | None = None) -> list[dict]:
        try:
            items = list(client.iter_odata(path, params))
            log.info("%s: %d %s", AREA, len(items), key)
            raw[key] = items
            return items
        except ApiError as exc:
            log.warning("%s: failed to collect %s: %s", AREA, key, exc)
            data.record_error(AREA, key, str(exc))
            raw[key] = []
            return []

    fetch("cloud_accounts", "/iaas/api/cloud-accounts")
    zones = fetch("zones", "/iaas/api/zones")
    fetch("fabric_computes", "/iaas/api/fabric-computes")
    fetch("network_profiles", "/iaas/api/network-profiles")
    fetch("fabric_networks", "/iaas/api/fabric-networks")
    # Internal ranges carry allocation counters; external (IPAM) ranges do
    # not, per the IaaS API, so the two are kept apart and read differently.
    fetch("network_ip_ranges", "/iaas/api/network-ip-ranges")
    fetch("external_network_ip_ranges", "/iaas/api/external-network-ip-ranges")
    fetch("storage_profiles", "/iaas/api/storage-profiles")
    # Regions give flavor/image profiles their identity: profile names are
    # optional in the API (a live estate showed 12 of 17 flavor profiles
    # unnamed) and the region + cloud account is what tells the rows apart.
    fetch("regions", "/iaas/api/regions")
    fetch("flavor_profiles", "/iaas/api/flavor-profiles")
    fetch("image_profiles", "/iaas/api/image-profiles")
    fetch("tags", "/iaas/api/tags")
    fetch("integrations", "/iaas/api/integrations")
    fetch("projects", "/iaas/api/projects")
    raw["naming_profiles"] = _naming_profiles(client, data)

    # Platform secrets (Secrets API, Spring paging). The document lists a
    # value field; it is never kept, and never asked for.
    try:
        raw["secrets"] = [_slim_secret(s) for s in client.iter_paged("/platform/api/secrets")]
        log.info("%s: %d secrets", AREA, len(raw["secrets"]))
    except ApiError as exc:
        log.warning("%s: failed to collect secrets: %s", AREA, exc)
        data.record_error(AREA, "secrets", str(exc))
        raw["secrets"] = []

    # Which computes are in each zone, by id. Placement needs the membership
    # and not only the size: a machine constrained by a compute tag can only
    # land in a zone that holds a compute carrying it. Ids alone, because
    # fabric_computes already holds each compute's tags and two copies of a
    # tag are two things to keep in step.
    #
    # A zone that answers nothing is recorded as a gap rather than as an empty
    # zone: zones with no computes are a finding, and a failed read must not
    # become one.
    raw["zone_computes"], raw["zone_compute_counts"] = _zone_computes(client, data, zones)

    data.raw[AREA] = raw
    data.derived["capability_tags"] = _build_capability_tag_map(raw)
    data.derived["project_names"] = {
        p.get("id"): p.get("name", "") for p in raw.get("projects", [])
    }


def _naming_profiles(client: ApiClient, data: AssessmentData) -> list[dict]:
    """The naming list returns assignments; only detail includes templates.

    Shapes and paths are defined by the pinned 8.x IaaS specification.
    Retain list evidence if a detail request fails.
    """
    profiles = []
    try:
        for summary in client.iter_odata("/iaas/api/naming"):
            profile = dict(summary)
            try:
                if not profile.get("id"):
                    raise ApiError("Naming profile has no id; details cannot be read")
                params = {}
                if getattr(client, "iaas_api_version", None):
                    params["apiVersion"] = client.iaas_api_version
                detail = client.get(
                    "/iaas/api/naming/" + quote(str(profile["id"]), safe=""), params=params
                )
                profile.update(detail)
                profile["details_collected"] = isinstance(detail.get("templates"), list)
                if not profile["details_collected"]:
                    raise ApiError("Naming profile response omitted templates")
            except ApiError as exc:
                profile["details_collected"] = False
                data.record_error(AREA, "naming_profiles", str(exc))
            profiles.append(profile)
    except ApiError as exc:
        data.record_error(AREA, "naming_profiles", str(exc))
    return profiles


def _slim_secret(secret: dict) -> dict:
    """The secret's identity and scope, never its value.

    projectIds is documented as capped at ten entries, so a secret shared
    more widely cannot be attributed in full from this document; the
    renderer says so rather than counting the cap as the total.
    """
    return {
        "id": secret.get("id") or "",
        "name": secret.get("name") or "",
        "description": secret.get("description") or "",
        "orgScoped": bool(secret.get("orgScoped")),
        "projectId": secret.get("projectId") or "",
        "projectName": secret.get("projectName") or "",
        "projectIds": [p for p in (secret.get("projectIds") or []) if isinstance(p, str)],
        "createdBy": secret.get("createdBy") or "",
        "updatedBy": secret.get("updatedBy") or "",
        "createdAt": secret.get("createdAt") or "",
        "updatedAt": secret.get("updatedAt") or "",
    }


def _zone_computes(
    client: ApiClient, data: AssessmentData, zones: list[dict]
) -> tuple[dict[str, list[str]], dict[str, int]]:
    """(computes in each zone by id, how many are in each zone).

    One zone that cannot be read leaves the others alone and records a gap.
    That zone is absent from both maps rather than empty: a zone with no
    computes is a finding, and a failed read must not become one.
    """
    membership: dict[str, list[str]] = {}
    counts: dict[str, int] = {}
    for zone in zones:
        zone_id = zone.get("id", "")
        try:
            computes = list(client.iter_odata(f"/iaas/api/zones/{zone_id}/computes"))
        except ApiError as exc:
            log.warning("%s: computes for zone %s failed: %s", AREA, zone.get("name", zone_id), exc)
            data.record_error(AREA, f"zone-computes:{zone.get('name', zone_id)}", str(exc))
            continue
        membership[zone_id] = [c.get("id", "") for c in computes if c.get("id")]
        counts[zone_id] = len(computes)
    return membership, counts


def _build_capability_tag_map(raw: dict) -> dict[str, list[dict]]:
    """Map normalized tag -> list of {kind, id, name, via} describing where the
    capability tag is assigned."""
    tag_map: dict[str, list[dict]] = {}

    def add(tag, kind: str, obj: dict, via: str) -> None:
        norm = normalize_tag(tag)
        if not norm:
            return
        tag_map.setdefault(norm, []).append(
            {
                "kind": kind,
                "id": obj.get("id", ""),
                "name": obj.get("name", ""),
                "via": via,
            }
        )

    # Account-level tags are inherited by the account's compute resources
    # (documented tag inheritance), so they participate in placement matching
    # like any compute tag - with one exception handled in the TAG checks:
    # storage profiles never inherit them. Integration tags are deliberately
    # NOT added: vRO capability tags route workflow runs, not placement.
    for ca in raw.get("cloud_accounts", []):
        for t in ca.get("tags") or []:
            add(t, "cloud-account", ca, "inherited by its computes")
    for zone in raw.get("zones", []):
        for t in zone.get("tags") or []:
            add(t, "cloud-zone", zone, "capability tag")
        for t in zone.get("tagsToMatch") or []:
            add(t, "cloud-zone", zone, "compute filter (tagsToMatch)")
    for fc in raw.get("fabric_computes", []):
        for t in fc.get("tags") or []:
            add(t, "fabric-compute", fc, "capability tag")
    for np in raw.get("network_profiles", []):
        for t in np.get("tags") or []:
            add(t, "network-profile", np, "capability tag")
    for fn in raw.get("fabric_networks", []):
        for t in fn.get("tags") or []:
            add(t, "fabric-network", fn, "capability tag")
    for sp in raw.get("storage_profiles", []):
        for t in sp.get("tags") or []:
            add(t, "storage-profile", sp, "capability tag")
    # Not built through add(): a project constraint carries which kind of
    # request it constrains and how hard, and that decides whether it bears on
    # placement at all. An extensibility constraint selects the runner that
    # executes extensibility work, never where a machine is built.
    for proj in raw.get("projects", []):
        for pc in extract_project_constraints(proj.get("constraints")):
            tag_map.setdefault(pc.tag, []).append(
                {
                    "kind": "project",
                    "id": proj.get("id", ""),
                    "name": proj.get("name", ""),
                    "via": f"{pc.constraint_type} constraint",
                    "constraint_type": pc.constraint_type,
                    "hard": pc.hard,
                    "negated": pc.negated,
                }
            )
    return tag_map
