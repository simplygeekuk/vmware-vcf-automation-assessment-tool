"""Infrastructure and project checks (INF-001..008, PRJ-001..006)."""

from __future__ import annotations

from ..models import (
    NEAR_LIMIT_RATIO,
    OK_ENDPOINT_STATUSES,
    ZONE_LIMITS,
    AffectedObject,
    AssessmentData,
    Finding,
    Severity,
    area_gap,
    endpoint_status,
    format_amount,
    ip_range_usage,
    secret_rows,
    zone_allocations,
)
from . import check

# Integration types that use capability tags (workflow-run routing when more
# than one Orchestrator is connected) - same predicate the vRO collector uses.
# Other integration types (source control, AD, ...) have no capability-tag
# mechanism, so "untagged" is meaningless for them.
VRO_INTEGRATION_TYPES = ("vro", "vro-gateway")


def _infra(data: AssessmentData) -> dict:
    return data.raw.get("infrastructure", {})


@check
def inf_001_problem_zones(data: AssessmentData) -> list[Finding]:
    infra = _infra(data)
    zones = infra.get("zones", [])
    if not zones:
        return []
    counts = infra.get("zone_compute_counts", {})
    zone_ids_in_projects: set[str] = set()
    for proj in infra.get("projects", []):
        for z in proj.get("zones") or []:
            zid = z.get("zoneId") or z.get("id")
            if zid:
                zone_ids_in_projects.add(zid)

    affected = []
    for zone in zones:
        problems = []
        zid = zone.get("id", "")
        if counts.get(zid, -1) == 0:
            problems.append("0 computes")
        if zone_ids_in_projects and zid not in zone_ids_in_projects:
            problems.append("assigned to no project")
        if problems:
            affected.append(
                AffectedObject(
                    kind="cloud-zone", id=zid, name=zone.get("name", ""), detail="; ".join(problems)
                )
            )
    if not affected:
        return []
    return [
        Finding(
            check_id="INF-001",
            title="Cloud zones with no computes or no project assignment",
            severity=Severity.WARNING,
            recommendation=(
                "Review the zone's compute selection and project assignment; "
                "correct them or retire the zone."
            ),
            affected=affected,
        )
    ]


@check
def inf_002_mapping_gaps(data: AssessmentData) -> list[Finding]:
    infra = _infra(data)
    accounts = infra.get("cloud_accounts", [])
    if not accounts:
        return []

    # Regions with mappings, per profile type.
    def regions_with(profiles_key: str, mapping_key: str) -> set[str]:
        regions = set()
        for prof in infra.get(profiles_key, []):
            mapping = (prof.get(mapping_key) or {}).get("mapping") or {}
            region_link = ((prof.get("_links") or {}).get("region") or {}).get("href", "")
            if mapping and region_link:
                regions.add(region_link.rsplit("/", 1)[-1])
        return regions

    flavor_regions = regions_with("flavor_profiles", "flavorMappings")
    image_regions = regions_with("image_profiles", "imageMappings")

    affected = []
    for account in accounts:
        for region in account.get("enabledRegions") or []:
            rid = region.get("id", "") if isinstance(region, dict) else str(region)
            rname = region.get("name", rid) if isinstance(region, dict) else str(region)
            missing = []
            if flavor_regions and rid not in flavor_regions:
                missing.append("no flavor mapping")
            if image_regions and rid not in image_regions:
                missing.append("no image mapping")
            if missing:
                affected.append(
                    AffectedObject(
                        kind="region",
                        id=rid,
                        name=f"{account.get('name', '?')} / {rname}",
                        detail="; ".join(missing),
                    )
                )

    # Image mappings whose referenced image looks broken.
    for prof in infra.get("image_profiles", []):
        mapping = (prof.get("imageMappings") or {}).get("mapping") or {}
        for map_name, img in mapping.items():
            if isinstance(img, dict) and not (img.get("id") or img.get("externalId")):
                affected.append(
                    AffectedObject(
                        kind="image-mapping",
                        id=prof.get("id", ""),
                        name=f"{prof.get('name', '?')} / {map_name}",
                        detail="image reference unresolved (source image likely deleted)",
                    )
                )
    if not affected:
        return []
    return [
        Finding(
            check_id="INF-002",
            title="Regions with no machine size or image mapping, or a broken image link",
            severity=Severity.WARNING,
            recommendation=(
                "Complete missing mappings and repair stale image references in "
                "every region in use."
            ),
            affected=affected,
        )
    ]


@check
def inf_003_unhealthy_endpoints(data: AssessmentData) -> list[Finding]:
    """Cloud accounts / integrations whose own document says they are not OK.

    Judged per document: one exposing no health signal at all is skipped,
    never assumed healthy. Some builds do not report endpoint health over the
    public API in any form, and on those this check stays silent rather than
    guess.
    """
    infra = _infra(data)
    affected = []
    for kind, key in (("cloud-account", "cloud_accounts"), ("integration", "integrations")):
        for obj in infra.get(key, []):
            status = endpoint_status(obj)
            if status is None or status.upper() in OK_ENDPOINT_STATUSES:
                continue
            type_word = obj.get("cloudAccountType") or obj.get("integrationType") or "?"
            affected.append(
                AffectedObject(
                    kind=kind,
                    id=obj.get("id", ""),
                    name=obj.get("name", ""),
                    detail=f"status {status} ({type_word})",
                )
            )
    if not affected:
        return []
    return [
        Finding(
            check_id="INF-003",
            title="Cloud accounts or integrations not in OK status",
            # CRITICAL by the report's own definition ("broken today"): an
            # endpoint the platform cannot talk to fails provisioning, day-2
            # and data collection right now, not eventually.
            severity=Severity.CRITICAL,
            recommendation=(
                "Retest each endpoint in Infrastructure > Connections and resolve "
                "the reported errors.\n"
                "The usual causes are an expired password or certificate, and a "
                "system the platform cannot reach.\n"
                "A system that reports no health information at all is not judged "
                "here."
            ),
            affected=affected,
        )
    ]


@check
def inf_004_untagged_endpoints(data: AssessmentData) -> list[Finding]:
    infra = _infra(data)
    affected = []
    for a in infra.get("cloud_accounts", []):
        if not (a.get("tags") or []):
            affected.append(
                AffectedObject(
                    kind="cloud-account",
                    id=a.get("id", ""),
                    name=a.get("name", ""),
                    detail=f"{a.get('cloudAccountType', '?')} account, no capability tags",
                )
            )
    for i in infra.get("integrations", []):
        if (i.get("integrationType") or "").lower() not in VRO_INTEGRATION_TYPES:
            continue
        if not (i.get("tags") or []):
            affected.append(
                AffectedObject(
                    kind="integration",
                    id=i.get("id", ""),
                    name=i.get("name", ""),
                    detail="Orchestrator integration, no capability tags",
                )
            )
    if not affected:
        return []
    return [
        Finding(
            check_id="INF-004",
            title="Cloud accounts and Orchestrator integrations without capability tags",
            severity=Severity.INFO,
            recommendation=(
                "Review whether capability tags are needed to select the intended "
                "cloud account or Orchestrator integration.\n"
                "Untagged connections rely on default selection, which may be "
                "sufficient for one endpoint but ambiguous with several.\n"
                "Tags on a cloud account pass to all of its computers, but never to "
                "storage profiles, and they decide where a machine is built. Tags "
                "on an Orchestrator connection decide which Orchestrator runs a "
                "workflow when there is more than one.\n"
                "Connections other than Orchestrator have no capability tags and "
                "are not listed."
            ),
            affected=affected,
        )
    ]


def _ip_range_rows(data: AssessmentData) -> list[dict]:
    """The IP Ranges table's rows, or nothing when the ranges could not be read."""
    if area_gap(data, "infrastructure", {"network_ip_ranges"}):
        return []
    return ip_range_usage(_infra(data).get("network_ip_ranges"))


def _ip_range_detail(row: dict) -> str:
    return (
        f"{row['start']} - {row['end']}: {format_amount(row['allocated'])} of "
        f"{format_amount(row['total'])} addresses allocated"
        + (f", {format_amount(row['available'])} available" if row["available"] is not None else "")
    )


@check
def inf_005_ip_ranges_exhausted(data: AssessmentData) -> list[Finding]:
    """Internal IP ranges with no address left to allocate.

    The counters are the platform's own, so this is what the next request
    meets. A range whose counters could not be read is not judged.
    """
    affected = [
        AffectedObject(
            kind="ip-range", id=row["id"], name=row["name"], detail=_ip_range_detail(row)
        )
        for row in _ip_range_rows(data)
        if row["ratio"] is not None and row["ratio"] >= 1
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="INF-005",
            title="IP ranges with no addresses left",
            severity=Severity.WARNING,
            recommendation=(
                "Extend the range, add another range to the network, or reclaim "
                "addresses confirmed unused.\n"
                "Manage ranges in Assembler > Infrastructure > Resources > Networks "
                "> IP Ranges.\n"
                "Ranges managed by an external IPAM are not counted here: the "
                "platform does not expose their usage."
            ),
            affected=affected,
        )
    ]


@check
def inf_006_ip_ranges_near_exhaustion(data: AssessmentData) -> list[Finding]:
    """Internal IP ranges within a fifth of full, reported before they stop a build."""
    affected = [
        AffectedObject(
            kind="ip-range", id=row["id"], name=row["name"], detail=_ip_range_detail(row)
        )
        for row in _ip_range_rows(data)
        if row["ratio"] is not None and NEAR_LIMIT_RATIO <= row["ratio"] < 1
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="INF-006",
            title="IP ranges close to full",
            severity=Severity.INFO,
            recommendation=(
                "Review expected network growth and extend the IP range before its "
                "remaining addresses run out."
            ),
            affected=affected,
        )
    ]


@check
def inf_007_secrets_no_template_reads(data: AssessmentData) -> list[Finding]:
    """Platform secrets no cloud template or property group reads.

    A review list, not a defect: a secret can also be read by code the
    report does not see. The claim is only made when every template's
    content was read, because an unread template could be the reader.
    """
    if area_gap(data, "infrastructure", {"secrets"}) or area_gap(data, "blueprints"):
        return []
    affected = [
        AffectedObject(
            kind="secret",
            id=row["id"],
            name=row["name"],
            detail=f"scope: {row['scope']}; created by {row['created_by'] or '?'}, "
            f"last updated {row['updated'] or '?'}",
        )
        for row in secret_rows(data)
        if not row["used_by"]
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="INF-007",
            title="Secrets no cloud template or property group reads",
            severity=Severity.INFO,
            recommendation=(
                "Delete secrets only after their owners confirm that no template, "
                "property group or other consumer needs them.\n"
                "No collected template or property group references these secrets. "
                "Secret values are never read."
            ),
            affected=affected,
        )
    ]


@check
def prj_001_empty_projects(data: AssessmentData) -> list[Finding]:
    projects = _infra(data).get("projects", [])
    if not projects:
        return []
    # "No deployments and no blueprints" is an absence claim over two other
    # areas: silent when either listing failed or was skipped, because a
    # project full of unread workloads would otherwise be called empty.
    if area_gap(data, "deployments", {"deployments"}) or area_gap(
        data, "blueprints", {"blueprints"}
    ):
        return []
    deployments = data.raw.get("deployments", {}).get("deployments", [])
    blueprints = data.raw.get("blueprints", {}).get("blueprints", [])
    deps_by_project: set[str] = {d.get("projectId", "") for d in deployments}
    bps_by_project: set[str] = {b.get("projectId", "") for b in blueprints}

    affected = [
        AffectedObject(
            kind="project",
            id=p.get("id", ""),
            name=p.get("name", ""),
            detail="no deployments and no blueprints",
        )
        for p in projects
        if p.get("id") not in deps_by_project and p.get("id") not in bps_by_project
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="PRJ-001",
            title="Projects with no deployments and no blueprints",
            severity=Severity.WARNING,
            recommendation=(
                "Confirm these projects are not reserved for planned work before deleting them."
            ),
            affected=affected,
        )
    ]


@check
def prj_002_memberless_projects(data: AssessmentData) -> list[Finding]:
    projects = _infra(data).get("projects", [])
    affected = []
    for p in projects:
        # All four roles of the IaaS Project model (supervisors confirmed in
        # this build's own swagger, 2026-08-12): a supervisors-only project
        # is administered, not memberless.
        members = (
            (p.get("administrators") or [])
            + (p.get("members") or [])
            + (p.get("supervisors") or [])
            + (p.get("viewers") or [])
        )
        if not members:
            affected.append(
                AffectedObject(
                    kind="project",
                    id=p.get("id", ""),
                    name=p.get("name", ""),
                    detail="no administrators, members, supervisors or viewers",
                )
            )
    if not affected:
        return []
    return [
        Finding(
            check_id="PRJ-002",
            title="Projects with no members of any role",
            severity=Severity.WARNING,
            recommendation=(
                "Assign the required project roles, or retire the project after owner review."
            ),
            affected=affected,
        )
    ]


@check
def prj_003_unverifiable_group_grants(data: AssessmentData) -> list[Finding]:
    """Projects granting to groups the organization does not list.

    Their membership cannot be read through any route this tool has found, so
    who these grants reach is unknown - which also means the access reported
    for owners on these projects is incomplete. Deliberately not called stale:
    absence from the organization's group list is not proof the group is gone.
    """
    identity = data.raw.get("identity", {})
    if not identity.get("collected"):
        return []
    unresolved = identity.get("unresolved") or []
    if not unresolved:
        return []
    names = data.derived.get("project_names", {})
    affected = [
        AffectedObject(
            kind="group",
            id=entry.get("principal", ""),
            name=entry.get("principal", ""),
            project=", ".join(
                names.get(pid) or f"(unknown project {pid[:8]})"
                for pid in entry.get("projects", [])
            ),
            detail=(
                f"granted on {len(entry.get('projects', []))} project(s), membership not readable"
            ),
        )
        for entry in unresolved
    ]
    return [
        Finding(
            check_id="PRJ-003",
            title="Projects that give access to groups the organization does not list",
            severity=Severity.INFO,
            recommendation=(
                "Verify these groups in your identity source before removing any "
                "unresolved project grants.\n"
                "A group with no role in the organization cannot reach Service "
                "Broker at all, so its project access gives it nothing."
            ),
            affected=affected,
        )
    ]


def _allocation_rows(data: AssessmentData) -> list[dict]:
    """Project-to-zone assignments with their limits resolved, worst first."""
    infra = _infra(data)
    zone_names = {z.get("id", ""): z.get("name", "") for z in infra.get("zones", [])}
    rows = zone_allocations(infra.get("projects", []), zone_names)
    return sorted(rows, key=lambda r: -_worst_ratio(r))


def _worst_ratio(row: dict) -> float:
    return max((entry["ratio"] or 0) for entry in row["limits"].values())


def _pressure_detail(row: dict, floor: float) -> str:
    """Name every limit at or above floor, with the numbers behind it. Limits
    below the floor are left to the allocation table: a finding that repeats
    an untroubled quota buries the one that matters."""
    parts = []
    for key, _limit_field, _used_field, label, unit in ZONE_LIMITS:
        entry = row["limits"][key]
        ratio = entry["ratio"]
        if ratio is None or ratio < floor:
            continue
        suffix = f" {unit}" if unit else ""
        if ratio > 1:
            state = "over limit"
        elif ratio >= 1:
            state = "full"
        else:
            state = f"{ratio:.0%}"
        parts.append(
            f"{label} {format_amount(entry['used'])} of "
            f"{format_amount(entry['limit'])}{suffix} ({state})"
        )
    return "; ".join(parts)


@check
def prj_004_zone_limits_reached(data: AssessmentData) -> list[Finding]:
    """Project quotas that have no room left in a cloud zone.

    The counters are the platform's own allocation figures, so this is what
    the next request meets rather than an estimate. A row can read above its
    limit: allocation is counted as it stands, and lowering a limit under what
    is already built leaves the project over it.
    """
    affected = [
        AffectedObject(
            kind="cloud-zone",
            id=row["zone_id"],
            name=row["zone"],
            project=row["project"],
            detail=_pressure_detail(row, 1),
        )
        for row in _allocation_rows(data)
        if _worst_ratio(row) >= 1
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="PRJ-004",
            title="Projects that have used up their quota in a cloud zone",
            severity=Severity.WARNING,
            recommendation=(
                "Review the project's zone quota; raise it if justified or release "
                "unneeded capacity.\n"
                "Set the limits on the project's Provisioning tab (Assembler, "
                "Infrastructure > Administration > Projects).\n"
                "A project with several zones can still build in the others, so the "
                "symptom is a build landing in one zone rather than every build "
                "failing."
            ),
            affected=affected,
        )
    ]


@check
def prj_005_zone_limits_near(data: AssessmentData) -> list[Finding]:
    """Quotas with little room left, reported before they stop a build."""
    affected = [
        AffectedObject(
            kind="cloud-zone",
            id=row["zone_id"],
            name=row["zone"],
            project=row["project"],
            detail=_pressure_detail(row, NEAR_LIMIT_RATIO),
        )
        for row in _allocation_rows(data)
        if NEAR_LIMIT_RATIO <= _worst_ratio(row) < 1
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="PRJ-005",
            title="Projects close to their quota in a cloud zone",
            severity=Severity.INFO,
            recommendation=(
                "Compare remaining quota with expected demand and raise the limit where justified."
            ),
            affected=affected,
        )
    ]


@check
def prj_006_projects_without_zones(data: AssessmentData) -> list[Finding]:
    """Projects with no cloud zone at all.

    The mirror of INF-001's zone half: a zone no project uses is unused
    configuration, and a project with no zone has nowhere to put a machine.
    """
    projects = _infra(data).get("projects", [])
    if not projects or area_gap(data, "infrastructure", {"projects"}):
        return []
    affected = [
        AffectedObject(
            kind="project",
            id=p.get("id", ""),
            name=p.get("name", ""),
            detail="no cloud zone assigned",
        )
        for p in projects
        if not (p.get("zones") or [])
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="PRJ-006",
            title="Projects with no cloud zone",
            severity=Severity.WARNING,
            recommendation=(
                "Assign a cloud zone if the project needs machine provisioning.\n"
                "Zone assignments are managed on the project's Provisioning tab.\n"
                "Projects that only carry catalog items running Orchestrator "
                "workflows or ABX actions need no zone, and belong here only as a "
                "reminder of what they cannot do."
            ),
            affected=affected,
        )
    ]
