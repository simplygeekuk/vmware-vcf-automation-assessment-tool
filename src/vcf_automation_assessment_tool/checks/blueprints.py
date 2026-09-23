"""Blueprint and tag cross-reference checks (BLU-001..003, TAG-001..004)."""

from __future__ import annotations

from ..models import AffectedObject, AssessmentData, Finding, Severity
from ..placement import (
    all_constraints,
    blueprints,
    capability_tags,
    constraint_match_gap,
    resolved_templates,
    resource_intersections,
    tag_evidence_missing,
)
from . import check


def _bp_obj(bp: dict, detail: str) -> AffectedObject:
    return AffectedObject(
        kind="blueprint",
        id=bp["id"],
        name=bp["name"],
        project=bp.get("projectName") or bp.get("projectId"),
        detail=detail,
    )


@check
def blu_001_invalid(data: AssessmentData) -> list[Finding]:
    affected = []
    for bp in blueprints(data):
        if bp.get("parse_error"):
            affected.append(_bp_obj(bp, f"YAML parse error: {bp['parse_error'][:150]}"))
        elif bp.get("valid") is False:
            msgs = bp.get("validationMessages") or []
            first = ""
            if msgs:
                m = msgs[0]
                first = (m.get("message", str(m)) if isinstance(m, dict) else str(m))[:150]
            affected.append(
                _bp_obj(bp, f"validation failed: {first}" if first else "validation failed")
            )
    if not affected:
        return []
    return [
        Finding(
            check_id="BLU-001",
            title="Cloud templates that fail validation or cannot be read",
            severity=Severity.WARNING,
            recommendation=(
                "Fix or delete these cloud templates. The platform cannot build anything "
                "from them today."
            ),
            affected=affected,
        )
    ]


@check
def blu_003_hardcoded_values(data: AssessmentData) -> list[Finding]:
    """Always on, not part of the opt-in REP family: credentials and
    environment specifics baked into template YAML are a hygiene and security
    finding regardless of any replacement plan."""
    affected = []
    for b in blueprints(data):
        quality = b.get("quality") or {}
        problems = []
        if quality.get("secrets"):
            problems.append(f"credential-looking literal(s): {', '.join(quality['secrets'][:3])}")
        if quality.get("ips"):
            problems.append(f"hardcoded IP(s): {', '.join(quality['ips'][:4])}")
        if quality.get("urls"):
            problems.append(f"hardcoded URL(s): {', '.join(quality['urls'][:3])}")
        if problems:
            affected.append(_bp_obj(b, "; ".join(problems)))
    if not affected:
        return []
    return [
        Finding(
            check_id="BLU-003",
            title="Templates with hardcoded IPs, URLs or credential-looking values",
            severity=Severity.WARNING,
            recommendation=(
                "Move credentials to protected secret references; replace hardcoded "
                "addresses and URLs with inputs or property groups.\n"
                "Credential-looking values may be visible to anyone who can read "
                "the template.\n"
                "Hardcoded addresses and URLs tie a template to one environment and "
                "break silently when that environment changes. Replace them with "
                "inputs or property groups."
            ),
            affected=affected,
        )
    ]


@check
def blu_002_draft_only(data: AssessmentData) -> list[Finding]:
    affected = [
        _bp_obj(bp, f"{bp.get('totalVersions', 0)} version(s), none released")
        for bp in blueprints(data)
        if bp.get("totalReleasedVersions", 0) == 0
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="BLU-002",
            title="Cloud templates with no released version",
            severity=Severity.INFO,
            recommendation=(
                "Release templates that are ready for use; review unfinished drafts "
                "with their owners."
            ),
            affected=affected,
        )
    ]


@check
def tag_001_unmatched_hard(data: AssessmentData) -> list[Finding]:
    cap = capability_tags(data)
    if tag_evidence_missing(data):
        return []
    affected = []
    for bp, ct in all_constraints(data):
        if ct["dynamic"] or ct["negated"] or not ct["hard"]:
            continue
        gap = constraint_match_gap(cap, ct)
        if gap:
            affected.append(
                _bp_obj(
                    bp,
                    f"hard constraint '{ct['tag']}' on {ct['resource']} ({ct['context']}) {gap}",
                )
            )
    if not affected:
        return []
    return [
        Finding(
            check_id="TAG-001",
            title="Required tags that no infrastructure offers",
            severity=Severity.CRITICAL,
            recommendation=(
                "Correct the required constraint or add its tag to the intended "
                "zone, profile or compute resource."
            ),
            affected=affected,
        )
    ]


@check
def tag_002_unmatched_soft(data: AssessmentData) -> list[Finding]:
    cap = capability_tags(data)
    if tag_evidence_missing(data):
        return []
    affected = []
    for bp, ct in all_constraints(data):
        # Dynamic (${input.x}) constraints are input-driven and cannot be
        # statically matched, so they are not reported at all; negated ones
        # are exclusions and have no "matching tag" requirement either.
        if ct["dynamic"] or ct["negated"] or ct["hard"]:
            continue
        gap = constraint_match_gap(cap, ct)
        if gap:
            affected.append(
                _bp_obj(
                    bp,
                    f"soft constraint '{ct['tag']}' on {ct['resource']} ({ct['context']}) {gap}",
                )
            )
    if not affected:
        return []
    return [
        Finding(
            check_id="TAG-002",
            title="Optional tags that match nothing",
            severity=Severity.WARNING,
            recommendation=("Correct or remove optional constraint tags that match nothing."),
            affected=affected,
        )
    ]


def _dynamic_prefixes(data: AssessmentData) -> list[str]:
    """Static prefixes of dynamic constraints, e.g. 'net:' from net:${input.env}.

    A dynamic constraint resolves at request time - the tool cannot know which
    tags it will produce, but the text before ${ bounds the possibilities. A
    constraint that STARTS with ${ has an empty prefix and could produce any
    tag at all.
    """
    return sorted({ct["tag"].split("${", 1)[0] for _, ct in all_constraints(data) if ct["dynamic"]})


@check
def tag_003_orphanedcapability_tags(data: AssessmentData) -> list[Finding]:
    cap = capability_tags(data)
    if not cap or not data.raw.get("blueprints"):
        return []
    # Consumers of a tag: blueprint constraints, project constraints, and cloud
    # zone compute filters (tagsToMatch selects fabric computes by their tags).
    consumed = {ct["tag"] for _, ct in all_constraints(data) if not ct["dynamic"]}
    consumed |= {
        tag
        for tag, uses in cap.items()
        if any(u["kind"] == "project" or "tagsToMatch" in u.get("via", "") for u in uses)
    }
    # Tags a dynamic constraint could select at request time are excluded
    # rather than called unreferenced - live estates drive network selection
    # exactly this way (net:<project>-<cluster>-<env> tags picked by an
    # input-built constraint), and flagging those was a false positive.
    dynamic_prefixes = _dynamic_prefixes(data)
    excluded_dynamic = 0
    affected = []
    for tag, uses in sorted(cap.items()):
        if tag in consumed:
            continue
        assignment_uses = [u for u in uses if u["kind"] != "project"]
        if not assignment_uses:
            continue
        if any(tag.startswith(p) for p in dynamic_prefixes):
            excluded_dynamic += 1
            continue
        # Dedupe by kind+name: the same object can surface once per
        # collection path (a fabric network seen by two cloud accounts).
        places = sorted({f"{u['kind']} '{u['name']}'" for u in assignment_uses})
        where = ", ".join(places[:5])
        if len(places) > 5:
            where += f" (+{len(places) - 5} more)"
        affected.append(
            AffectedObject(
                kind="tag",
                id=tag,
                name=tag,
                detail=f"assigned to {where}; referenced by no blueprint or project constraint",
            )
        )
    if not affected:
        return []
    dyn_note = (
        f" A further {excluded_dynamic} assigned tag(s) are not listed because a "
        "request-time (dynamic) constraint in a template could select them."
        if excluded_dynamic
        else ""
    )
    return [
        Finding(
            check_id="TAG-003",
            title="Capability tags not referenced by any visible constraint",
            severity=Severity.INFO,
            recommendation=(
                "Remove these tags only after their owners confirm that no "
                "placement, script or external tool needs them.\n"
                "No visible placement reference does not prove a tag is unused: "
                "extensibility scripts and "
                "tooling outside the platform (backup, monitoring, CMDB) can key "
                "off tags without the platform knowing." + dyn_note
            ),
            affected=affected,
        )
    ]


@check
def tag_005_constraints_that_share_no_place(data: AssessmentData) -> list[Finding]:
    """Hard constraints on one resource that cannot be met together.

    Each one matches something, so TAG-001 says nothing, and every build of
    the resource fails anyway because no single place matches them all.
    """
    if tag_evidence_missing(data):
        return []
    resolved, scope = resolved_templates(data)
    affected = []
    for entry in resolved:
        zone_ids = scope.zone_ids(entry["project_ids"])
        for (name, _res_type), constraints in entry["resources"].items():
            for group in resource_intersections(constraints, scope, zone_ids):
                if not group["conflict"]:
                    continue
                tags = ", ".join(f"'{t}'" for t in group["tags"])
                affected.append(
                    _bp_obj(
                        entry["blueprint"],
                        f"{name} asks for {tags} together, and no {group['kind']} place "
                        "carries all of them",
                    )
                )
    if not affected:
        return []
    return [
        Finding(
            check_id="TAG-005",
            title="Constraints on one resource that nothing satisfies together",
            severity=Severity.CRITICAL,
            recommendation=(
                "Align the constraint tags so one eligible placement satisfies them "
                "all.\n"
                "Either tag one zone, profile or computer with the whole set, or "
                "drop the constraint that does not belong on that resource."
            ),
            affected=affected,
        )
    ]


# How many of the projects that cannot place a template are named before the
# finding says "and N more". It was borrowing the tag table's consumer cap,
# which is a different list with a different reason to be capped.
MAX_PROJECTS_SHOWN = 8


@check
def tag_004_unplaceable_in_a_requesting_project(data: AssessmentData) -> list[Finding]:
    """A template shared with projects that have no zone satisfying it.

    TAG-001 answers whether the estate carries the tag at all. This answers a
    different question with a different owner: the tag exists, and the project
    the request comes from is assigned nothing that carries it. On a live
    estate one template was requestable from 45 projects and placeable in 19.
    """
    if tag_evidence_missing(data):
        return []
    resolved, scope = resolved_templates(data)
    if not scope.usable:
        # No project carries a zone assignment: "cannot place" would be a
        # claim about a map that was never read.
        return []
    affected = []
    for entry in resolved:
        missing, projects = entry["cannot_place"], entry["project_ids"]
        if not missing:
            continue
        names = sorted(data.derived.get("project_names", {}).get(pid, pid) for pid in missing)
        shown = ", ".join(names[:MAX_PROJECTS_SHOWN])
        if len(names) > MAX_PROJECTS_SHOWN:
            shown += f" (+{len(names) - MAX_PROJECTS_SHOWN} more)"
        affected.append(
            _bp_obj(
                entry["blueprint"],
                f"{len(missing)} of {len(projects)} project(s) that can request it have no "
                f"zone satisfying its constraints: {shown}",
            )
        )
    if not affected:
        return []
    return [
        Finding(
            check_id="TAG-004",
            title="Templates shared with projects that cannot build them",
            severity=Severity.WARNING,
            recommendation=(
                "Assign a matching cloud zone to the project, or stop sharing the "
                "item with it.\n"
                "The tags themselves are fine: TAG-001 covers the case where "
                "nothing in the estate carries them at all, and a project with no "
                "zone assignment at all is PRJ-006 rather than a fault of any one "
                "template."
            ),
            affected=affected,
        )
    ]
