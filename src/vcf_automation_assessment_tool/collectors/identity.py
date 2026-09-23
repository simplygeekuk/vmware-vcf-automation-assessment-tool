"""Identity collector: the groups projects grant to, and who is in them.

Project membership is the platform's answer to "who can act on this", but on
an AD estate most of it arrives through groups - on a live run, 322 of the
380 grants across 69 projects went to groups and only 58 to named users.
Without expanding them the report can only say "no direct grant" about most
owners, which reads as an accusation and is usually wrong.

What the platform will and will not answer, established by probing a live
build rather than assumed:

* Projects spell the same group differently. The domain is written twice by
  the project service's own convention, but the case varies and some grants
  carry it once, so 191 distinct principal strings on the live estate were
  175 groups. They are merged on the organization's group id before anything
  is expanded, which is also what stops one group being fetched three times.
* /csp/gateway/am/api/orgs/{org}/groups lists groups the organization knows,
  paged with pageStart/pageLimit. On the live estate it held 141, covering
  115 of the 175 groups projects grant to.
* The other 60 are not in it and no other route reaches them: the RBAC
  service returns nothing at all here (a control project listing 80 viewers
  in its own document came back with total=0 under every parameter
  combination). Their membership is unknowable, so the report says so rather
  than treating absence as evidence about anybody.
* Nothing here says whether an account still exists in the directory. The
  platform holds principals that were granted something, not the directory.
"""

from __future__ import annotations

import logging

from ..client import ApiClient, ApiError
from ..models import AssessmentData

log = logging.getLogger(__name__)

AREA = "identity"

# Project roles that name a principal, strongest first.
PROJECT_ROLE_FIELDS = ("administrators", "supervisors", "members", "viewers")

# Roles every synced group carries. They say a group exists in the org, not
# that it was given anything in particular.
BASELINE_ROLES = frozenset({"org_member", "automationservice:user", "catalog:user"})


def collect(client: ApiClient, data: AssessmentData) -> None:
    if data.meta.get("group_membership") is False:
        data.raw[AREA] = {"collected": False, "groups": [], "unresolved": []}
        return
    projects = data.raw.get("infrastructure", {}).get("projects") or []
    org_id = next((p.get("orgId") for p in projects if p.get("orgId")), "")
    referenced = _referenced_groups(projects)
    if not org_id or not referenced:
        # No projects, no orgId, or no group grants: nothing to expand, and an
        # empty result here must not read as "these groups have no members".
        data.raw[AREA] = {"collected": False, "groups": [], "unresolved": []}
        return

    try:
        listing = list(client.iter_csp(f"/csp/gateway/am/api/orgs/{org_id}/groups"))
    except ApiError as exc:
        # Org-level identity data needs rights a narrow assessment account may
        # not have. Degrade to knowing nothing rather than to knowing nobody.
        log.warning("%s: org group listing failed: %s", AREA, exc)
        data.record_error(AREA, "org groups", str(exc))
        data.raw[AREA] = {"collected": False, "groups": [], "unresolved": []}
        return

    by_form: dict[str, dict] = {}
    for group in listing:
        for form in identity_forms(group.get("displayName") or ""):
            by_form.setdefault(form, group)
    log.info("%s: %d group(s) known to the organization", AREA, len(listing))

    # One group, one row. Projects name the same group in whatever form was
    # typed into each of them - the domain once or twice, upper case or lower -
    # and a live estate had three spellings of one group across thirteen
    # projects. Merging before anything is expanded is what stops that group
    # being fetched three times, listed three times, and counted as three.
    listed: dict[str, dict] = {}
    unlisted: dict[str, dict] = {}
    for principal, project_ids in sorted(referenced.items()):
        record = next((by_form[f] for f in identity_forms(principal) if f in by_form), None)
        shown = canonical_principal(principal)
        if record is None:
            entry = unlisted.setdefault(shown.lower(), {"principal": shown, "projects": set()})
        else:
            entry = listed.setdefault(
                record.get("id") or shown.lower(),
                {"principal": shown, "record": record, "projects": set()},
            )
        entry["projects"] |= project_ids

    groups = [
        _expand(client, data, org_id, e["principal"], e["record"], sorted(e["projects"]))
        for e in sorted(listed.values(), key=lambda e: e["principal"].lower())
    ]
    unresolved = [
        {"principal": e["principal"], "projects": sorted(e["projects"])}
        for e in sorted(unlisted.values(), key=lambda e: e["principal"].lower())
    ]
    if unresolved:
        log.info("%s: %d group(s) not known to the organization", AREA, len(unresolved))

    data.raw[AREA] = {
        "collected": True,
        "org_group_count": len(listing),
        "groups": groups,
        "unresolved": unresolved,
    }


def _referenced_groups(projects: list[dict]) -> dict[str, set[str]]:
    """Group principals named on projects, mapped to the projects naming them.

    Only these matter: the organization's group list is a directory, and
    expanding all of it would be thousands of calls for people no project
    grants anything to.
    """
    referenced: dict[str, set[str]] = {}
    for project in projects:
        for field in PROJECT_ROLE_FIELDS:
            for principal in project.get(field) or []:
                if not isinstance(principal, dict):
                    continue
                if (principal.get("type") or "user").lower() != "group":
                    continue
                name = principal.get("email") or ""
                if name:
                    referenced.setdefault(name, set()).add(project.get("id") or "")
    return referenced


def _expand(
    client: ApiClient,
    data: AssessmentData,
    org_id: str,
    principal: str,
    record: dict,
    project_ids: list[str],
) -> dict:
    """One group with its members, or with members_read False if it would not
    expand. The distinction is the whole point: an empty membership list and
    an unreadable one look identical downstream unless it is recorded."""
    group_id = record.get("id") or ""
    members: list[str] = []
    read = False
    try:
        rows = list(client.iter_csp(f"/csp/gateway/am/api/orgs/{org_id}/groups/{group_id}/users"))
        read = True
    except ApiError as exc:
        log.warning("%s: expanding %s failed: %s", AREA, principal, exc)
        data.record_error(AREA, f"group members:{principal}", str(exc))
        rows = []
    for row in rows:
        user = row.get("user") if isinstance(row.get("user"), dict) else row
        name = user.get("username") or user.get("acct") or user.get("email") or ""
        if name:
            members.append(name)
    roles = _roles(record)
    claimed = record.get("usersCount")
    return {
        "principal": principal,
        "id": group_id,
        "name": record.get("displayName") or principal,
        "domain": record.get("domain") or "",
        "projects": project_ids,
        "members": sorted(set(members)),
        "members_read": read,
        # The platform's own count. Where it disagrees with what came back the
        # expansion is short, and absence from the member list proves nothing.
        "members_claimed": claimed,
        "members_complete": read and (claimed is None or len(set(members)) == claimed),
        "roles": roles,
        "elevated_roles": [r for r in roles if r not in BASELINE_ROLES],
    }


def _roles(record: dict) -> list[str]:
    """Organization and service role names held by a group, flattened."""
    roles = [r.get("name") for r in record.get("organizationRoles") or [] if r.get("name")]
    roles += [
        name
        for service in record.get("serviceRoles") or []
        for name in service.get("serviceRoleNames") or []
    ]
    return sorted(set(roles))


def canonical_principal(name: str) -> str:
    """One spelling of a principal, for merging grants and for showing them.

    The doubled domain is the project service's own convention rather than
    damaged data, but a reader has no way to know that, and the same group
    reached from another project may carry the domain once or in a different
    case. Writing the domain once, in the case the platform gave it, makes the
    three spellings one group without inventing anything.
    """
    text = (name or "").strip()
    parts = text.split("@")
    if len(parts) == 3 and parts[1] and parts[1].lower() == parts[2].lower():
        return f"{parts[0]}@{parts[1]}"
    return text


def identity_forms(name: str) -> set[str]:
    """Every form an identity string may be matched on.

    A project names a group as "name@domain@domain" - the project service
    schema documents that convention outright - while the group's own
    displayName carries the domain once. Matching the bare local part as well
    is deliberately generous: wrongly reporting that somebody has access is a
    milder error than wrongly reporting they have none.
    """
    low = (name or "").strip().lower()
    if not low:
        return set()
    parts = low.split("@")
    if len(parts) == 3 and parts[1] and parts[1] == parts[2]:
        return {low, f"{parts[0]}@{parts[1]}", parts[0]}
    if low.endswith("@"):
        return {low, low[:-1]}
    return {low, parts[0]}
