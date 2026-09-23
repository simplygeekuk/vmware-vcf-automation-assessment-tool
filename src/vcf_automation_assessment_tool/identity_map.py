"""Who can still act on what: project grants, resolved through groups.

Shared by the report and the checks so both answer the question the same way.
The rules that matter are all about what may not be claimed:

* A grant reached through a group is a grant. Most of an AD estate's access
  arrives that way, and reporting only named principals calls the majority of
  owners ungranted.
* A group whose membership could not be read explains nothing, and the owners
  it might cover must stay unresolved rather than being reported as having no
  access at all.
* None of this says whether an account still exists in the directory. It says
  what the platform still grants, which is the half that can be acted on.
"""

from __future__ import annotations

from .collectors.identity import canonical_principal, identity_forms

# Project roles strongest first: an owner's column reports the strongest grant
# they hold, because that governs what they can still do with what they own.
PROJECT_ROLES = (
    ("administrators", "administrator"),
    ("supervisors", "supervisor"),
    ("members", "member"),
    ("viewers", "viewer"),
)
_ROLE_RANK = {word: rank for rank, (_, word) in enumerate(PROJECT_ROLES)}

# The deployment records a username, not a person: nobody owns these.
UNKNOWN_OWNER = "(unknown)"


def principal_index(projects: list[dict], identity: dict | None = None) -> dict:
    """Project grants keyed by every matchable form of an identity.

    Each entry maps a project id to (role, via) where via names the group that
    carried the grant, or is empty for a principal named directly.
    """
    identity = identity or {}
    groups_by_form: dict[str, dict] = {}
    for group in identity.get("groups") or []:
        for form in identity_forms(group.get("principal") or ""):
            groups_by_form.setdefault(form, group)

    by_identity: dict[str, dict[str, tuple[str, str]]] = {}
    named_users = 0
    # Keyed by the lower-cased canonical principal so that one group two
    # projects spell differently counts once. Counted per spelling, the note
    # under the ownership table and PRJ-003 report different numbers for the
    # same groups.
    resolved_groups: dict[str, str] = {}
    unreadable_groups: dict[str, str] = {}
    # Per project, because that is the scope the doubt actually applies to. An
    # unreadable group on some other project says nothing about an owner whose
    # own project grants only to principals that were read.
    unreadable_by_project: dict[str, dict[str, str]] = {}
    for project in projects or []:
        pid = project.get("id") or ""
        # Strongest role first, so the first grant recorded for a project wins.
        for field, word in PROJECT_ROLES:
            for principal in project.get(field) or []:
                if not isinstance(principal, dict):
                    continue
                name = principal.get("email") or ""
                if not name:
                    continue
                # Principal.type defaults to "user" when absent in the IaaS
                # project schema; only an explicit "group" is a group.
                if (principal.get("type") or "user").lower() != "group":
                    named_users += 1
                    for form in identity_forms(name):
                        by_identity.setdefault(form, {}).setdefault(pid, (word, ""))
                    continue
                group = next(
                    (groups_by_form[f] for f in identity_forms(name) if f in groups_by_form), None
                )
                shown = canonical_principal(name)
                if group is None or not group.get("members_read"):
                    unreadable_groups.setdefault(shown.lower(), shown)
                    unreadable_by_project.setdefault(pid, {}).setdefault(shown.lower(), shown)
                    continue
                resolved_groups.setdefault(shown.lower(), shown)
                for member in group.get("members") or []:
                    for form in identity_forms(member):
                        by_identity.setdefault(form, {}).setdefault(
                            pid, (word, group.get("name") or name)
                        )
    return {
        "by_identity": by_identity,
        "named_users": named_users,
        "resolved_groups": sorted(resolved_groups.values()),
        # Groups the organization does not list, or that would not expand.
        # Anyone reached only through one of these is unresolvable, not
        # ungranted, and every claim below has to allow for them.
        "unreadable_groups": sorted(unreadable_groups.values()),
        "unreadable_by_project": {
            pid: sorted(names.values()) for pid, names in unreadable_by_project.items()
        },
    }


def has_evidence(index: dict) -> bool:
    """Whether the index can support a claim about an individual at all.

    With no named principal and no expanded group anywhere, grants are either
    entirely invisible or were never readable, and absence from the index says
    nothing about anybody.
    """
    return bool(index.get("named_users") or index.get("resolved_groups"))


def owner_access(owner: str, project_ids: set[str], index: dict) -> tuple[str, str]:
    """(label, state) for one owner.

    State is "granted", "elsewhere", "unresolved" or "none" - the last two are
    deliberately different: unresolved means a group that could not be read
    might cover them, and only "none" is a finding.
    """
    grants: dict[str, tuple[str, str]] = {}
    for form in identity_forms(owner):
        grants.update(index["by_identity"].get(form, {}))
    here = [(role, via) for pid, (role, via) in grants.items() if pid in project_ids]
    if here:
        role, via = min(here, key=lambda pair: _ROLE_RANK[pair[0]])
        return (f"{role} (via {via})" if via else role), "granted"
    if grants:
        return "other projects only", "elsewhere"
    # Doubt only where it belongs: a group that would not expand on one of
    # this owner's own projects could be the one that covers them.
    unreadable = index.get("unreadable_by_project") or {}
    if any(unreadable.get(pid) for pid in project_ids):
        return "not determined", "unresolved"
    return "no grant found", "none"
