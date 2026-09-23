"""Where a request can actually be placed.

The placement model, kept apart from the checks that report on it because two
consumers share it: the TAG findings and the report's placement diagrams. A
finding and a diagram disagreeing about the same constraint is the one failure
this code cannot have, and one model with two readers is what stops it.

It lives beside the other derived models - access.py, flows.py, identity_map.py
- rather than inside a checks module, which is also where the renderer expects
to find something it draws from. Which template asks for which tag is the same
model read from the other end, so the tag table's labels are built here too.

Two dialects of constraint travel through here and they are not
interchangeable. A constraint as the collector wrote it carries the resource
type and the raw tag. A constraint this module has resolved carries its places,
its state and the kind it was resolved as, and no resource type at all. Any
function taking one must say which.
"""

from __future__ import annotations

from .access import has_sharing_evidence
from .flows import item_blueprints
from .models import AssessmentData, area_gap
from .tagutil import describe_dynamic_tag, input_source_label


def blueprints(data: AssessmentData) -> list[dict]:
    return data.raw.get("blueprints", {}).get("blueprints", [])


def capability_tags(data: AssessmentData) -> dict[str, list[dict]]:
    return data.derived.get("capability_tags", {})


# The collections the capability-tag map is built from. A failed fetch of any
# of them leaves tags invisible, so a constraint may match on the live estate
# while matching nothing here.
_TAG_SOURCES = {
    "cloud_accounts",
    "zones",
    "fabric_computes",
    "network_profiles",
    "fabric_networks",
    "storage_profiles",
    "projects",
}


def tag_evidence_missing(data: AssessmentData) -> bool:
    """True when the capability-tag map cannot be trusted as complete.

    Infrastructure skipped entirely, or any tag-bearing collection failed:
    an unmatched-constraint claim (up to CRITICAL) would then rest on a map
    with holes in it, so the TAG checks stay silent instead.
    """
    if not data.raw.get("infrastructure"):
        return True
    return area_gap(data, "infrastructure", _TAG_SOURCES)


def all_constraints(data: AssessmentData):
    for bp in blueprints(data):
        for ct in bp.get("constraint_tags", []):
            yield bp, ct


# Which family of places a constraint selects from. The resource type decides
# it for a resource's own constraints, because a Cloud.Network resource selects
# networks rather than zones, and the context decides it for the network and
# storage blocks nested inside a machine.
def constraint_kind(ct: dict) -> str:
    """Which family of places a constraint selects from, read from the
    template's own constraint tag.

    Takes a constraint as the blueprint collector wrote it, carrying the
    resource type. A constraint already resolved by _placement_constraint
    carries the answer as its "kind" and must use that: the resolved dict has
    no resource type, so re-deriving it here calls a standalone network or
    storage resource compute.
    """
    context = ct.get("context") or "resource"
    if context.startswith("network"):
        return "network"
    if context == "storage" or context.startswith("disk"):
        return "storage"
    rtype = (ct.get("resource_type") or "").lower()
    if "network" in rtype:
        return "network"
    if "volume" in rtype or "disk" in rtype or "storage" in rtype:
        return "storage"
    return "compute"


# The places each kind of resource is put on. A machine lands in a cloud zone,
# on a compute in it, or on one of the account's computes through the tags the
# account passes down. A network resource takes a network profile or a fabric
# network, and a disk takes a storage profile. Nothing else can satisfy them.
_ELIGIBLE_PLACES = {
    "compute": {"cloud-zone", "fabric-compute", "cloud-account"},
    "network": {"network-profile", "fabric-network"},
    "storage": {"storage-profile"},
}

_PLACED_ON = {
    "compute": "a cloud zone, a compute or an account that passes its tags down",
    "network": "a network profile or a fabric network",
    "storage": "a storage profile",
}


def _project_requirement_applies(source: dict, kind: str) -> bool:
    """Whether a project constraint bears on this constraint's placement.

    A project constrains network and storage requests through its own lists,
    so one of those is an extra requirement on a resource of that kind. Its
    extensibility list selects the runner that executes extensibility work and
    never touches placement: on a live estate, 66 of 70 project constraints
    were extensibility ones, and 57 of them were drawn as a requirement on a
    machine. A list this tool does not recognise is left alone rather than
    read as one of the others.
    """
    ctype = (source.get("constraint_type") or "").strip().lower()
    return bool(ctype) and ctype != "extensibility" and ctype == kind


def constraint_match_gap(cap: dict[str, list[dict]], ct: dict) -> str | None:
    """Why this constraint matches no capability tag - None when it matches.

    A tag only counts where it sits on something the resource can be put on. A
    machine is placed on a cloud zone or a compute, and cloud-account tags are
    inherited by the account's compute resources, so an account tag counts for
    a machine. Storage profiles are the documented exception to that
    inheritance: 8.10 removed the unintended compute to storage propagation,
    so a tag living only on a cloud account cannot satisfy a disk. A network
    resource is placed on a network profile or a fabric network, and a tag on
    a cloud zone says nothing about where its network can go.

    A project constraint never satisfies anything. It is a requirement the
    project adds to the requests made in it, not a tag on infrastructure, so a
    tag that only a project names is a tag nothing offers.
    """
    sources = [s for s in cap.get(ct["tag"]) or [] if s["kind"] != "project"]
    if not sources:
        if cap.get(ct["tag"]):
            return (
                "matches no capability tag: only a project constraint names it, "
                "which is a requirement on requests rather than somewhere to build"
            )
        return "matches no capability tag"
    kind = constraint_kind(ct)
    if any(s["kind"] in _ELIGIBLE_PLACES[kind] for s in sources):
        return None
    if kind == "storage" and all(s["kind"] == "cloud-account" for s in sources):
        # Kept as its own sentence: it is the one documented exception, and it
        # is the difference between a mistake and a version change.
        return (
            "matches only a cloud account tag, and storage profiles "
            "do not inherit account-level tags"
        )
    carried_by = ", ".join(sorted({s["kind"] for s in sources}))
    return f"matches only {carried_by}, and this resource is placed on {_PLACED_ON[kind]}"


def _requesting_projects(data: AssessmentData) -> dict[str, set[str]]:
    """Template id -> the projects that can request it.

    A library template is authored in one project and requested from many. On
    a live estate, five of the six templates worth drawing sit in projects
    with no zones at all, and their catalog items are shared with 43 to 46
    others. Placement happens in the project the request comes from, so that
    is the set that decides where the request can land.
    """
    joined = item_blueprints(data)
    out: dict[str, set[str]] = {}
    for item in data.raw.get("catalog", {}).get("items", []):
        bp = joined.get(item.get("id", ""))
        if bp and bp.get("id"):
            out.setdefault(bp["id"], set()).update(item.get("projectIds") or [])
    return out


class PlacementScope:
    """Which places a request can reach, and whether that is knowable at all.

    A machine is placed in a cloud zone assigned to the requesting project, so
    the candidate zones are the zones of the projects that can request the
    template. A network profile, a fabric network or a storage profile is
    reachable when it sits in the cloud account and region of one of those
    zones.

    Nothing here rules a place out on a missing fact. An estate where no
    project carries a zone assignment leaves `usable` False and every place
    allowed, which is how the diagrams read before any of this.
    """

    def __init__(self, data: AssessmentData):
        infra = data.raw.get("infrastructure") or {}
        self.zones_by_project: dict[str, set[str]] = {
            proj.get("id", ""): {
                za.get("zoneId", "") for za in proj.get("zones") or [] if za.get("zoneId")
            }
            for proj in infra.get("projects") or []
        }
        self.zone_names: dict[str, str] = {
            z.get("id", ""): z.get("name") or z.get("id", "") for z in infra.get("zones") or []
        }
        self.zone_home: dict[str, tuple[str, str]] = {
            z.get("id", ""): (z.get("cloudAccountId") or "", z.get("externalRegionId") or "")
            for z in infra.get("zones") or []
            if z.get("id")
        }
        self.zone_computes: dict[str, set[str]] = {
            zid: set(ids) for zid, ids in (infra.get("zone_computes") or {}).items()
        }
        # Where each place that is not a zone lives, so reachability is a
        # lookup. A fabric network can belong to several accounts, which is
        # why the value is a set of pairs.
        self.place_home: dict[tuple[str, str], set[tuple[str, str]]] = {}
        for kind, docs in (
            ("network-profile", infra.get("network_profiles")),
            ("fabric-network", infra.get("fabric_networks")),
            ("storage-profile", infra.get("storage_profiles")),
        ):
            for doc in docs or []:
                accounts = doc.get("cloudAccountIds") or [doc.get("cloudAccountId") or ""]
                region = doc.get("externalRegionId") or ""
                self.place_home[(kind, doc.get("id", ""))] = {(a or "", region) for a in accounts}
        self.usable = any(self.zones_by_project.values())

    def zone_ids(self, project_ids) -> set[str]:
        found: set[str] = set()
        for project_id in project_ids:
            found |= self.zones_by_project.get(project_id, set())
        return found

    def allows(self, source: dict, zone_ids: set[str]) -> bool:
        """Whether a request placed in these zones can reach this place."""
        if not self.usable or not zone_ids:
            return True
        kind, place_id = source.get("kind"), source.get("id") or ""
        if kind == "cloud-zone":
            return place_id in zone_ids
        if kind == "fabric-compute":
            # A zone the collector could not list is absent from the map, not
            # empty, and what it holds is unknown. Reading an absent zone as
            # an empty one turns one failed listing into an unplaceable
            # template and a warning about it.
            return any(
                zid not in self.zone_computes or place_id in self.zone_computes[zid]
                for zid in zone_ids
            )
        homes = {self.zone_home.get(zid, ("", "")) for zid in zone_ids}
        if any(not account for account, _ in homes):
            # A zone whose account the listing did not carry: what it reaches
            # is unknown, and an unknown is not a reason to rule anything out.
            return True
        if kind == "cloud-account":
            return any(account == place_id for account, _ in homes)
        place = self.place_home.get((kind, place_id))
        return True if place is None else bool(place & homes)


def _dedupe_places(places: list[dict]) -> list[dict]:
    """One entry per place, ordered by kind then name.

    The same object surfaces once per collection path it was reached by (a
    fabric network seen through two cloud accounts), and a duplicate is not a
    second place a resource could land.
    """
    seen: dict[tuple[str, str], dict] = {}
    for place in places:
        seen.setdefault((place["kind"], place["name"]), place)
    return [seen[key] for key in sorted(seen)]


def _dedupe_requirements(requirements: list[dict]) -> list[dict]:
    """One entry per project and the thing it says about the tag.

    Keyed on what it claims as well as who claims it: one project can name
    the same tag in its network list and rule it out in its storage list, and
    collapsing those two on the project name alone drops one of them.
    """
    seen: dict[tuple, dict] = {}
    for entry in requirements:
        key = (
            entry["name"],
            entry.get("constraint_type") or "",
            bool(entry.get("negated")),
            bool(entry.get("hard", True)),
        )
        seen.setdefault(key, entry)
    return [seen[key] for key in sorted(seen)]


def _placement_constraint(
    cap: dict[str, list[dict]],
    ct: dict,
    scope: PlacementScope | None = None,
    zone_ids: set[str] | None = None,
    by_project: dict[str, set[str]] | None = None,
    inputs: dict[str, dict] | None = None,
) -> dict:
    """One constraint with the places that satisfy it, and what that means.

    States, and why each exists:

    * unsatisfied - nothing carries the tag, or the one thing that does is a
      cloud account and this is a storage context. Hard means placement
      always fails; soft means the constraint is silently ignored.
    * single - at most one place satisfies it, so that zone, profile or
      compute is a single point of failure for every deployment of this
      template. No finding reports this today; the diagram is where it
      shows. Counted over places only: a project-level constraint carrying the same
      tag is another requirement to satisfy rather than somewhere to build,
      and counting it hid four one-place hard constraints on a live estate
      behind the 57 projects that demanded the same tag.
    * open - two or more places satisfy it.
    * unverifiable - a ${input.x} constraint resolves at request time and
      cannot be matched statically. Where the expression chooses between
      tags written out in the template, or names one input whose values the
      platform declares, each of those values is resolved as an option:
      which one a request takes is unknowable, but where each one would land
      is not.
    * exclusion - a negated constraint rules places out rather than in, so
      matching nothing is not a fault.
    """
    kind = constraint_kind(ct)
    targets, reachable, requirements = [], [], []
    eligible: list[dict] = []
    for source in cap.get(ct["tag"]) or []:
        place = {
            "kind": source["kind"],
            "name": source.get("name") or "(unnamed)",
            "via": source.get("via") or "",
        }
        # A project constraint is a requirement the project imposes on the
        # requests made in it, not a place anything lands on, and only the
        # list covering this kind of resource bears on it at all.
        if source["kind"] == "project":
            if _project_requirement_applies(source, kind):
                place["constraint_type"] = source.get("constraint_type") or ""
                # A project can rule a tag out as well as ask for it, and a
                # soft one is a preference. Reading every entry as "also
                # required by" says the opposite of what a negated one does.
                place["hard"] = bool(source.get("hard", True))
                place["negated"] = bool(source.get("negated"))
                requirements.append(place)
            continue
        # A tag on something this resource cannot be put on is not a place it
        # can land, and drawing it as one is what the gap above refuses to do.
        if source["kind"] in _ELIGIBLE_PLACES[kind]:
            targets.append(place)
            eligible.append(source)
            if scope is None or scope.allows(source, zone_ids or set()):
                reachable.append(place)
    # Only the places a request can reach are drawn, and where scoping leaves
    # nothing the constraint is unreachable rather than quietly estate-wide.
    unreachable = bool(targets) and not reachable
    targets = _dedupe_places(reachable)
    requirements = _dedupe_requirements(requirements)
    # Which requesting projects cannot reach any place satisfying it. Every
    # request made from one of them fails on this constraint.
    misses = _missing_projects(scope, eligible, by_project)

    gap, note = None, ""
    expression, options = None, []
    if ct["dynamic"]:
        state = "unverifiable"
        expression, options = _request_time_options(cap, ct, scope, zone_ids, by_project, inputs)
    elif ct["negated"]:
        state = "exclusion"
    else:
        gap = constraint_match_gap(cap, ct)
        if gap:
            state = "unsatisfied"
        elif unreachable:
            # The tag is on something, and on nothing any project that can
            # request the template is assigned.
            state = "unsatisfied"
            gap = "no place a project requesting this template can use carries the tag"
        elif len(targets) <= 1:
            state = "single"
        else:
            state = "open"
        # No note for "only a project constraint carries this tag" any more:
        # a tag nothing but a project names is unsatisfied, and the gap says so.
    return {
        "tag": ct["tag"],
        "hard": bool(ct["hard"]),
        "negated": bool(ct["negated"]),
        "dynamic": bool(ct["dynamic"]),
        "context": ct.get("context") or "resource",
        # Which family of places it selects from, so a consumer never has to
        # work it out again from the resource type and the context.
        "kind": kind,
        "state": state,
        "gap": gap,
        "note": note,
        "targets": targets,
        "requirements": requirements,
        # Both None/empty unless the constraint is dynamic: how the tag is
        # decided, and one resolved constraint per tag it can be decided on.
        "expression": expression,
        "options": options,
        # What carries the tag, kept so an intersection can ask which zones
        # each source puts a machine in.
        "sources": eligible,
        # Requesting projects that cannot reach any place satisfying it, and
        # how many could ask for the template at all.
        "misses": misses,
        "projects_total": len(by_project or {}),
    }


def _missing_projects(
    scope: PlacementScope | None,
    eligible: list[dict],
    by_project: dict[str, set[str]] | None,
) -> list[str]:
    """The projects among by_project that reach none of these places.

    Empty where the estate cannot answer the question, which is the same
    silence the rest of the placement code keeps: a project with no zone
    assignment is not a project that cannot place anything, it is a project
    whose zones were not read.
    """
    if not (scope and scope.usable and eligible and by_project):
        return []
    return sorted(
        project_id
        for project_id, zones in by_project.items()
        if zones and not any(scope.allows(source, zones) for source in eligible)
    )


def _request_time_options(
    cap: dict[str, list[dict]],
    ct: dict,
    scope: PlacementScope | None = None,
    zone_ids: set[str] | None = None,
    by_project: dict[str, set[str]] | None = None,
    inputs: dict[str, dict] | None = None,
) -> tuple[dict, list[dict]]:
    """How a request-time constraint decides its tag, and where each tag it
    can decide on would land.

    Values come from two places, both of them written down: an expression
    choosing between tags spelled out in the template, and an input whose
    candidate values the platform declares in the schema the request form is
    built from. Each value then goes through _placement_constraint like any
    static constraint, so one that matches nothing is a dead end for the same
    reason, decided by the same function, as one written directly.

    An input filled from somewhere else - an Orchestrator action, typically -
    yields no values at all. The action is named instead: running it to find
    out is not something a read-only assessment does.
    """
    described = describe_dynamic_tag(ct["tag"])
    expression = {
        "kind": described.kind,
        "references": list(described.references),
        "prefix": described.prefix,
        # Set only where the constraint is one input and the platform says
        # where that input's values come from.
        "input": "",
        "source": "",
    }
    values = described.values
    if not values and described.kind == "reference":
        values = _declared_input_values(described.references, expression, inputs)
    options = [
        _placement_constraint(
            cap, {**ct, "tag": value, "dynamic": False}, scope, zone_ids, by_project
        )
        for value in values
    ]
    return expression, options


def _declared_input_values(
    references: tuple[str, ...],
    expression: dict,
    inputs: dict[str, dict] | None,
) -> tuple[str, ...]:
    """What the one input a constraint names can be, as the platform says.

    Only a constraint that is exactly one input reference resolves this way.
    The values are the strings the schema declares, so a redacted copy
    rewrites them with the tag map rather than printing a real tag beside a
    renamed estate.
    """
    if len(references) != 1:
        return ()
    namespace, _, name = references[0].partition(".")
    if namespace != "input" or not name:
        return ()
    expression["input"] = name
    entry = (inputs or {}).get(name)
    if not entry:
        return ()
    if entry.get("kind") == "external" and entry.get("source"):
        expression["source"] = input_source_label(entry["source"])
        return ()
    if entry.get("kind") != "declared":
        return ()
    return tuple(entry.get("values") or ())


# States that make a template worth drawing. A template whose every constraint
# resolves to two or more places produces a diagram that says
# "this is fine" at the cost of a page of report, which is the reasoning that
# retired the access map and the org-wide topology.
DRAWN_STATES = ("unsatisfied", "single")


def _dead_options(c: dict) -> int:
    """Values this constraint offers that match no place.

    Only a hard constraint counts. A soft one the platform ignores rather than
    fails, so a value of it matching nothing costs a request nothing.
    """
    if not c["hard"] or c["negated"]:
        return 0
    return sum(1 for o in c["options"] if o["state"] == "unsatisfied")


def _worth_drawing(c: dict) -> bool:
    """Whether this constraint is a reason to draw its template.

    A resolved request-time value is otherwise display-only: which value a
    request takes is unknowable, and a template whose values all land
    somewhere is not worth a page. A hard value that lands nowhere is
    different. The form offers it, every request choosing it fails to place,
    and no finding reports it - TAG-001 skips request-time constraints by
    design, because it cannot say the template is broken for every request.
    """
    return c["state"] in DRAWN_STATES or bool(_dead_options(c))


def resolved_templates(data: AssessmentData) -> tuple[list[dict], PlacementScope]:
    """Every template with its constraints resolved against what its requests
    can reach, and which of the requesting projects cannot place it.

    One resolution, two consumers: the diagrams draw from it and TAG-004
    reports from it, so a project named in the finding is a project named on
    the diagram.
    """
    cap = capability_tags(data)
    scope = PlacementScope(data)
    requesting = _requesting_projects(data)
    # Whether this build says anything at all about who a catalog item is
    # shared with. Without it, an item with no projects on it is an unread
    # sharing map rather than an item nobody can ask for.
    sharing_known = has_sharing_evidence(data)
    resolved = []
    for bp in blueprints(data):
        # The projects that can request it, or the one that owns it when it is
        # in no catalog item.
        blueprint_id = bp.get("id") or ""
        project_ids = set(requesting.get(blueprint_id) or ())
        # A template shared through the catalog whose sharing could not be
        # read is not a template that can only be requested where it was
        # written. Narrowing to the authoring project there would turn a
        # failed read into a dead end and a finding, so the scoping is
        # withheld and the estate-wide places are shown instead.
        scope_unknown = not project_ids and blueprint_id in requesting and not sharing_known
        if not project_ids and not scope_unknown and bp.get("projectId"):
            project_ids = {bp["projectId"]}
        zone_ids = scope.zone_ids(project_ids)
        by_project = {pid: scope.zones_by_project.get(pid, set()) for pid in project_ids}

        inputs = {i["name"]: i for i in bp.get("inputs") or [] if i.get("name")}
        resources: dict[tuple[str, str], list[dict]] = {}
        for ct in bp.get("constraint_tags") or []:
            key = (ct.get("resource") or "?", ct.get("resource_type") or "")
            resources.setdefault(key, []).append(
                _placement_constraint(cap, ct, scope, zone_ids, by_project, inputs)
            )
        constraints = [c for entries in resources.values() for c in entries]
        # A project that cannot satisfy one hard constraint cannot place the
        # template: every request it makes fails on that one. Soft constraints
        # are ignored at request time, so they never make a template
        # unplaceable, and a request-time constraint is unknowable rather than
        # unplaceable - its own values carry their own misses.
        cannot_place: set[str] = set()
        for c in constraints:
            if c["hard"] and not c["negated"] and not c["dynamic"]:
                cannot_place |= set(c["misses"])
        # And the projects where every constraint is satisfiable but no single
        # place satisfies them all, which is the same failure a resource at a
        # time rather than a constraint at a time.
        for entries in resources.values():
            cannot_place |= _projects_without_one_place(entries, scope, by_project)
        resolved.append(
            {
                "blueprint": bp,
                "project_ids": project_ids,
                "resources": resources,
                "constraints": constraints,
                "cannot_place": sorted(cannot_place),
                "scope_unknown": scope_unknown,
            }
        )
    return resolved, scope


def resource_intersections(
    constraints: list[dict],
    scope: PlacementScope | None = None,
    zone_ids: set[str] | None = None,
) -> list[dict]:
    """Per constraint kind on one resource, what satisfies all of it at once.

    The platform needs one place that meets every hard constraint together,
    and the diagrams answered one constraint at a time. Two constraints that
    each match something, with nothing in common, are a resource that can
    never be built, and neither constraint looks wrong on its own.

    A machine lands in a cloud zone, so compute constraints are intersected
    over zones and not over the objects carrying the tags. Intersecting those
    compares a cloud account with a cloud zone, which never match even when a
    zone inside that account carries both tags: the live estate produced two
    critical findings that way, both wrong. A network or storage constraint is
    satisfied by the profile itself, so there the object is the basis.

    Only constraints that reach somewhere are intersected. One that reaches
    nowhere is already a dead end that TAG-001 or TAG-004 reports, and folding
    it in here would report the same fault twice with a worse explanation.
    """
    groups: dict[str, list[dict]] = {}
    for c in constraints:
        if c["hard"] and not c["negated"] and not c["dynamic"] and c["targets"]:
            # The kind the constraint was resolved with, not one derived
            # again: a resolved constraint carries no resource type, so a
            # standalone network or storage resource would come back compute
            # and be intersected over zones instead of over its profiles.
            groups.setdefault(c["kind"], []).append(c)
    out = []
    for kind, group in groups.items():
        if len(group) < 2:
            # One constraint is its own answer, and its node already says it.
            continue
        if kind == "compute":
            if not (scope and scope.usable and zone_ids):
                # No zone assignment to reason over, so no claim.
                continue
            shared_zones = set.intersection(*(_zones_satisfying(scope, c, zone_ids) for c in group))
            places = sorted(scope.zone_names.get(z, z) for z in shared_zones)
            conflict = not shared_zones
        else:
            shared = set.intersection(*(_places_satisfying(scope, c, zone_ids) for c in group))
            places = sorted(f"{place_kind}: {name}" for place_kind, name in shared)
            conflict = not shared
        out.append(
            {
                "kind": kind,
                "tags": [c["tag"] for c in group],
                "places": places,
                "conflict": conflict,
            }
        )
    return out


def _places_satisfying(
    scope: PlacementScope | None, c: dict, zone_ids: set[str] | None
) -> set[tuple[str, str]]:
    """The profiles satisfying this constraint that a request placed in these
    zones can use.

    Read from the sources rather than from the places already on the
    constraint, because those were narrowed once, against every requesting
    project's zones together. Asking the question for one project needs the
    narrowing done again with that project's zones.
    """
    return {
        (s["kind"], s.get("name") or "(unnamed)")
        for s in c.get("sources") or []
        if scope is None or scope.allows(s, zone_ids or set())
    }


def _projects_without_one_place(
    constraints: list[dict],
    scope: PlacementScope | None,
    by_project: dict[str, set[str]] | None,
) -> set[str]:
    """Requesting projects where no one place meets every hard constraint on
    this resource.

    Each constraint can be satisfiable in the project and the resource still
    unbuildable there: one zone carries the first tag, another carries the
    second, and a machine lands in one zone. Asked per project because that is
    where a request is placed. Asking it across every requesting project's
    zones at once hides the case behind whichever other project happens to
    hold a zone carrying both.
    """
    if not (scope and scope.usable and by_project):
        return set()
    return {
        project_id
        for project_id, zones in by_project.items()
        if zones
        and any(group["conflict"] for group in resource_intersections(constraints, scope, zones))
    }


def _zones_satisfying(scope: PlacementScope, c: dict, zone_ids: set[str]) -> set[str]:
    """The candidate zones a machine constrained by this tag can land in.

    A zone qualifies through its own tags, through the account that passes its
    tags down to the computes in it, or through a compute it holds.
    """
    return {
        zone_id
        for zone_id in zone_ids
        if any(scope.allows(source, {zone_id}) for source in c.get("sources") or [])
    }


def template_placements(data: AssessmentData) -> tuple[list[dict], str]:
    """(templates worth a placement diagram, note on what is not drawn and why).

    A placement is the resolution the platform performs at request time, in
    the order it performs it: the template, each resource it declares, the
    constraint tags on that resource, and the zones, profiles and computes
    whose capability tags satisfy them.

    Whether a constraint is satisfied is decided by constraint_match_gap,
    the same function TAG-001 and TAG-002 use, so a dead end in a diagram and
    a finding in the table can never disagree about the same constraint.
    """
    if tag_evidence_missing(data):
        # The same guard the TAG checks apply: with holes in the capability
        # tag map, a dead end could be an unread tag rather than a missing
        # one, and a diagram asserts it far more loudly than a table.
        return [], (
            "Placement diagrams are withheld for this run: the capability tag map "
            "has gaps (see Collection Gaps), so a constraint that matches nothing "
            "here cannot be told from one whose tags could not be read."
        )
    resolved, scope = resolved_templates(data)
    project_names = data.derived.get("project_names", {})
    placements, unconstrained = [], 0
    # Why each undrawn template is undrawn. "Resolves to two or more places"
    # covered all of them until a live estate turned out to decide 75 of its
    # 97 constraints from a request-time input, which is a different fact
    # about the estate and was being reported as the wrong one.
    undrawn = {"wide": 0, "dynamic": 0, "mixed": 0}
    for entry in resolved:
        bp, resources = entry["blueprint"], entry["resources"]
        project_ids = entry["project_ids"]
        if not resources:
            unconstrained += 1
            continue
        constraints = entry["constraints"]
        if not any(_worth_drawing(c) for c in constraints):
            states = {c["state"] for c in constraints}
            undrawn[_undrawn_reason(states)] += 1
            continue
        placements.append(
            {
                "blueprint_id": bp.get("id") or "",
                "blueprint_name": bp.get("name") or "(unnamed template)",
                "project": bp.get("projectName") or bp.get("projectId") or "",
                # Who can ask for it, which is who decides where it lands.
                "requesting_projects": sorted(project_names.get(pid, pid) for pid in project_ids),
                # And which of those a request would fail from.
                "cannot_place": sorted(
                    project_names.get(pid, pid) for pid in entry["cannot_place"]
                ),
                "resources": [
                    {
                        "name": name,
                        "type": res_type,
                        "constraints": entries,
                        # What satisfies every hard constraint here at once,
                        # which is the question the platform actually asks.
                        "intersections": resource_intersections(
                            entries, scope, scope.zone_ids(project_ids)
                        ),
                    }
                    for (name, res_type), entries in resources.items()
                ],
                "counts": {
                    **{
                        state: sum(1 for c in constraints if c["state"] == state)
                        for state in ("unsatisfied", "single", "open", "unverifiable", "exclusion")
                    },
                    # Values a request can choose that land nowhere, which is
                    # the other reason a template is drawn.
                    "dead_options": sum(_dead_options(c) for c in constraints),
                },
            }
        )
    placements.sort(key=lambda p: p["blueprint_name"].casefold())

    # Each clause stands on its own: any of them can be the only one, and a
    # count that leans on the clause above it reads as nonsense when that
    # clause is absent.
    unscoped = sum(1 for e in resolved if e["scope_unknown"])
    parts = []
    if undrawn["wide"]:
        parts.append(f"{undrawn['wide']} resolve every constraint to two or more places")
    if undrawn["dynamic"]:
        parts.append(
            f"{undrawn['dynamic']} build every constraint from a request-time input, so "
            "where they land cannot be worked out here"
        )
    if undrawn["mixed"]:
        parts.append(
            f"{undrawn['mixed']} carry no constraint that narrows to a single place or fails"
        )
    if unconstrained:
        parts.append(
            f"{unconstrained} declare no constraint tags at all, so nothing narrows where they land"
        )
    note = "Templates not drawn: " + "; ".join(parts) + "." if parts else ""
    if placements and unscoped:
        note = (note + " " if note else "") + (
            f"{unscoped} template(s) are shown estate-wide: they are shared through the "
            "catalog, and who they are shared with could not be read in this run "
            "(see Collection Gaps)."
        )
    if placements and not scope.usable:
        note = (note + " " if note else "") + (
            "Where each template can be built is not narrowed by project here: no project "
            "carries a cloud zone assignment in this run, so every place carrying the tag "
            "is shown."
        )
    return placements, note


def _undrawn_reason(states: set[str]) -> str:
    """Which bucket an undrawn template's constraints fall in.

    Exclusions sit with the wide ones: a negated constraint rules places out
    rather than in, so it is not a narrowing anybody needs to see either.
    """
    if states <= {"open", "exclusion"}:
        return "wide"
    if states == {"unverifiable"}:
        return "dynamic"
    return "mixed"


# The tag table's "Consumed by" column is the tag usage matrix, and this
# helper feeds the column.
MAX_CONSUMERS_SHOWN = 8


def tag_consumer_labels(data: AssessmentData) -> dict[str, str]:
    """Per-tag "consumed by" label for the report's tag table.

    Blueprints with a static constraint on the tag are listed by name. With
    no static consumer, a dynamic constraint whose static prefix could select
    the tag names the template as "possibly ... (dynamic constraint)" rather
    than claiming "nothing"; a tag with no visible consumer at all says so -
    the API cannot see tags consumed by scripts or external tooling.
    """
    consumed_by: dict[str, set[str]] = {}
    dynamic_consumers: dict[str, set[str]] = {}
    for bp, ct in all_constraints(data):
        if ct["dynamic"]:
            dynamic_consumers.setdefault(ct["tag"].split("${", 1)[0], set()).add(bp["name"])
        else:
            consumed_by.setdefault(ct["tag"], set()).add(bp["name"])

    def capped(names: list[str], cap: int) -> str:
        more = len(names) - cap
        return ", ".join(names[:cap]) + (f" (+{more} more)" if more > 0 else "")

    labels: dict[str, str] = {}
    for tag in capability_tags(data):
        consumers = sorted(consumed_by.get(tag, set()))
        if consumers:
            labels[tag] = capped(consumers, MAX_CONSUMERS_SHOWN)
            continue
        maybe = sorted(
            {
                name
                for prefix, names in dynamic_consumers.items()
                if tag.startswith(prefix)
                for name in names
            }
        )
        if maybe:
            labels[tag] = f"possibly {capped(maybe, 4)} (dynamic constraint)"
        else:
            labels[tag] = "no visible constraint"
    return labels
