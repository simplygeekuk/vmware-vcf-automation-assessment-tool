"""End-to-end flow builder: catalog item -> blueprint -> lifecycle event topics
-> matching subscriptions -> runnable. Feeds the mermaid diagrams."""

from __future__ import annotations

import logging

from .models import AssessmentData

log = logging.getLogger(__name__)

# Canonical provisioning lifecycle order; topics outside this list sort after,
# alphabetically.
TOPIC_ORDER = [
    "deployment.request.pre",
    "deployment.action.request.pre",
    "compute.allocation.pre",
    "network.allocation.pre",
    "storage.allocation.pre",
    "compute.provision.pre",
    "compute.provision.post",
    "network.configure",
    "compute.post.provision",
    "deployment.resource.action.request.pre",
    "deployment.resource.action.pre",
    "deployment.action.pre",
    "deployment.request.post",
    "deployment.action.request.post",
    "compute.removal.pre",
    "compute.removal.post",
    "deployment.resource.action.request.post",
    "deployment.resource.action.post",
    "deployment.action.post",
]


def topic_sort_key(topic: str):
    try:
        return (0, TOPIC_ORDER.index(topic))
    except ValueError:
        return (1, topic)


# Which part of a deployment's life a topic serves, in the order the report
# draws them. One diagram per concern, so a reader asking what happens when
# an item is built is not handed the teardown in the same picture.
CONCERNS = ("provisioning", "day2", "disposal", "request", "other")

CONCERN_TITLES = {
    "provisioning": "Provisioning",
    "day2": "Day 2 Changes",
    "disposal": "Disposal",
    "request": "Request",
    "other": "Other Events",
}

# Topics whose concern is the KIND of request rather than the topic name: one
# of these fires for a new deployment, a change to one and a destroy alike,
# which is why the live estate's own delete hook has to test eventType to tell
# them apart. The ".action." variants are NOT here - those are day-2 topics
# that some builds spell with a ".request." segment.
REQUEST_TOPIC_PREFIXES = ("deployment.request.", "deployment.approval")

# Matched as whole dot-separated segments, so "compute.post.provision" reads
# as provisioning without "provision" also matching inside a longer word.
DISPOSAL_SEGMENTS = ("removal", "purge", "destroy", "delete")
DAY2_SEGMENTS = ("action",)
PROVISIONING_SEGMENTS = ("allocation", "provision", "configure")


def topic_concern(topic: str) -> str:
    """Which concern a topic belongs to, before its criteria is read.

    Anything this tool cannot place lands in "other" rather than being pushed
    into the nearest plausible stage: a build with topics we have never seen
    should say so, not file them under Provisioning and be believed.
    """
    if topic.startswith(REQUEST_TOPIC_PREFIXES):
        return "request"
    segments = set(topic.split("."))
    if segments & set(DISPOSAL_SEGMENTS):
        return "disposal"
    if segments & set(DAY2_SEGMENTS):
        return "day2"
    if segments & set(PROVISIONING_SEGMENTS):
        return "provisioning"
    return "other"


# The verb inside an eventType literal, not a list of values the API is
# expected to use. This build spells a destroy DESTROY_DEPLOYMENT; a build
# that spells it otherwise falls back to the Request section instead of being
# placed wrongly.
EVENT_TYPE_VERBS = (
    ("CREATE", "provisioning"),
    ("PROVISION", "provisioning"),
    ("DESTROY", "disposal"),
    ("DELETE", "disposal"),
    ("UPDATE", "day2"),
    ("CHANGE", "day2"),
)


def _verb_concern(value: str) -> str | None:
    """The concern one eventType literal names, or None when it names none of
    them or more than one."""
    upper = value.upper()
    matched = {concern for verb, concern in EVENT_TYPE_VERBS if verb in upper}
    return matched.pop() if len(matched) == 1 else None


def _request_concern(sub: dict) -> str:
    """Which part of the life a subscription on a request topic belongs to.

    A request event fires for a new deployment, a change to one and a teardown
    alike, so the topic on its own cannot say. Where the criteria requires an
    eventType, that answers it.

    Where it requires none, the subscription goes with the build. Raising the
    request is what starts a deployment, and on a real estate almost nothing
    names the kind - the aib estate's only eventType test is a built-in - so a
    Request section of its own repeated the whole catalog beside a
    Provisioning section missing the events that open it. The section says
    plainly that these events also fire for changes and teardowns.

    Where the criteria rules the build OUT without saying what it rules in,
    nothing is claimed: the subscription keeps a section of its own rather
    than being filed under a part of the life its own conditions exclude.
    """
    concerns = {_verb_concern(value) for value in sub.get("criteria_event_types_eq") or []}
    if concerns:
        return concerns.pop() if len(concerns) == 1 and None not in concerns else "request"
    excluded = {_verb_concern(value) for value in sub.get("criteria_event_types_ne") or []}
    return "request" if "provisioning" in excluded else "provisioning"


def flow_topics(flow: dict) -> list[dict]:
    """Every topic entry of one flow, with the concern split flattened away.

    For consumers that count what is attached to an item rather than where in
    its life it happens. A topic whose subscriptions split across concerns
    yields one entry per concern, and no subscription appears twice.
    """
    return [entry for concern in flow.get("concerns", []) for entry in concern["topics"]]


# Resource-lifecycle topics fire only while Cloud.* resources are provisioned.
RESOURCE_TOPIC_PREFIXES = ("compute.", "network.", "storage.")

# Design-time topics fire when a template is edited/versioned/released in the
# authoring UI - never as part of requesting a catalog item, so they belong in
# the subscriptions inventory but not in per-item flows.
DESIGN_TOPIC_PREFIXES = ("blueprint.",)


def _topic_applies(topic: str, item_type: str, resource_types: list[str] | None):
    """Whether an event topic can fire when this catalog item is requested.

    deployment.* (and custom) topics fire for any catalog request. compute./
    network./storage. lifecycle topics fire only when the item's template
    provisions matching Cloud.* resources - never for vRO-workflow or ABX
    catalog items. blueprint.* topics are design-time (template authoring)
    events and never fire for a request, whatever the item. Returns True
    (applies), False (cannot apply) or None (unknown - item's template could
    not be resolved).
    """
    if topic.startswith(DESIGN_TOPIC_PREFIXES):
        return False
    if not topic.startswith(RESOURCE_TOPIC_PREFIXES):
        return True
    if item_type and "blueprint" not in item_type:
        return False
    if resource_types is None:
        return None
    from .checks.deployments import is_machine

    types = set(resource_types)
    has_machine = any(is_machine(t) for t in types)
    if topic.startswith("compute."):
        return has_machine
    if topic.startswith("network."):
        # Machines imply NICs, which drive network allocation/configuration.
        return has_machine or any(
            "Network" in t or "LoadBalancer" in t or "SecurityGroup" in t for t in types
        )
    return has_machine or any("Disk" in t or "Volume" in t for t in types)


def _criteria_values(sub: dict, field: str) -> tuple[set[str], set[str]]:
    """(equals, not-equals) literals for one criteria field.

    Tolerates subscriptions collected before negation was parsed - a --json
    dump replayed through the report, say. Those carry only `criteria_*_ids`,
    and reading the absent equals key as "no constraint" would silently turn a
    narrowly targeted subscription into one that matches every catalog item.
    """
    eq = sub.get(f"criteria_{field}_eq")
    if eq is None:
        eq = sub.get(f"criteria_{field}_ids") or []
    return set(eq), set(sub.get(f"criteria_{field}_ne") or [])


def _decide(candidates: set[str] | None, eq: set[str], ne: set[str]) -> tuple[bool, bool]:
    """(include, confirmed) for one criteria field.

    `candidates` is every value the event's field could carry for this catalog
    item; None means that could not be established. An undecidable criteria is
    always included but never confirmed - the report must not hide a
    subscription it cannot rule out.
    """
    if candidates is None:
        return True, False
    if eq and candidates & eq:
        # Any overlap counts: an item shared to several projects, or built from
        # several blueprint versions, fires for the ones the criteria names.
        return True, not (ne and candidates & ne)
    if eq:
        return False, True
    if ne:
        if candidates <= ne:
            return False, True
        return True, not (candidates & ne)
    return True, True


def _or_may_add(sub: dict, field: str) -> bool:
    """Whether a top-level disjunction can make this subscription fire for a
    reason the verdict on `field` did not account for.

    A disjunct the parser could not read can always fire on its own, so it
    stops any clause ruling the subscription out. A disjunct it did read on
    the same field cannot: `_decide` already treats the equals list as a set,
    which is what an `||` chain of `blueprintId ==` comparisons means. The
    live estate has both shapes, and treating them alike drew
    "Delete Windows Server - WIS" on every catalog item in the report,
    including the RHEL ones its own criteria excludes.

    The other field still blocks the exclusion, because only one of the two is
    evaluated for any given subscription: `blueprintId == A || projectId == B`
    fires on the project half this verdict never looked at.
    """
    if not sub.get("criteria_top_level_or"):
        return False
    if not sub.get("criteria_fully_read", True):
        return True
    other = "project" if field == "blueprint" else "blueprint"
    eq, ne = _criteria_values(sub, other)
    return bool(eq or ne)


def item_blueprints(data: AssessmentData) -> dict[str, dict]:
    """Catalog item id -> the template it deploys, where one can be resolved.

    Learned from deployments carrying both ids first, because item id equals
    blueprint id on some builds and not others; then an item whose own id is a
    blueprint id; then a name match, which needs a name on both sides so that
    two documents which each left it out are not read as the same template.

    Shared with the placement checks, so the diagrams and the flows cannot
    disagree about which template a catalog item requests.
    """
    blueprints = {
        b["id"]: b for b in data.raw.get("blueprints", {}).get("blueprints", []) if b.get("id")
    }
    learned: dict[str, str] = {}
    for dep in data.raw.get("deployments", {}).get("deployments", []):
        if dep.get("catalogItemId") and dep.get("blueprintId"):
            learned.setdefault(dep["catalogItemId"], dep["blueprintId"])

    out: dict[str, dict] = {}
    for item in data.raw.get("catalog", {}).get("items", []):
        name = item.get("name") or ""
        bp = (
            blueprints.get(learned.get(item["id"], ""))
            or blueprints.get(item["id"])
            or (
                next((b for b in blueprints.values() if b.get("name") == name), None)
                if name
                else None
            )
        )
        if bp:
            out[item["id"]] = bp
    return out


def build_flows(data: AssessmentData) -> None:
    """Populate data.derived['flows'] with one entry per catalog item.

    Each entry carries its matched subscriptions under `concerns`, grouped by
    the part of the deployment's life they serve and then by topic. Use
    flow_topics() for the flat list.
    """
    items = data.raw.get("catalog", {}).get("items", [])
    include_builtin = data.meta.get("include_system_subscriptions", False)
    subscriptions = [
        s
        for s in data.raw.get("extensibility", {}).get("subscriptions", [])
        if include_builtin or not s.get("builtin")
    ]
    project_names = data.derived.get("project_names", {})

    # Every blueprint id an item has ever deployed, which is a different
    # question from which template it requests today: an item whose template
    # was replaced carries both, and a subscription pinned to either could
    # fire for it.
    item_bp_ids: dict[str, set[str]] = {}
    for dep in data.raw.get("deployments", {}).get("deployments", []):
        if dep.get("catalogItemId") and dep.get("blueprintId"):
            item_bp_ids.setdefault(dep["catalogItemId"], set()).add(dep["blueprintId"])

    # Catalog items with no template of their own (vRO workflow, ABX action,
    # pipeline) still produce deployments, and the platform stamps a sentinel
    # in blueprintId for them - "inline-blueprint" on this estate. Criteria in
    # the wild filter on it, so learn the value from the estate's own
    # deployments rather than hardcoding it: a build that stamps something else
    # stays correct, and a build that stamps nothing learns nothing and the
    # matcher falls back to "unknown" instead of guessing.
    item_types = {i["id"]: i.get("type") or "" for i in items}
    sentinel_bp_ids = {
        bp_id
        for item_id, ids in item_bp_ids.items()
        if item_id in item_types and "blueprint" not in item_types[item_id]
        for bp_id in ids
    }

    joined = item_blueprints(data)
    flows = []
    for item in items:
        item_name = item.get("name") or ""
        bp = joined.get(item["id"])

        # Every blueprintId this item's events could carry, or None when that
        # cannot be established. Observed deployments are the strongest
        # evidence; a resolved template is next; an item with no template by
        # nature and no deployments of its own falls back to the sentinel the
        # rest of the estate shows for its kind.
        item_type = item.get("type") or ""
        if item_bp_ids.get(item["id"]):
            bp_candidates = set(item_bp_ids[item["id"]])
        elif bp is not None:
            bp_candidates = {bp["id"]}
        elif "blueprint" not in item_type and sentinel_bp_ids:
            bp_candidates = set(sentinel_bp_ids)
        else:
            bp_candidates = None

        matched = []
        for sub in subscriptions:
            # Topic gate first: a resource-lifecycle topic (compute./network./
            # storage.) can never fire for a non-blueprint item, whatever the
            # criteria says.
            applies = _topic_applies(
                sub.get("eventTopicId") or "",
                item_type,
                bp.get("resource_types") if bp else None,
            )
            if applies is False:
                continue

            # Matching is conservative: when the subscription cannot be ruled
            # out it is shown, but with match="unverified" so the diagram can
            # present it as conditional rather than certain. Only provable
            # matches (and criteria-less globals) are match="confirmed".
            if sub["scope"] == "blueprint":
                eq, ne = _criteria_values(sub, "blueprint")
                cands = bp_candidates
                # Some builds put the catalog item id where a blueprint id
                # belongs; honor that on the equals side only, so it can never
                # turn a negated criteria into a spurious match.
                if cands is not None and item["id"] in eq:
                    cands = cands | {item["id"]}
                include, confirmed = _decide(cands, eq, ne)
            elif sub["scope"] == "project":
                proj_eq, proj_ne = _criteria_values(sub, "project")
                include, confirmed = _decide(
                    set(item.get("projectIds") or []) or None, proj_eq, proj_ne
                )
            elif sub["scope"] == "conditional":
                include, confirmed = True, False
            else:
                include, confirmed = True, True

            # A verdict from the blueprint/project clauses alone is only worth
            # as much as the rest of the expression allows. Clauses this tool
            # cannot read (eventType, status, custom properties) can stop a
            # subscription firing, so they never let it be ruled IN; and under
            # a top-level disjunction they can also make it fire anyway, so
            # they stop it being ruled OUT either - see _or_may_add for which
            # disjunctions that covers.
            if not include and _or_may_add(sub, sub["scope"]):
                include, confirmed = True, False
            elif confirmed and not sub.get("criteria_fully_read", True):
                confirmed = False
            if include:
                # An unresolved template makes the topic gate itself uncertain,
                # which downgrades an otherwise provable criteria match.
                match = "confirmed" if confirmed and applies is not None else "unverified"
                matched.append({**sub, "match": match})

        # Grouped by concern first, then by topic within it. A request topic
        # can land in two concerns at once, because the kind of request comes
        # from each subscription's own criteria and not from the topic.
        by_concern: dict[str, dict[str, list[dict]]] = {}
        for sub in matched:
            topic = sub["eventTopicId"] or "unknown"
            concern = topic_concern(topic)
            if concern == "request":
                concern = _request_concern(sub)
            by_concern.setdefault(concern, {}).setdefault(topic, []).append(sub)

        flows.append(
            {
                "item_id": item["id"],
                "item_name": item_name,
                "item_type": item_type,
                "source_name": item.get("sourceName", ""),
                "blueprint_id": bp["id"] if bp else None,
                "blueprint_name": bp.get("name") if bp else None,
                "projects": [project_names.get(p, p) for p in item.get("projectIds") or []],
                "deployment_count": item.get("deployment_count", 0),
                "concerns": [
                    {
                        "key": key,
                        "title": CONCERN_TITLES[key],
                        "topics": [
                            {"topic": t, "subscriptions": subs}
                            for t, subs in sorted(
                                by_concern[key].items(), key=lambda kv: topic_sort_key(kv[0])
                            )
                        ],
                    }
                    for key in CONCERNS
                    if key in by_concern
                ],
            }
        )

    data.derived["flows"] = flows
    log.info(
        "flows: built %d catalog item flows against %d subscriptions",
        len(flows),
        len(subscriptions),
    )
