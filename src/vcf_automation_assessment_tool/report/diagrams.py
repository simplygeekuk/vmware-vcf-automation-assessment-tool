"""Mermaid diagram source generation for catalog item end-to-end flows."""

from __future__ import annotations

import hashlib
import re
import textwrap

_ID_RE = re.compile(r"[^A-Za-z0-9_]")


def _node_id(prefix: str, value: str) -> str:
    """Sanitized, truncated, and hash-suffixed mermaid node id.

    The hash suffix keeps ids unique even when the readable part collides -
    without it, per-item topic ids like '<36-char-uuid>_compute.provision.pre'
    and '..._compute.provision.post' truncated to the same id, and mermaid
    silently merged the nodes, attaching subscriptions to the wrong topic.
    """
    digest = hashlib.md5(value.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}_{_ID_RE.sub('_', value)[:32]}_{digest}"


def _label(text: str) -> str:
    """Escape a mermaid node label (rendered inside double quotes).

    CR is stripped alongside LF: HTML parsing normalizes a bare CR in the
    <pre> to a newline, which would land a real line break inside the quoted
    label despite the newline replacement.
    """
    text = re.sub(r"[\r\n]+", " ", text or "?").replace('"', "'")
    if len(text) <= 60:
        return text
    # _safe_text writes a brace as #123; before the text gets here, so a cut
    # at 60 can land inside an entity and leave "#12" on the page as text.
    return re.sub(r"&?#\d*$", "", text[:60])


def flow_diagram(flow: dict, concern: dict) -> str:
    """One flowchart LR for ONE concern of a catalog item: item -> source ->
    blueprint -> that concern's topics -> subscriptions -> runnables.

    The item, source and blueprint spine is repeated on each of an item's
    diagrams. It is what the events hang off, and a picture of the teardown
    that does not say what is being torn down is no use on its own.
    """
    lines = ["flowchart LR"]
    classes = {
        "item": [],
        "source": [],
        "bp": [],
        "topic": [],
        "sub": [],
        "disabled": [],
        "none": [],
        "run": [],
    }

    item_node = _node_id("ci", flow["item_id"])
    lines.append(f'{item_node}["{_label(flow["item_name"])}"]')
    classes["item"].append(item_node)
    prev = item_node

    if flow.get("source_name"):
        src_node = _node_id("src", flow["source_name"])
        lines.append(f'{src_node}["{_label(flow["source_name"])}"]')
        lines.append(f"{prev} --> {src_node}")
        classes["source"].append(src_node)
        prev = src_node

    if flow.get("blueprint_name"):
        bp_node = _node_id("bp", flow["blueprint_id"] or flow["blueprint_name"])
        lines.append(f'{bp_node}["{_label(flow["blueprint_name"])}"]')
        lines.append(f"{prev} --> {bp_node}")
        classes["bp"].append(bp_node)
        prev = bp_node

    anchor = prev
    topics = concern["topics"]
    for entry in topics:
        topic = entry["topic"]
        topic_node = _node_id("t", f"{flow['item_id']}_{topic}")
        lines.append(f'{topic_node}(["{_label(topic)}"])')
        lines.append(f"{anchor} --> {topic_node}")
        classes["topic"].append(topic_node)
        for sub in entry["subscriptions"]:
            sub_node = _node_id("s", f"{flow['item_id']}_{sub['id']}")
            flags = []
            # Read like every other field here: a subscription replayed from an
            # older --json dump may not carry the flags, and a missing one must
            # read as "not set" rather than ending the whole diagram.
            blocking, disabled = sub.get("blocking"), sub.get("disabled")
            if blocking:
                flags.append("blocking")
            if disabled:
                flags.append("disabled")
            conditional = sub.get("match") == "unverified"
            if conditional:
                flags.append("conditional")
            marker = f" ({', '.join(flags)})" if flags else ""
            # Marker outside _label: truncation must never swallow it - in a
            # diagram the text marker is the only signal blocking has (red
            # is reserved for disabled).
            lines.append(f'{sub_node}["{_label(sub["name"])}{marker}"]')
            # Dashed edge: fires only if its criteria matches at runtime -
            # could not be conclusively tied to this item.
            arrow = "-.->" if conditional else "-->"
            lines.append(f"{topic_node} {arrow} {sub_node}")
            # Red is reserved for disabled subscriptions; blocking ones render
            # as normal nodes with the "(blocking)" text marker only.
            if disabled:
                classes["disabled"].append(sub_node)
            else:
                classes["sub"].append(sub_node)
            runnable = sub.get("runnableName") or sub.get("runnableId")
            if runnable:
                run_node = _node_id("r", f"{sub['id']}_{runnable}")
                kind = "ABX" if "abx" in (sub.get("runnableType") or "") else "Orchestrator"
                lines.append(f'{run_node}[/"{kind}: {_label(runnable)}"/]')
                lines.append(f"{sub_node} --> {run_node}")
                classes["run"].append(run_node)

    if not topics:
        # Only reachable if a caller hands over an empty concern; the builder
        # never emits one, and an item nothing reacts to is tabled, not drawn.
        none_node = _node_id("n", flow["item_id"])
        lines.append(f'{none_node}["no matching subscriptions"]')
        lines.append(f"{anchor} -.-> {none_node}")
        classes["none"].append(none_node)

    lines += _class_defs(classes)
    return "\n".join(lines)


# Approval gate nodes hold several label lines; cap the action list so the
# node stays readable (the full list lives in the Approval Policies table).
# The node is the ONLY place the actions are printed - the header above the
# diagram used to repeat all of them - so the cap sits above the live
# estate's longest chain rather than at a tidy six.
MAX_GATE_ACTIONS = 8


def _mlabel(label_lines: list[str]) -> str:
    """Multi-line mermaid node label: each line escaped, joined with <br/>."""
    return "<br/>".join(_label(line) for line in label_lines)


def approval_gates_diagram(chain: dict) -> str:
    """One gate chain: a request for the listed actions passes each approval
    policy in level order before it proceeds; every gate can also reject
    (dotted edges to the rejected outcome)."""
    lines = ["flowchart LR"]
    classes = {"topic": [], "gate": [], "ok": [], "rej": []}

    actions = chain["actions"]
    shown = actions[:MAX_GATE_ACTIONS]
    more = len(actions) - len(shown)
    req_lines = ["request:"] + shown + ([f"+{more} more action(s), see table"] if more else [])
    req = _node_id("areq", chain["context"] + "|" + ",".join(actions))
    lines.append(f'{req}(["{_mlabel(req_lines)}"])')
    classes["topic"].append(req)

    prev = req
    for pos, slot in enumerate(chain["gates"]):
        policy = slot.get("policy")
        # "level N:" and never "N." - mermaid reads a leading "N. " as a
        # markdown ordered list and renders "Unsupported markdown: list".
        level = slot["level"] if slot.get("level") is not None else "?"
        if policy:
            node = _node_id("gate", policy.get("id") or policy.get("name", ""))
            glines = [f"level {level}: {policy.get('name') or '?'}"]
        else:
            node = _node_id("gate", f"{chain['context']}|{pos}")
            glines = [f"level {level}: {slot['count']} per-project policies"]
        glines.append(f"{slot.get('enforcementType') or '?'}, {slot.get('approvalMode') or '?'}")
        # Approver identities stay OUT of the label: mermaid's markdown pass
        # autolinks email-shaped text and renders "Unsupported markdown:
        # link" instead (live estate approvers are "USER:12345@example.com").
        # The count is structure; the identities live in the table above.
        if policy:
            approvers = policy.get("approvers") or []
            if approvers:
                glines.append(f"{len(approvers)} approver(s), see table")
        else:
            glines.append("approvers vary per policy, see table")
        decision = slot.get("autoApprovalDecision") or ""
        if decision:
            expiry = slot.get("autoApprovalExpiry")
            glines.append(f"auto-expiry{f' after {expiry}d' if expiry else ''}: {decision}")
        if slot.get("scope_criteria"):
            glines.append("(scope criteria apply)")
        lines.append(f'{node}["{_mlabel(glines)}"]')
        classes["gate"].append(node)
        lines.append(f"{prev} --> {node}")
        prev = node

    ok = _node_id("aok", chain["context"])
    lines.append(f'{ok}(["approved: request proceeds"])')
    classes["ok"].append(ok)
    lines.append(f"{prev} --> {ok}")
    rej = _node_id("arej", chain["context"])
    lines.append(f'{rej}(["rejected: request denied"])')
    classes["rej"].append(rej)
    for node in classes["gate"]:
        lines.append(f"{node} -.-> {rej}")

    lines += _class_defs(classes)
    return "\n".join(lines)


def _class_defs(classes: dict[str, list[str]]) -> list[str]:
    defs = {
        "item": "fill:#2a78d6,color:#ffffff,stroke:#1c5cab",
        "proj": "fill:#e7f4ef,color:#0b0b0b,stroke:#0e8a5e",
        "agg": "fill:#0e8a5e,color:#ffffff,stroke:#0a6b49",
        "source": "fill:#e8eef7,color:#0b0b0b,stroke:#c3c2b7",
        "bp": "fill:#1baf7a,color:#ffffff,stroke:#0e8a5e",
        "topic": "fill:#f0efec,color:#0b0b0b,stroke:#898781",
        "sub": "fill:#ffffff,color:#0b0b0b,stroke:#52514e",
        "disabled": "fill:#fbe9e9,color:#7a1f1f,stroke:#d03b3b,stroke-width:2px",
        "none": "fill:#f0efec,color:#898781,stroke:#c3c2b7,stroke-dasharray:4 3",
        "run": "fill:#4a3aa7,color:#ffffff,stroke:#372b80",
        "gate": "fill:#ffffff,color:#0b0b0b,stroke:#52514e",
        "ok": "fill:#0e8a5e,color:#ffffff,stroke:#0a6b49",
        "rej": "fill:#fbe9e9,color:#7a1f1f,stroke:#d03b3b",
        "res": "fill:#e8eef7,color:#0b0b0b,stroke:#7f93b3",
        "cons": "fill:#ffffff,color:#0b0b0b,stroke:#52514e",
        # The report's own warning yellow and critical red, so a placement
        # diagram reads the same way as the severity tiles above it.
        "warn": "fill:#fdf3d7,color:#5a4a00,stroke:#c9a227,stroke-width:2px",
        "fail": "fill:#fbe9e9,color:#7a1f1f,stroke:#d03b3b,stroke-width:2px",
        "tgt": "fill:#e7f4ef,color:#0b0b0b,stroke:#0e8a5e",
        # Deliberately not the green of a place: a project constraint is one
        # more thing to satisfy, not somewhere a resource can be built.
        "req": "fill:#f4f1ea,color:#4a4a45,stroke:#a8a496",
    }
    out = []
    for name, style in defs.items():
        nodes = classes.get(name) or []
        if nodes:
            out.append(f"classDef {name} {style}")
            out.append(f"class {','.join(nodes)} {name}")
    return out


# What each state puts on the constraint node. Red is the report's own
# "broken today" colour and is used only where placement genuinely fails;
# a soft constraint that matches nothing is ignored at request time rather
# than fatal, so it renders muted like any other dead end.
# Characters per line in a dead-end node before it wraps.
DEAD_END_WIDTH = 44
# Places drawn under one constraint before the rest become a count. A tag
# every place in the estate carries is not worth a hundred nodes, and the
# point of the diagram is the constraint that narrows to one place next to it.
MAX_PLACES = 12
# Project names listed on the requirement node before the rest become a count.
MAX_REQUIREMENT_NAMES = 3
# Tags drawn under one request-time constraint before the rest become a count.
MAX_OPTIONS = 6
# Inputs named on a request-time constraint before the rest become a count.
MAX_REFERENCES = 3

_CONSTRAINT_CLASS = {
    "single": "warn",
    "open": "cons",
    "unverifiable": "none",
    "exclusion": "cons",
}


def placement_diagram(placement: dict) -> str:
    """One flowchart LR: template -> each resource it declares -> each
    constraint tag on that resource -> the places whose capability tags
    satisfy it, with anything unsatisfied ending in a dead end.

    Target nodes are shared across the constraints of one diagram on purpose:
    three constraints converging on a single zone is the shape worth seeing,
    and separate nodes would hide it.
    """
    lines = ["flowchart LR"]
    classes: dict[str, list[str]] = {
        "bp": [],
        "res": [],
        "cons": [],
        "warn": [],
        "fail": [],
        "none": [],
        "tgt": [],
        "req": [],
    }
    scope = placement.get("blueprint_id") or placement["blueprint_name"]

    bp_node = _node_id("pbp", scope)
    lines.append(f'{bp_node}["{_label(placement["blueprint_name"])}"]')
    classes["bp"].append(bp_node)

    for res in placement["resources"]:
        res_node = _node_id("pres", f"{scope}_{res['name']}")
        res_lines = [res["name"]] + ([res["type"]] if res.get("type") else [])
        lines.append(f'{res_node}["{_mlabel(res_lines)}"]')
        lines.append(f"{bp_node} --> {res_node}")
        classes["res"].append(res_node)
        constraint_nodes: dict[tuple[str, str], list[str]] = {}

        for position, constraint in enumerate(res["constraints"]):
            node = _node_id("pc", f"{scope}_{res['name']}_{position}_{constraint['tag']}")
            lines.append(f'{node}{{"{_mlabel(_constraint_lines(constraint))}"}}')
            lines.append(f"{res_node} --> {node}")
            constraint_nodes.setdefault(
                (constraint.get("kind") or "compute", constraint["tag"]), []
            ).append(node)
            state = constraint["state"]
            if state == "unsatisfied":
                classes["fail" if constraint["hard"] else "none"].append(node)
            else:
                classes[_CONSTRAINT_CLASS[state]].append(node)
            # A request-time expression that chooses between tags written out
            # in the template resolves each of them instead of stopping at a
            # dead end: which one a request takes is unknowable, where each
            # one would land is not.
            if state == "unverifiable" and constraint["options"]:
                _options(lines, classes, node, scope, res["name"], position, constraint)
            else:
                _resolved(lines, classes, node, scope, res["name"], position, constraint)

        _together(lines, classes, scope, res, constraint_nodes)

    lines += _class_defs(classes)
    return "\n".join(lines)


def _together(
    lines: list[str],
    classes: dict[str, list[str]],
    scope: str,
    res: dict,
    constraint_nodes: dict[tuple[str, str], list[str]],
) -> None:
    """What satisfies every hard constraint on this resource at once.

    A resource is built in one place, so the constraints on it have to agree
    on one. Drawn only where that says something the constraints do not say
    on their own: nothing satisfies them together, or one place does while at
    least one of them looks wider than that on its own. Two constraints that
    each resolve to the same two places need no third shape to say so.
    """
    for position, group in enumerate(res.get("intersections") or []):
        places, conflict, tags = group["places"], group["conflict"], group["tags"]
        # By kind as well as tag: one tag can sit on a machine's own
        # constraint and on its disk, and those are two different questions.
        contributors = [
            c
            for c in res["constraints"]
            if c["tag"] in set(tags) and (c.get("kind") or "compute") == group["kind"]
        ]
        wider = any(len(c["targets"]) > 1 for c in contributors)
        if not conflict and not (len(places) == 1 and wider):
            continue
        node = _node_id("pall", f"{scope}_{res['name']}_{position}_{group['kind']}")
        if conflict:
            label = [f"no {group['kind']} place carries all {len(tags)} tags"]
            classes["fail"].append(node)
        else:
            label = [f"one {group['kind']} place carries all {len(tags)} tags"]
            label += [_safe_text(place) for place in places]
            classes["warn"].append(node)
        lines.append(f'{node}["{_mlabel(label)}"]')
        for tag in tags:
            for constraint_node in constraint_nodes.get((group["kind"], tag)) or []:
                lines.append(f"{constraint_node} -.->|together| {node}")


def _resolved(
    lines: list[str],
    classes: dict[str, list[str]],
    node: str,
    scope: str,
    resource: str,
    key: object,
    c: dict,
) -> None:
    """What a constraint reaches: the places that satisfy it, or a dead end.

    Shared with the values of a request-time constraint, so a tag chosen at
    request time is drawn exactly like the same tag written directly.
    """
    if c["state"] in ("unsatisfied", "unverifiable"):
        _dead_end(lines, classes, node, scope, key, c)
        return
    arrow = "-.->|excludes|" if c["state"] == "exclusion" else "-->"
    shown = c["targets"][:MAX_PLACES]
    for place in shown:
        place_node = _node_id("ptgt", f"{scope}_{place['kind']}_{place['name']}")
        if place_node not in classes["tgt"]:
            lines.append(f'{place_node}["{_mlabel(_place_lines(place))}"]')
            classes["tgt"].append(place_node)
        lines.append(f"{node} {arrow} {place_node}")
    rest = len(c["targets"]) - len(shown)
    if rest:
        more = _node_id("pmore", f"{scope}_{resource}_{key}_{c['tag']}")
        lines.append(f'{more}["+{rest} more place(s)"]')
        lines.append(f"{node} {arrow} {more}")
        classes["tgt"].append(more)
    _requirements(lines, classes, node, scope, resource, key, c)


def _options(
    lines: list[str],
    classes: dict[str, list[str]],
    node: str,
    scope: str,
    resource: str,
    position: int,
    c: dict,
) -> None:
    """One node per tag a request-time constraint can decide on.

    Dotted arrows: exactly one of them applies to any given request, and
    which one is the answer the requester gives.
    """
    shown = c["options"][:MAX_OPTIONS]
    for i, option in enumerate(shown):
        key = f"{position}.{i}"
        opt = _node_id("popt", f"{scope}_{resource}_{key}_{option['tag']}")
        lines.append(f'{opt}["{_mlabel(_option_lines(option))}"]')
        lines.append(f"{node} -.-> {opt}")
        classes[_option_class(option)].append(opt)
        _resolved(lines, classes, opt, scope, resource, key, option)
    rest = len(c["options"]) - len(shown)
    if rest:
        more = _node_id("pomore", f"{scope}_{resource}_{position}_{c['tag']}")
        lines.append(f'{more}["+{rest} more tag(s)"]')
        lines.append(f"{node} -.-> {more}")
        classes["none"].append(more)


def _option_class(option: dict) -> str:
    """Never the red of a constraint nothing satisfies: that colour means
    every build of the resource fails and TAG-001 reports it as well, and
    neither is true of a tag only some requests ask for."""
    if option["state"] == "unsatisfied":
        return "warn" if option["hard"] else "none"
    return _CONSTRAINT_CLASS[option["state"]]


def _safe_text(text: str) -> str:
    """Characters that survive as text but not as mermaid syntax.

    A dynamic constraint tag is written env:${input.env}, and its braces sit
    inside a rhombus node whose own delimiters are braces. An "@" anywhere in
    a label is read as an email address by the markdown pass and rendered as
    "Unsupported markdown: link" - the same trap that keeps approver
    identities out of the approval gate labels.

    The entity is written WITHOUT its ampersand, which is mermaid's own form
    and not a typo. Its encodeEntities pass rewrites every "#nnn;" it finds
    back into "&#nnn;" before the label reaches the DOM, so "&#123;" arrived
    on the page as "&{" - the stray ampersand a live report showed against
    ${input.environment}.
    """
    return text.replace("{", "#123;").replace("}", "#125;").replace("@", "#64;")


def _constraint_lines(constraint: dict) -> list[str]:
    """Label for a constraint node: the tag, then what kind of constraint it
    is and how much room it leaves."""
    qualifiers = ["hard" if constraint["hard"] else "soft"]
    if constraint["negated"]:
        qualifiers.append("negated")
    if constraint["context"] != "resource":
        qualifiers.append(constraint["context"])
    label = _expression_lines(constraint) if constraint["dynamic"] else _tag_lines(constraint)
    label.append(", ".join(qualifiers))
    return label + _match_lines(constraint)


def _tag_lines(c: dict) -> list[str]:
    """The tag itself, wrapped rather than cut: _label's 60 characters landed
    in the middle of one on a live estate."""
    return [_safe_text(line) for line in textwrap.wrap(c["tag"], DEAD_END_WIDTH) or [c["tag"]]]


def _expression_lines(c: dict) -> list[str]:
    """A request-time constraint said in words rather than in its expression.

    A live template decides one constraint through a five-branch conditional,
    and the rhombus holding it told the reader nothing except that it was
    long. What decides the tag is the readable part; the tags it can decide
    on are drawn as their own nodes.
    """
    expression = c.get("expression") or {}
    kind = expression.get("kind") or "computed"
    references = expression.get("references") or []
    prefix = expression.get("prefix") or ""
    source = expression.get("source") or ""
    computed = kind == "computed"
    label = []
    # Not for a choice: its values already carry the prefix, spelled out.
    if prefix and kind != "choice":
        label.append(_safe_text(f'a "{prefix}..." tag'))
    label.append("built at request time" if computed else "decided at request time")
    if references:
        shown = references[:MAX_REFERENCES]
        rest = len(references) - len(shown)
        named = ", ".join(shown) + (f" +{rest} more" if rest else "")
        label.append(_safe_text(("from " if computed else "by ") + named))
    if source:
        # The platform fills the field from somewhere this tool will not go,
        # so the reader is told where to look rather than left guessing.
        label.append(_safe_text(f"values come from {source}"))
    return label


def _option_lines(option: dict) -> list[str]:
    """Label for one tag a request-time constraint can decide on. Hardness is
    the parent constraint's and is not repeated on every value."""
    return _tag_lines(option) + _match_lines(option)


def _match_lines(c: dict) -> list[str]:
    """What the match leaves, where that is worth saying on the node."""
    label = []
    # A tag no place carries at all is described by the dead end instead -
    # saying one place matches when none does would be worse than nothing.
    if c["state"] == "single" and c["targets"]:
        label.append("only one place matches")
    misses, total = c.get("misses") or [], c.get("projects_total") or 0
    if misses and total:
        # The same count TAG-004 reports, from the same resolution.
        label.append(f"out of reach for {len(misses)} of {total} project(s)")
    if c["note"]:
        label.append(c["note"])
    return label


def _place_lines(place: dict) -> list[str]:
    """Label for a place: what it is and what it is called, plus how the tag
    got there when that is not simply "it carries the tag"."""
    label = [_safe_text(f"{place['kind']}: {place['name']}")]
    if place["via"] and place["via"] != "capability tag":
        label.append(_safe_text(place["via"]))
    return label


def _requirements(
    lines: list[str],
    classes: dict[str, list[str]],
    node: str,
    scope: str,
    resource: str,
    key: object,
    c: dict,
) -> None:
    """Project-level constraints carrying the same tag, grouped by what they
    say about it.

    They are conditions a project puts on every request made in it, not places
    anything lands on, so they never take the place styling. One node each
    buried a constraint that only one cloud account satisfied under 57 project
    nodes on a live estate, all of them reading as somewhere it could build.
    Only the project lists that bear on this kind of resource reach here, so
    the node names which list it was.

    A project can rule a tag out as readily as ask for it, and a soft entry is
    a preference the platform drops when nothing matches. Those are three
    different claims and they get three different nodes: one node saying "also
    required by" over all of them tells the reader the opposite of what a
    negated entry does.
    """
    groups: dict[tuple[bool, bool], list[dict]] = {}
    for entry in c["requirements"]:
        groups.setdefault((bool(entry.get("negated")), bool(entry.get("hard", True))), []).append(
            entry
        )
    for index, ((negated, hard), entries) in enumerate(sorted(groups.items())):
        names = [r["name"] for r in entries]
        kinds = {(r.get("constraint_type") or "").strip() for r in entries}
        kind = kinds.pop() if len(kinds) == 1 else ""
        named = f"the {kind} constraint" if kind else "a project constraint"
        if negated:
            heading = f"ruled out by {named} on {len(names)} project(s)"
        elif hard:
            heading = f"also required by {named} on {len(names)} project(s)"
        else:
            heading = f"preferred by {named} on {len(names)} project(s)"
        shown = names[:MAX_REQUIREMENT_NAMES]
        # Its own line: the heading is already near the width a label is cut
        # at, and this one was landing mid-word.
        label = [heading]
        if not hard:
            label.append(
                "soft, so it is set aside where nothing else matches"
                if negated
                else "soft, so it is dropped where nothing matches"
            )
        label.append(", ".join(shown))
        if len(names) > len(shown):
            label.append(f"+{len(names) - len(shown)} more")
        req = _node_id("preq", f"{scope}_{resource}_{key}_{c['tag']}_{index}")
        lines.append(f'{req}["{_mlabel([_safe_text(line) for line in label])}"]')
        lines.append(f"{node} -.-> {req}")
        classes["req"].append(req)


def _dead_end(
    lines: list[str], classes: dict[str, list[str]], node: str, scope: str, key: object, c: dict
) -> None:
    """The terminal node saying why a constraint resolves to nowhere.

    Never shared between constraints: the reason belongs to this one, and two
    constraints failing for different reasons on one node would read as a
    single fault.
    """
    if c["state"] == "unverifiable":
        text = "where it lands depends on the answer"
    else:
        text = c["gap"] or "matches no capability tag"
    end = _node_id("pend", f"{scope}_{key}_{c['tag']}_{text}")
    # Wrapped rather than truncated: the storage-inheritance reason is a
    # sentence, and _label's cut landed mid-word on the half that matters.
    lines.append(f'{end}(["{_mlabel(textwrap.wrap(text, DEAD_END_WIDTH))}"])')
    lines.append(f"{node} -.-> {end}")
    classes["none"].append(end)
