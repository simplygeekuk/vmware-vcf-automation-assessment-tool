"""Tag normalization and blueprint YAML constraint extraction."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import yaml

log = logging.getLogger(__name__)


def normalize_tag(tag: dict | str) -> str:
    """Normalize {'key': 'env', 'value': 'prod'} (or 'env:prod') to 'env:prod'.

    A tag with an empty value normalizes to just its key.
    """
    if isinstance(tag, str):
        return tag.strip()
    key = (tag.get("key") or "").strip()
    value = (tag.get("value") or "").strip()
    return f"{key}:{value}" if value else key


@dataclass(frozen=True)
class ConstraintTag:
    tag: str  # normalized, without hardness suffix or negation prefix
    hard: bool  # True unless an explicit :soft suffix was present
    negated: bool  # leading '!'
    dynamic: bool  # contains '${...}' - cannot be statically verified
    resource: str  # resource name inside the blueprint
    resource_type: str  # e.g. Cloud.vSphere.Machine
    context: str  # "resource", "network[0]", "disk[1]", "storage"


class BlueprintParseError(Exception):
    pass


def extract_constraint_tags(content: str) -> list[ConstraintTag]:
    """Pull every constraint tag out of a blueprint YAML document.

    Constraints appear at: resources.<name>.properties.constraints,
    per-NIC properties.networks[].constraints, per-disk
    properties.attachedDisks[].constraints and properties.storage.constraints.
    Entries look like {'tag': 'env:prod:hard'} with optional :hard/:soft suffix
    and optional '!' negation prefix.
    """
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise BlueprintParseError(str(exc)) from exc
    if not isinstance(doc, dict):
        return []

    out: list[ConstraintTag] = []

    def take(constraints, res_name: str, res_type: str, context: str) -> None:
        if not isinstance(constraints, list):
            return
        for c in constraints:
            raw = c.get("tag") if isinstance(c, dict) else None
            if not isinstance(raw, str) or not raw.strip():
                continue
            tag = raw.strip()
            hardness = "hard"
            if tag.endswith((":hard", ":soft")):
                tag, _, hardness = tag.rpartition(":")
            negated = tag.startswith("!")
            tag = tag.lstrip("!")
            if not tag:
                # The entry was nothing but a hardness suffix (or a bare "!").
                # There is no tag to match on, and an empty one would join the
                # capability map lookup as a key that matches everything.
                continue
            out.append(
                ConstraintTag(
                    tag=tag,
                    hard=(hardness == "hard"),
                    negated=negated,
                    dynamic="${" in tag,
                    resource=res_name,
                    resource_type=res_type,
                    context=context,
                )
            )

    resources = doc.get("resources")
    if not isinstance(resources, dict):
        return out
    for res_name, res in resources.items():
        if not isinstance(res, dict):
            continue
        res_type = str(res.get("type", ""))
        props = res.get("properties")
        if not isinstance(props, dict):
            continue
        take(props.get("constraints"), res_name, res_type, "resource")
        networks = props.get("networks")
        if isinstance(networks, list):
            for i, net in enumerate(networks):
                if isinstance(net, dict):
                    take(net.get("constraints"), res_name, res_type, f"network[{i}]")
        disks = props.get("attachedDisks")
        if isinstance(disks, list):
            for i, disk in enumerate(disks):
                if isinstance(disk, dict):
                    take(disk.get("constraints"), res_name, res_type, f"disk[{i}]")
        storage = props.get("storage")
        if isinstance(storage, dict):
            take(storage.get("constraints"), res_name, res_type, "storage")
    return out


@dataclass(frozen=True)
class ProjectConstraint:
    tag: str  # normalized, without hardness suffix or negation prefix
    constraint_type: str  # the list it came from: network, storage, extensibility
    hard: bool
    negated: bool


def extract_project_constraints(constraints: dict | None) -> list[ProjectConstraint]:
    """Every constraint a project imposes on the requests made in it.

    Two shapes, both read. The documented model (Project.constraints in
    docs/vcf_automation_oas_specs/8.x/projects.json) maps a constraint type to a
    Constraint holding conditions[], each with an enforcement of HARD or SOFT,
    an occurrence of MUST_OCCUR or MUST_NOT_OCCUR, and an expression of key and
    value. The live 8.x build answers with a list of
    {"expression": "ca:sigma", "mandatory": true} per type instead. A shape
    that is neither is ignored: reading the keys of an object that turns out
    to be a Constraint adds a capability tag called "conditions".
    """
    out: list[ProjectConstraint] = []
    if not isinstance(constraints, dict):
        return out
    for ctype, value in constraints.items():
        for entry in _constraint_entries(value):
            parsed = _project_constraint(str(ctype), entry)
            if parsed:
                out.append(parsed)
    return out


def _constraint_entries(value) -> list:
    """The individual constraints under one type, in either shape."""
    if isinstance(value, list):
        return [entry for entry in value if entry]
    if isinstance(value, dict):
        conditions = value.get("conditions")
        return [c for c in conditions if c] if isinstance(conditions, list) else []
    return []


def _project_constraint(ctype: str, entry) -> ProjectConstraint | None:
    if isinstance(entry, str):
        expression, mandatory, enforcement, occurrence = entry, None, None, None
    elif isinstance(entry, dict):
        # A documented condition states its own type. Only a tag condition
        # carries a capability tag, and another kind is left alone rather than
        # read as one.
        if str(entry.get("type") or "TAG").upper() != "TAG":
            return None
        expression = entry.get("expression")
        mandatory = entry.get("mandatory")
        enforcement = entry.get("enforcement")
        occurrence = entry.get("occurrence")
    else:
        return None

    tag = normalize_tag(expression) if isinstance(expression, dict) else str(expression or "")
    tag, written_hard, written_negation = _read_expression(tag)
    if not tag:
        return None

    if written_hard is not None:
        hard = written_hard
    elif isinstance(enforcement, str):
        hard = enforcement.strip().upper() != "SOFT"
    elif isinstance(mandatory, bool):
        hard = mandatory
    else:
        hard = True

    negated = written_negation or (
        isinstance(occurrence, str) and occurrence.strip().upper() == "MUST_NOT_OCCUR"
    )
    return ProjectConstraint(tag=tag, constraint_type=ctype, hard=hard, negated=negated)


def _read_expression(raw: str) -> tuple[str, bool | None, bool]:
    """(tag, hardness where the text states one, negated) from an expression.

    The user interface offers `key:value`, `key:value:soft` and `!key:value` in
    the same box, so the text can carry what the documented model puts in
    separate fields.
    """
    tag = (raw or "").strip()
    hard: bool | None = None
    if tag.endswith((":hard", ":soft")):
        tag, _, hardness = tag.rpartition(":")
        hard = hardness == "hard"
    negated = tag.startswith("!")
    return tag.lstrip("!").strip(), hard, negated


@dataclass(frozen=True)
class DynamicTag:
    """What a request-time constraint expression can be read to say.

    A dynamic constraint is written as an expression, e.g.
    ${input.environment == "env:dev" ? "net:dev" : "net:prod"}. The tool
    cannot know which branch a request takes, but the branches themselves are
    in the template, and a reader needs those far more than the expression.
    """

    kind: str  # "choice" (values are enumerable), "reference", or "computed"
    values: tuple[str, ...]  # every tag the expression can produce; () unless "choice"
    references: tuple[str, ...]  # what it reads, e.g. ("input.environment",)
    prefix: str  # static leading text, e.g. "net:" from ${"net:"+env.projectName}


# Namespaces an expression can read. Anything else is a function call
# (to_lower, split) or a literal, and naming those as inputs would mislead.
_NAMESPACES = ("input", "env", "self", "resource", "propgroup")
_REFERENCE_RE = re.compile(r"\b(" + "|".join(_NAMESPACES) + r")\.([A-Za-z0-9_]+)")
_PATH_RE = re.compile(r"^(" + "|".join(_NAMESPACES) + r")(\.[A-Za-z0-9_]+)+$")
_QUOTES = "\"'"
# Chained ternaries nest one level per branch. The bound is a guard against a
# pathological expression, not a limit any template comes near.
_MAX_DEPTH = 40


def describe_dynamic_tag(tag: str) -> DynamicTag:
    """Read a ${...} constraint tag for what it decides and what it reads.

    Values are only claimed where every branch of the expression is a string
    literal, so "one of these tags" is never a guess: a concatenation or a
    property-group lookup produces no values at all and is described as
    computed instead.

    They are also only claimed where the expression IS the whole tag, so
    every value handed back is a string the template wrote out in full.
    net:${input.env == "dev" ? "dtq" : "ppp"} could be read as net:dtq and
    net:ppp, and both would be true - but neither string exists in the
    estate's own text, so the redacted copy of the report cannot rewrite them
    the way it rewrites the tag map, and it would print a real tag next to
    somewhere it does not match. Lifting the restriction means enumerating at
    collection time, where the values become ordinary strings in the raw data
    and redaction treats them like any other tag.
    """
    spans = _expression_spans(tag)
    references = _references("".join(inner for _, _, inner in spans))
    if len(spans) != 1:
        # Two expressions in one tag, or none: nothing to enumerate, and the
        # static text before the first one is all the prefix there is.
        prefix = tag[: spans[0][0]] if spans else tag
        return DynamicTag("computed", (), references, prefix)

    start, end, inner = spans[0]
    static_prefix, suffix = tag[:start], tag[end:]
    whole = not static_prefix and not suffix
    choices = _choices(inner) if whole else ()
    if choices:
        return DynamicTag("choice", _unique(choices), references, "")
    if _PATH_RE.match(inner.strip()):
        return DynamicTag("reference", (), references, static_prefix)
    return DynamicTag("computed", (), references, static_prefix or _leading_literal(inner))


def _expression_spans(tag: str) -> list[tuple[int, int, str]]:
    """(start, end, inner expression) for every ${...} in a tag.

    Quote-aware: a literal inside the expression can hold a brace, and the
    span has to end on the brace that closes the expression rather than the
    first one after it.
    """
    spans: list[tuple[int, int, str]] = []
    i = 0
    while True:
        start = tag.find("${", i)
        if start < 0:
            return spans
        depth, quote, j = 1, "", start + 2
        while j < len(tag):
            ch = tag[j]
            if quote:
                if ch == "\\":
                    j += 2
                    continue
                if ch == quote:
                    quote = ""
            elif ch in _QUOTES:
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= len(tag):  # unclosed: the rest of the tag is the expression
            spans.append((start, len(tag), tag[start + 2 :]))
            return spans
        spans.append((start, j + 1, tag[start + 2 : j]))
        i = j + 1


def _mask(expr: str) -> str:
    """The expression with every string literal blanked, indices preserved.

    Scanning for an operator has to ignore the ones inside literals: a tag
    value is written 'net:ALL-sigma-dtq', and its colon is not a ternary.
    """
    out: list[str] = []
    quote, i = "", 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            out.append("\0")
            if ch == "\\" and i + 1 < len(expr):
                out.append("\0")
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in _QUOTES:
            quote = ch
            out.append("\0")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _references(expr: str) -> tuple[str, ...]:
    """Every input, environment or property group the expression reads."""
    return _unique(ns + "." + name for ns, name in _REFERENCE_RE.findall(_mask(expr)))


def _unique(values) -> tuple[str, ...]:
    """Duplicates dropped, first appearance order kept."""
    return tuple(dict.fromkeys(v for v in values if v))


def _unwrap(expr: str) -> str:
    """Whitespace and any parentheses that wrap the whole expression removed."""
    expr = expr.strip()
    while len(expr) > 1 and expr.startswith("(") and expr.endswith(")"):
        masked = _mask(expr)
        depth = 0
        for i, ch in enumerate(masked):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(expr) - 1:
                    return expr  # the first "(" closes before the end
        expr = expr[1:-1].strip()
    return expr


def _literal(expr: str) -> str | None:
    """The text of a whole-expression string literal, else None."""
    expr = expr.strip()
    if len(expr) < 2 or expr[0] not in _QUOTES or expr[-1] != expr[0]:
        return None
    return expr[1:-1] if _mask(expr) == "\0" * len(expr) else None


def _ternary_split(expr: str) -> tuple[str, str] | None:
    """(consequent, alternate) of a top-level a ? b : c, else None.

    The alternate of a chained ternary is another ternary, so the split
    counts the "?" it passes on the way to its own ":" - stopping at the
    first one would cut a chain in the wrong place.
    """
    masked = _mask(expr)
    question = _top_level(masked, "?")
    if question < 0:
        return None
    colon = _top_level(masked, ":", start=question + 1, skip_pairs=True)
    if colon < 0:
        return None
    return expr[question + 1 : colon], expr[colon + 1 :]


def _top_level(masked: str, char: str, start: int = 0, skip_pairs: bool = False) -> int:
    """Index of char outside every bracket, or -1."""
    depth, pending = 0, 0
    for i in range(start, len(masked)):
        ch = masked[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and ch == char:
            if pending == 0:
                return i
            pending -= 1
        elif depth == 0 and skip_pairs and ch == "?":
            pending += 1
    return -1


def _choices(expr: str, depth: int = 0) -> tuple[str, ...]:
    """Every tag a select-one expression can produce, or () when it computes
    its result instead of choosing between written-out tags."""
    if depth > _MAX_DEPTH:
        return ()
    expr = _unwrap(expr)
    literal = _literal(expr)
    if literal is not None:
        return (literal,)
    branches = _ternary_split(expr)
    if branches is None:
        return ()
    consequent = _choices(branches[0], depth + 1)
    alternate = _choices(branches[1], depth + 1)
    # One unreadable branch makes the whole list a guess: the request could
    # always be the one that takes it.
    return consequent + alternate if consequent and alternate else ()


def _leading_literal(expr: str) -> str:
    """The literal a concatenation starts with, e.g. "net:" from
    ${"net:"+env.projectName}, which bounds what the tag can come out as."""
    plus = _top_level(_mask(expr), "+")
    if plus < 0:
        return ""
    return _literal(expr[:plus]) or ""


@dataclass(frozen=True)
class InputDefinition:
    """What a template input can be, as the platform resolved it.

    Read from /blueprint/api/blueprints/{id}/inputs-schema, the same schema
    the request form is built from, so a constraint written as
    ${input.environment} can be answered with the values a requester will
    actually be offered.
    """

    name: str
    type: str  # the declared JSON type, e.g. "string"
    title: str  # the label the form shows, "" when the input has none
    values: tuple[str, ...]  # every value it can take; () unless kind is "declared"
    default: str  # the value a request takes unless changed, "" when none or not text
    source: str  # where an external list comes from, "" unless kind is "external"
    kind: str  # "declared", "external", "none" or "unread"


# Where a resolved schema names the list it fills a field from. $data is what
# this build writes; $dynamicDefault is the other spelling the API documents.
_SOURCE_KEYS = ("$data", "$dynamicDefault")
_VRO_ACTION_PREFIX = "/data/vro-actions/"


def read_input_schema(schema: dict, wanted: set[str] | None = None) -> list[InputDefinition]:
    """Read a blueprint inputs schema into one entry per input.

    Only the shapes the API documents are read: enum, oneOf carrying const,
    and the two keys naming an external list. Anything else keeps an empty
    value list and says which kind of silence it is, so an input that
    declares no values stays distinguishable from one whose declaration
    could not be read. Claiming a value from a shape this tool does not
    recognise would put one estate's spelling into every estate's report.
    """
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict):
        return []
    out = []
    for name, definition in properties.items():
        if not isinstance(name, str) or not isinstance(definition, dict):
            continue
        if wanted is not None and name not in wanted:
            continue
        values, kind, source = _input_values(definition)
        default = definition.get("default")
        out.append(
            InputDefinition(
                name=name,
                type=str(definition.get("type") or ""),
                title=str(definition.get("title") or ""),
                values=values,
                default=default if isinstance(default, str) else "",
                source=source,
                kind=kind,
            )
        )
    return out


def _input_values(definition: dict) -> tuple[tuple[str, ...], str, str]:
    """(values, kind, source) for one input definition."""
    for key in _SOURCE_KEYS:
        source = definition.get(key)
        if isinstance(source, str) and source.strip():
            # The platform fills this list when the form is opened, by
            # running something this tool will not run.
            return (), "external", source.strip()

    enum, one_of = definition.get("enum"), definition.get("oneOf")
    if isinstance(enum, list) and isinstance(one_of, list):
        # Two declarations, and nothing says which one governs.
        return (), "unread", ""
    if isinstance(enum, list):
        if enum and all(isinstance(v, str) for v in enum):
            return _unique(enum), "declared", ""
        return (), "unread", ""
    if isinstance(one_of, list):
        consts = [b.get("const") if isinstance(b, dict) else None for b in one_of]
        if consts and all(isinstance(v, str) for v in consts):
            return _unique(consts), "declared", ""
        # One unreadable branch drops the whole list: a request could always
        # be the one that takes it.
        return (), "unread", ""
    if any(key in definition for key in ("anyOf", "allOf", "$ref", "items")):
        return (), "unread", ""
    return (), "none", ""


def input_source_label(source: str) -> str:
    """What an external value list is fed by, for a reader.

    Named rather than followed: fetching the list runs the action behind it,
    and this is a read-only assessment.
    """
    if source.startswith(_VRO_ACTION_PREFIX):
        return f"Orchestrator action {source[len(_VRO_ACTION_PREFIX) :]}"
    return source


def input_references(constraint_tags) -> set[str]:
    """The input names a template's constraint expressions read.

    Only these are worth collecting: an input no constraint mentions cannot
    change where anything is placed, and free-text business fields have no
    business in the dump.
    """
    wanted = set()
    for tag in constraint_tags or []:
        text = tag.get("tag", "") if isinstance(tag, dict) else getattr(tag, "tag", "")
        for reference in describe_dynamic_tag(text).references:
            namespace, _, name = reference.partition(".")
            if namespace == "input" and name:
                wanted.add(name)
    return wanted
