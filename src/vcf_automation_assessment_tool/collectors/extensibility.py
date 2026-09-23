"""Extensibility collector: event subscriptions (with criteria analysis and
runnable resolution) and ABX actions (code-quality analysis plus per-action
run evidence). Every sub-collector is best-effort."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

from .. import codequality
from ..client import ApiClient, ApiError
from ..models import AssessmentData

log = logging.getLogger(__name__)

AREA = "extensibility"

UUID_RE = r"[0-9a-fA-F-]{8,}"


_QUOTED_RE = re.compile(r"'([^']*)'|\"([^\"]*)\"")


def _quoted_literals(text: str) -> list[str]:
    """Every quoted literal in a fragment, in order. Falls back to bare
    id-shaped tokens so an unquoted `in [uuid, uuid]` list still reads."""
    quoted = [single or double for single, double in _QUOTED_RE.findall(text)]
    return quoted or re.findall(UUID_RE, text)


def _field_pattern(field: str) -> str:
    """Every comparison form this parser understands, for one criteria field."""
    return (
        rf"{field}\s*(?:(==|!=)\s*(?:'([^']*)'|\"([^\"]*)\")"
        rf"|(not\s+in|in)\s*\[([^\]]*)\])"
    )


# Any operator that narrows an event: what is left after the comparisons this
# parser understands have been removed decides whether the criteria was read
# in full.
_COMPARISON_RE = re.compile(r"==|!=|=~|!~|\bnot\s+in\b|\bin\b|\bmatches\b|[<>]")

_READ_FIELDS = ("blueprintId", "projectId")


def _criteria_fully_read(criteria: str) -> bool:
    """Whether every comparison in the expression is one this parser evaluated.

    A criteria that also filters on eventType, status or a custom property is
    only partly read. Its blueprint/project half can still rule a subscription
    OUT - under an outermost AND, one false clause settles the whole
    expression - but it can never rule one IN, because the clauses left
    unread decide that. Live estates lean on this: four of the five
    `blueprintId != "inline-blueprint"` guards seen in one report also test
    eventType, and treating those as fully evaluated would have turned a
    conditional edge into a confident one.
    """
    residual = criteria
    for field in _READ_FIELDS:
        residual = re.sub(_field_pattern(field), " ", residual)
    return not _COMPARISON_RE.search(residual)


def _strip_enclosing_brackets(criteria: str) -> str:
    """Drop a bracket pair that wraps the whole expression.

    `(a || b)` is a top-level disjunction with a redundant pair around it, but
    a depth-based scan reads it at depth 1 and calls it subordinate. Live
    estates write it that way: three subscriptions on the aib estate wrap a
    disjunction of blueprint ids and custom properties in one pair, and the
    unread half was silently ruled out of every item it did not name.

    Only a pair that encloses the WHOLE expression is dropped. `(a) || (b)`
    opens and closes before the end, so it is left alone.
    """
    text = criteria.strip()
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        i = 0
        while i < len(text) - 1:
            char = text[i]
            if char in "'\"":
                close = text.find(char, i + 1)
                i = len(text) if close == -1 else close + 1
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    # The opening bracket closed before the end: it wraps a
                    # sub-expression, not the whole thing.
                    return text
            i += 1
        text = text[1:-1].strip()
    return text


def _criteria_top_level_or(criteria: str) -> bool:
    """Whether the expression has a disjunction at its outermost level.

    `a && (b || c)` does not: the parenthesised `||` is subordinate, so a
    false `a` still settles the expression. `a || b` does, and then no clause
    on its own can rule the subscription out. Quoted literals are skipped so
    an `||` inside a string cannot be mistaken for an operator.
    """
    criteria = _strip_enclosing_brackets(criteria)
    depth = 0
    i = 0
    while i < len(criteria):
        char = criteria[i]
        if char in "'\"":
            close = criteria.find(char, i + 1)
            i = len(criteria) if close == -1 else close + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth <= 0:
            if criteria.startswith("||", i):
                return True
            if re.match(r"\bor\b", criteria[i:]):
                return True
        i += 1
    return False


def _criteria_comparisons(field: str, criteria: str) -> tuple[list[str], list[str]]:
    """The values a criteria expression requires `field` to equal, and the
    values it requires `field` not to equal.

    `==` and `in [...]` feed the equals list; `!=` and `not in [...]` feed the
    not-equals list. Negation used to be invisible here: the expression parsed
    to nothing, every item fell through to the conditional scope, and each such
    subscription was then drawn on every catalog item in the report. A criteria
    mixing both (`x != 'a' or x == 'b'`) was worse - only the `==` half was
    read, so the tool made confident decisions on an inverted expression.

    Literals are taken whole, whatever their shape. A blueprintId is usually a
    uuid, but the platform stamps a sentinel there for catalog items that have
    no template (this estate: "inline-blueprint"), and the old uuid-shaped
    filter dropped it silently.
    """
    pattern = _field_pattern(field)
    equals: list[str] = []
    not_equals: list[str] = []
    for m in re.finditer(pattern, criteria):
        if m.group(1):
            target = not_equals if m.group(1) == "!=" else equals
            target.append(m.group(2) if m.group(2) is not None else m.group(3))
        else:
            target = not_equals if m.group(4).startswith("not") else equals
            target.extend(_quoted_literals(m.group(5)))
    return equals, not_equals


def _id_shaped(value: str) -> bool:
    """Whether a literal looks like a platform id rather than a sentinel or a
    name. Gates what reaches `criteria_*_ids`, which EXT-001 reads as real
    object references - a sentinel there would report a missing blueprint."""
    return bool(re.fullmatch(UUID_RE, value))


# Platform-created subscriptions that exist on every install and carry no
# customer logic; hidden from the report by default (kept in the JSON dump).
# Matched case-insensitively as substrings of the subscription name, in
# addition to the API's own system flag.
BUILTIN_SUBSCRIPTION_PATTERNS = (
    "quota enforcement",
    "migration assessment",
    "abx-cgs-",
    "approval workflow",
)


def _is_builtin(sub: dict) -> bool:
    """True for platform-internal subscriptions a customer never created.

    The event-broker API returns every subscription in the broker, including
    service-to-service plumbing on internal topics (broker.broadcast.command,
    cgs-content-update-topic, endpoint.cud, ...) that the UI never shows and
    that is not reliably marked with the system flag. The robust discriminator
    is the runnable: UI-created subscriptions always run an extensibility
    runnable (ABX action or vRO workflow); internal service subscriptions
    do not.
    """
    if sub.get("system"):
        return True
    if not (sub.get("runnableType") or "").startswith("extensibility."):
        return True
    name = (sub.get("name") or "").lower()
    return any(p in name for p in BUILTIN_SUBSCRIPTION_PATTERNS)


def collect(client: ApiClient, data: AssessmentData) -> None:
    raw: dict = {}

    def fetch(key: str, path: str, params: dict | None = None) -> list:
        try:
            items = list(client.iter_paged(path, params))
            log.info("%s: %d %s", AREA, len(items), key)
            raw[key] = items
            return items
        except ApiError as exc:
            log.warning("%s: %s unavailable: %s", AREA, key, exc)
            data.record_error(AREA, key, str(exc))
            raw[key] = []
            return []

    subscriptions = fetch("subscriptions", "/event-broker/api/subscriptions")
    abx_actions = fetch("abx_actions", "/abx/api/resources/actions")

    raw["subscriptions"] = [
        _analyze_subscription(s, abx_actions, client, data) for s in subscriptions
    ]
    # Replace raw ABX actions with slimmed + quality-analyzed entries. The
    # inline source is analyzed then dropped so the JSON dump stays lean.
    raw["abx_actions"] = [_analyze_abx_action(a) for a in abx_actions]
    entries = raw["abx_actions"]
    _upgrade_analyses(
        entries, abx_actions, "powershell", codequality.parse_powershell_batch, "PowerShell"
    )
    _upgrade_analyses(
        entries, abx_actions, NODE_RUNTIMES, codequality.parse_javascript_batch, "node"
    )
    # Run evidence rides on the inventory: one small per-action lookup each.
    # With no inventoried actions there is nothing to look up and no
    # evidence key exists (the Last run column and EXT-006 need actions
    # anyway).
    if raw["abx_actions"]:
        raw["abx_run_evidence"] = _collect_abx_run_evidence(client, data, raw["abx_actions"])
    data.raw[AREA] = raw


# Newest runs fetched per action: record 0 is the claimed latest, the page
# verifies descending order, and a total at or under this means the action's
# whole retained history was read (the latest then needs no ordering trust).
PER_ACTION_RUN_PAGE = 10
# One lookup per action is N+1 by design; the cap bounds a pathological
# estate the same way the vRO detail sweep is bounded, with the remainder
# recorded as a gap.
MAX_RUN_LOOKUPS = 500


def _collect_abx_run_evidence(client: ApiClient, data: AssessmentData, actions: list) -> dict:
    """Per-action run evidence via /abx/api/resources/actions/{id}/action-runs.

    One small request per inventoried action. totalElements answers "has
    this action ever run within the retained history" outright, and the
    association comes from the URL - no join between run actionIds and
    inventory ids (a live build returned name-like run actionIds that would
    not match). Housekeeping prunes old runs, so absence is never presented
    as proof an action never ran.

    The latest run is claimed only when it can be trusted: the whole history
    fit in the page (client-side max), or newest-first was requested via
    $orderby - the one parameter the ABX run APIs accept beyond paging;
    the swagger-advertised sort/projection params fail with HTTP 500 - AND
    the page verifies as descending. Otherwise the entry keeps the count
    and no latest, and the report shows "N run(s)" rather than a claimed
    date. A build without this route records a gap and run evidence is
    omitted entirely - never guessed.

    When the lookups complete, one extra request dates the floor of the
    window they cover: the oldest run record still retained anywhere
    (oldest_run_millis, via _fetch_oldest_run_millis). "No recorded runs"
    then means "no run since at least that date".

    Evidence grade of the run-record fields: runState, createdMillis and
    startTimeMillis are observed on live run records (aib estate, 2026-08),
    not taken from a swagger - an absent field degrades that entry to
    count-only evidence, never a wrong date.
    """
    evidence: dict = {
        "collected": False,
        "complete": False,
        "total_runs": 0,
        "by_action": {},
    }
    use_orderby = True
    first_fetch = True
    partial = False
    looked_up = 0
    with_ids = sum(1 for a in actions if a.get("id"))

    def fetch_page(action_id: str, ordered: bool) -> dict:
        path = f"/abx/api/resources/actions/{action_id}/action-runs"
        if ordered:
            path += "?$orderby=createdMillis%20desc"
        body = client.get(path, {"page": 0, "size": PER_ACTION_RUN_PAGE})
        return body if isinstance(body, dict) else {}

    for action in actions:
        aid = action.get("id") or ""
        if not aid:
            # An unidentifiable action cannot be looked up; the evidence is
            # partial, so nothing downstream claims it never ran.
            partial = True
            continue
        if looked_up >= MAX_RUN_LOOKUPS:
            data.record_error(
                AREA,
                "abx_action_runs",
                f"run lookups capped at {MAX_RUN_LOOKUPS} of {with_ids} action(s); "
                "the remainder was not read",
            )
            partial = True
            break
        looked_up += 1
        try:
            try:
                body = fetch_page(aid, use_orderby)
            except ApiError:
                if not first_fetch or not use_orderby:
                    raise
                # First fetch only: $orderby may be the problem - try bare.
                # Gated on "first fetch attempted", not list position: an
                # id-less action[0] used to leave the fallback dead.
                use_orderby = False
                body = fetch_page(aid, False)
        except ApiError as exc:
            if evidence["collected"] and getattr(exc, "status_code", None) == 404:
                # The route is proven present by an earlier 200: one action
                # answering 404 (deleted between inventory and lookup) gets
                # its own gap instead of voiding the estate's evidence.
                data.record_error(AREA, f"abx_action_runs:{action.get('name') or aid}", str(exc))
                partial = True
                continue
            if not evidence["collected"]:
                log.warning(
                    "%s: per-action run endpoint unavailable (%s); run evidence omitted",
                    AREA,
                    exc,
                )
                data.record_error(AREA, "abx_action_runs", str(exc))
                return evidence
            data.record_error(
                AREA,
                "abx_action_runs",
                f"per-action run lookups aborted at '{action.get('name') or aid}': {exc}",
            )
            return evidence
        first_fetch = False
        evidence["collected"] = True
        content = body.get("content") or []
        total = body.get("totalElements")
        has_total = isinstance(total, int)
        n = total if has_total else len(content)
        evidence["total_runs"] += n
        if n <= 0:
            continue
        entry = {"count": n, "last_millis": 0, "last_state": ""}
        millis = []
        for r in content:
            value = r.get("createdMillis") or r.get("startTimeMillis")
            millis.append(int(value) if isinstance(value, int | float) else 0)
        if content:
            descending = all(b <= a for a, b in zip(millis, millis[1:], strict=False))
            # Whole history only when the envelope SAYS so (an int total at
            # or under the page) or a short page proves it; with no usable
            # total a full page may hide newer runs beyond it, and the page
            # max must not be claimed as the latest.
            whole_history = n <= len(content) and (has_total or len(content) < PER_ACTION_RUN_PAGE)
            best = None
            if whole_history:
                best = max(range(len(content)), key=lambda i: millis[i])
            elif use_orderby and descending:
                best = 0
            if best is not None and millis[best]:
                entry["last_millis"] = int(millis[best])
                entry["last_state"] = content[best].get("runState") or ""
        evidence["by_action"][aid] = entry
    evidence["complete"] = evidence["collected"] and not partial
    if evidence["collected"]:
        oldest = _fetch_oldest_run_millis(client, data, use_orderby)
        suffix = ""
        if oldest:
            evidence["oldest_run_millis"] = oldest
            day = datetime.fromtimestamp(oldest / 1000, tz=UTC).strftime("%Y-%m-%d")
            suffix = f"; oldest retained record {day}"
        log.info(
            "%s: per-action run evidence for %d action(s): %d recorded run(s), %d never-run%s",
            AREA,
            len([a for a in actions if a.get("id")]),
            evidence["total_runs"],
            len([a for a in actions if a.get("id") and a["id"] not in evidence["by_action"]]),
            suffix,
        )
    return evidence


def _fetch_oldest_run_millis(client: ApiClient, data: AssessmentData, use_orderby: bool) -> int:
    """The oldest run record still retained anywhere, from one page of the
    global run list ordered ascending - the floor of the window "no recorded
    runs" covers.

    0 when it cannot be claimed honestly: the page neither holds the whole
    history nor verifies as ascending, so a build that silently ignores
    $orderby dates nothing rather than dating the floor from an arbitrary
    record. use_orderby carries what the per-action loop learned; a rejected
    ordered request gets one bare retry, which can then only claim via the
    whole-history-fits rule. A failed fetch records a gap and leaves the
    per-action evidence untouched.
    """

    def fetch(ordered: bool) -> dict:
        path = "/abx/api/resources/action-runs"
        if ordered:
            path += "?$orderby=createdMillis%20asc"
        body = client.get(path, {"page": 0, "size": PER_ACTION_RUN_PAGE})
        return body if isinstance(body, dict) else {}

    try:
        try:
            body = fetch(use_orderby)
        except ApiError:
            if not use_orderby:
                raise
            use_orderby = False
            body = fetch(False)
    except ApiError as exc:
        data.record_error(AREA, "abx_run_history_oldest", str(exc))
        return 0
    content = body.get("content") or []
    if not content:
        return 0
    millis = []
    for r in content:
        value = r.get("createdMillis") or r.get("startTimeMillis")
        millis.append(int(value) if isinstance(value, int | float) else 0)
    total = body.get("totalElements")
    has_total = isinstance(total, int)
    n = total if has_total else len(content)
    # Same envelope rule as the per-action latest: a short page proves the
    # whole history only alongside a usable total or by being under the max.
    whole_history = n <= len(content) and (has_total or len(content) < PER_ACTION_RUN_PAGE)
    if whole_history:
        dated = [m for m in millis if m]
        return min(dated) if dated else 0
    ascending = all(a <= b for a, b in zip(millis, millis[1:], strict=False))
    if use_orderby and ascending and millis[0]:
        return millis[0]
    return 0


def _analyze_abx_action(action: dict) -> dict:
    """Slim an ABX action and attach static code-quality analysis.

    Bundled (zip) actions carry no inline source over the API - recorded as
    not analyzable rather than pretending they were reviewed.
    """
    source = action.get("source") or ""
    runtime = action.get("runtime") or ""
    # Read defensively: anything other than a map leaves declared inputs empty,
    # and the unread-input signal then stays silent rather than guessing at a
    # shape this build does not use.
    declared = action.get("inputs")
    entry = {
        "id": action.get("id", ""),
        "name": action.get("name", ""),
        "selfLink": action.get("selfLink", ""),
        "projectId": action.get("projectId", ""),
        "runtime": runtime,
        # "3.10", "20" or "7.4" per the ABX Action schema (runtimeVersion); the
        # version is what decides whether the platform still runs the action.
        "runtimeVersion": action.get("runtimeVersion") or "",
        "provider": action.get("provider") or "",
        "actionType": action.get("actionType", ""),
        "entrypoint": action.get("entrypoint", ""),
        "timeoutSeconds": action.get("timeoutSeconds"),
        "memoryInMB": action.get("memoryInMB"),
        "dependencies": action.get("dependencies") or "",
        "has_inline_source": bool(source),
        # Input names only: the values are defaults and can hold environment
        # specifics that have no business in the JSON dump.
        "declared_inputs": sorted(declared) if isinstance(declared, dict) else [],
        "analysis": None,
        "issues": [],
        "pedantic_issues": [],
        "complexity": None,
        "source_fingerprint": "",
        "source_sketch": [],
    }
    # ABX flows are YAML orchestrations of other actions, not scripts - script
    # analysis on them produces meaningless "no error handling" noise. The
    # same goes for anything without a recognizable scripting runtime.
    if (action.get("actionType") or "").upper() == "FLOW" or not runtime:
        entry["issues"] = []
        entry["analysis"] = None
        return entry
    if not source:
        entry["issues"] = ["bundled action - source not analyzable via the API"]
        return entry
    analysis = codequality.analyze_script(source, runtime)
    literals = codequality.scan_literals(source, runtime)
    unpinned = codequality.unpinned_dependencies(entry["dependencies"])
    entry["analysis"] = {**analysis, "literals": literals, "unpinned_dependencies": unpinned}
    _apply_quality(entry)
    sketch = codequality.source_sketch(source, runtime)
    entry["source_fingerprint"] = sketch["fingerprint"]
    entry["source_sketch"] = sketch["sketch"]
    return entry


def _apply_quality(entry: dict) -> None:
    """(Re)derive the issue lists and complexity from an entry's analysis.

    Shared by first analysis and by each parser upgrade pass, so an upgrade can
    never leave the issue lists describing the superseded heuristics.
    """
    analysis = entry["analysis"]
    entry["issues"] = codequality.code_issues(
        analysis,
        analysis.get("literals") or {},
        analysis.get("unpinned_dependencies") or [],
        entrypoint=entry.get("entrypoint") or "",
    )
    entry["pedantic_issues"] = codequality.pedantic_issues(analysis, entry.get("declared_inputs"))
    entry["complexity"] = codequality.complexity_rating(analysis)


# ABX names its Node runtime "nodejs"; Orchestrator calls the same language
# "javascript". Both spellings reach the same syntax check.
NODE_RUNTIMES = ("nodejs", "node", "javascript")


def _upgrade_analyses(
    entries: list[dict], actions: list[dict], runtime: str | tuple[str, ...], parse, label: str
) -> None:
    """Swap heuristic metrics for real ones from a language's own parser (one
    batched subprocess). No-op when that parser is not on PATH or a source has
    parse errors - the heuristics are kept, never downgraded."""
    pending = [
        (entry, action.get("source") or "")
        for entry, action in zip(entries, actions, strict=True)
        if entry.get("analysis") and (entry.get("runtime") or "").lower().startswith(runtime)
    ]
    if not pending:
        return
    metrics = parse([source for _, source in pending])
    if metrics is None:
        return
    for (entry, _), m in zip(pending, metrics, strict=True):
        if m is None:
            continue
        entry["analysis"].update(m)
        _apply_quality(entry)
    log.info("%s: %s parser upgraded %d ABX analysis(es)", AREA, label, len(pending))


def _analyze_subscription(
    sub: dict, abx_actions: list[dict], client: ApiClient, data: AssessmentData
) -> dict:
    criteria = sub.get("criteria") or ""
    runnable_type = sub.get("runnableType", "")
    runnable_id = sub.get("runnableId", "")

    entry = {
        "id": sub.get("id", ""),
        "name": sub.get("name", ""),
        "description": sub.get("description", ""),
        "eventTopicId": sub.get("eventTopicId", ""),
        "blocking": bool(sub.get("blocking")),
        "disabled": bool(sub.get("disabled")),
        "priority": sub.get("priority"),
        "timeout": sub.get("timeout"),
        "runnableType": runnable_type,
        "runnableId": runnable_id,
        "runnableName": "",
        "runnableResolved": None,  # None = could not check, True/False otherwise
        "criteria": criteria,
        "scope": "global",  # global | blueprint | project | conditional
        "criteria_blueprint_ids": [],
        "criteria_project_ids": [],
        # Full comparison lists behind those ids, negation included. The
        # *_ids keys stay id-shaped equals-only for EXT-001 and the report's
        # Criteria column; the flows builder evaluates these instead.
        "criteria_blueprint_eq": [],
        "criteria_blueprint_ne": [],
        "criteria_project_eq": [],
        "criteria_project_ne": [],
        # eventType literals the criteria requires and excludes, for the
        # concern a request-topic subscription belongs to. The equals list
        # says which part of a deployment's life it serves; the not-equals
        # list can only say which part it does not. Never used to rule a
        # subscription in or out.
        "criteria_event_types_eq": [],
        "criteria_event_types_ne": [],
        # Whether the expression holds clauses this parser cannot evaluate, and
        # whether its outermost level is a disjunction. Together they say which
        # direction a blueprint/project verdict may be trusted in.
        "criteria_fully_read": True,
        "criteria_top_level_or": False,
        "constraints": sub.get("constraints") or {},
        "subscriberId": sub.get("subscriberId", ""),
        "system": bool(sub.get("system")),
        "builtin": _is_builtin(sub),
    }

    # Best-effort criteria classification: extract the literals the boolean
    # expression compares against. Handles == and != with single or double
    # quotes and EVERY element of an `in [...]` / `not in [...]` list; anything
    # more exotic leaves the lists empty and the flows builder then errs on the
    # side of showing the subscription.
    bp_eq, bp_ne = _criteria_comparisons("blueprintId", criteria)
    proj_eq, proj_ne = _criteria_comparisons("projectId", criteria)
    # Which KIND of request a subscription on a request topic reacts to. Read
    # for the flow diagrams alone, and deliberately absent from _READ_FIELDS:
    # counting it as evaluated would upgrade conditional edges to confident
    # ones all over the report, which is a separate question from where a
    # subscription belongs in the life of a deployment.
    event_eq, event_ne = _criteria_comparisons("eventType", criteria)
    entry["criteria_event_types_eq"] = event_eq
    entry["criteria_event_types_ne"] = event_ne
    entry["criteria_blueprint_eq"] = bp_eq
    entry["criteria_blueprint_ne"] = bp_ne
    entry["criteria_project_eq"] = proj_eq
    entry["criteria_project_ne"] = proj_ne
    entry["criteria_blueprint_ids"] = [v for v in bp_eq if _id_shaped(v)]
    entry["criteria_project_ids"] = [v for v in proj_eq if _id_shaped(v)]
    entry["criteria_fully_read"] = _criteria_fully_read(criteria)
    entry["criteria_top_level_or"] = _criteria_top_level_or(criteria)
    if bp_eq or bp_ne:
        entry["scope"] = "blueprint"
    elif proj_eq or proj_ne:
        entry["scope"] = "project"
    elif criteria.strip():
        # Criteria exists but filters on something we cannot evaluate (custom
        # properties, endpoint types, ...): the subscription fires only when it
        # matches, so flows must present it as conditional, not certain.
        entry["scope"] = "conditional"

    # Resolve the runnable name. runnableResolved semantics: True = confirmed
    # to exist, False = confirmed missing, None = could not verify (never
    # flagged by checks).
    if runnable_type == "extensibility.abx":
        match = next(
            (
                a
                for a in abx_actions
                if a.get("id") == runnable_id or (a.get("selfLink") or "").endswith(runnable_id)
            ),
            None,
        )
        entry["runnableName"] = (match or {}).get("name", "")
        # An empty actions list usually means the ABX collection itself failed
        # or was permission-limited - absence there proves nothing.
        entry["runnableResolved"] = (match is not None) if abx_actions else None
    elif runnable_type in ("extensibility.vco", "extensibility.vro"):
        try:
            wf = client.get(f"/vco/api/workflows/{runnable_id}")
            entry["runnableName"] = wf.get("name", "")
            entry["runnableResolved"] = True
        except ApiError as exc:
            # A 404 from the embedded vRO is NOT proof the workflow is gone:
            # the subscription may target an external vRO integration, and vRO
            # answers 404 (not 403) for workflows the caller's ACLs hide. Leave
            # as unverified rather than reporting a false "missing".
            entry["runnableResolved"] = None
            if exc.status_code != 404:
                data.record_error(AREA, f"vro-workflow:{sub.get('name', runnable_id)}", str(exc))
    return entry
