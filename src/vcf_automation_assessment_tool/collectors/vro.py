"""vRO collector: resolve referenced workflows to names.

Talks to the embedded Orchestrator (/vco on the VCF Automation host) and to any external
vRO integration endpoints found on the platform, using the same bearer token
(external vROs integrated with VCF Automation trust its identity provider).

Deliberately narrow scope: only workflows referenced by a subscription or a
custom resource are looked up, each by direct GET - no full inventory sweep.
That avoids pagination limits entirely (a sweep capped at N per endpoint left
workflows unresolved on live data) and keeps the built-in Library out of the
report. Workflow internals are not statically analyzed: top-level workflows
mostly orchestrate actions and sub-workflows, so scriptable-task heuristics on
them mislead - logic classification stays a vRO-side review (REP-003).

Outputs:
- raw["vro"]["endpoints"]: endpoints tried, reachability, server-side total
- raw["vro"]["workflows"]: referenced workflows with resolved names
- subscriptions in raw["extensibility"] are enriched in place: runnableName is
  filled from the lookups so diagrams show names instead of ids
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from urllib.parse import urlparse

from .. import codequality
from ..client import ApiClient, ApiError
from ..models import AssessmentData, area_gap

log = logging.getLogger(__name__)

AREA = "vro"
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

# VMware-shipped action modules; excluded from inventory and analysis.
BUILTIN_ACTION_PREFIXES = ("com.vmware.",)
ACTION_PAGE_SIZE = 200
MAX_ACTION_PAGES = 50
# Per-endpoint cap on detail fetches (one GET per action to obtain source).
MAX_ACTION_DETAILS = 500


def collect(client: ApiClient, data: AssessmentData) -> None:
    raw: dict = {"endpoints": [], "workflows": []}
    reachable: list[tuple[str, str]] = []

    for source, api_base in _endpoints(client, data):
        entry = {"url": api_base, "source": source, "reachable": False, "workflows_total": None}
        try:
            body = client.get(f"{api_base}/api/workflows", params={"maxResult": 1, "startIndex": 0})
            entry["reachable"] = True
            total = body.get("total")
            # This build answers -1 when it declines to count. A negative total
            # is not a count, and rendering it as one reads as a real figure.
            entry["workflows_total"] = total if isinstance(total, int) and total >= 0 else None
            reachable.append((source, api_base))
            log.info(
                "%s: endpoint %s (%s) reachable, %s workflow(s) server-side",
                AREA,
                api_base,
                source,
                entry["workflows_total"]
                if entry["workflows_total"] is not None
                else "an unstated number of",
            )
        except ApiError as exc:
            log.warning("%s: endpoint %s unreachable: %s", AREA, api_base, exc)
            data.record_error(AREA, f"endpoint:{api_base}", str(exc))
        raw["endpoints"].append(entry)

    used_by = _used_by_map(data)
    bindings = custom_resource_bindings(data)
    bound_ids = {b["runnable_id"] for b in bindings if b["kind"] != "abx"}
    resolved_names: dict[str, str] = {}
    workflows: list[dict] = []
    for wf_id, refs in sorted(used_by.items()):
        wf = {
            "id": wf_id,
            "name": wf_id,
            "resolved": False,
            "endpoint_source": "",
            "used_by": refs,
            "structure": None,
            "complexity": "",
        }
        for source, api_base in reachable:
            try:
                body = client.get(f"{api_base}/api/workflows/{wf_id}")
            except ApiError:
                continue
            name = _workflow_name(body)
            if name:
                wf.update(name=name, resolved=True, endpoint_source=source)
                resolved_names[wf_id] = name
                # Structural complexity from the workflow definition. This is
                # NOT script analysis (which misleads on workflows) - the
                # orchestration graph itself is what gets rated.
                try:
                    content = client.get(f"{api_base}/api/workflows/{wf_id}/content")
                    wf["structure"] = _workflow_structure(content)
                    wf["complexity"] = _complexity_rating(wf["structure"])
                except ApiError:
                    pass  # content unreadable: structure stays None
                break
        # Custom-resource references come from a UUID scan of their raw JSON,
        # which also matches non-workflow ids - keep only what resolved, or
        # definite workflow references (subscriptions name the runnable id).
        definite = wf_id in bound_ids or any(r.startswith("subscription:") for r in refs)
        if wf["resolved"] or definite:
            workflows.append(wf)

    _enrich_subscriptions(data, resolved_names)
    _confirm_bindings(data, bindings, resolved_names)
    raw["custom_resource_bindings"] = bindings
    raw["workflows"] = sorted(workflows, key=lambda w: (not w["resolved"], w["name"].lower()))

    actions: list[dict] = []
    builtin_excluded = 0
    for source, api_base in reachable:
        found, excluded = _collect_actions(client, data, source, api_base)
        actions.extend(found)
        builtin_excluded += excluded
    raw["actions"] = sorted(actions, key=lambda a: (not a["issues"], a["fqn"].lower()))
    raw["builtin_actions_excluded"] = builtin_excluded
    raw["action_runtimes"] = dict(Counter(a["runtime"] for a in actions))

    data.raw[AREA] = raw
    data.derived["vro_workflow_names"] = resolved_names
    log.info(
        "%s: resolved %d of %d referenced workflow(s); %d customer action(s) analyzed",
        AREA,
        len(resolved_names),
        len(workflows),
        len(actions),
    )


def _endpoint_key(url: str) -> str:
    """Identity of a vRO endpoint, so one server spelled two ways is one.

    A live run reached the embedded Orchestrator as both
    "https://host/vco" and "https://host:443/vco" - the same server with the
    default port written out - and analysed every customer action twice.
    Comparing the raw strings cannot see that; comparing scheme, host and an
    explicit-only port can.
    """
    parsed = urlparse(url.lower().rstrip("/"))
    host = parsed.hostname or ""
    default = {"https": 443, "http": 80}.get(parsed.scheme)
    port = parsed.port
    suffix = "" if port in (None, default) else f":{port}"
    return f"{parsed.scheme}://{host}{suffix}{parsed.path}"


def _endpoints(client: ApiClient, data: AssessmentData) -> list[tuple[str, str]]:
    """Embedded /vco plus every external vRO integration endpoint."""
    endpoints = [("embedded", f"{client.base_url}/vco")]
    for integration in data.raw.get("infrastructure", {}).get("integrations", []):
        if (integration.get("integrationType") or "").lower() not in ("vro", "vro-gateway"):
            continue
        props = integration.get("integrationProperties") or {}
        for value in props.values():
            if not isinstance(value, str) or not value.startswith("http"):
                continue
            url = value.rstrip("/")
            if not url.endswith("/vco"):
                url = f"{url}/vco"
            # Dedupe on the server the URL names, not on its spelling:
            # two spellings of one server double-probe it and double-count
            # every customer action.
            key = _endpoint_key(url)
            if all(key != _endpoint_key(existing) for _, existing in endpoints):
                endpoints.append((integration.get("name") or "external", url))
    return endpoints


def _workflow_structure(content) -> dict:
    """Structural metrics from the workflow definition's item graph."""
    items = content.get("workflow-item") if isinstance(content, dict) else None
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        items = []
    structure = {
        "items": 0,
        "scriptable_tasks": 0,
        "decisions": 0,
        "sub_workflows": 0,
        "user_interactions": 0,
        "timers": 0,
    }
    for item in items:
        if not isinstance(item, dict):
            continue
        item_type = (item.get("type") or "").lower()
        if item_type == "end":
            continue
        structure["items"] += 1
        if "script" in item:
            structure["scriptable_tasks"] += 1
        if "condition" in item_type or "switch" in item_type:
            structure["decisions"] += 1
        if item.get("linked-workflow-id"):
            structure["sub_workflows"] += 1
        if item_type == "input":
            structure["user_interactions"] += 1
        if item_type.startswith("waiting"):
            structure["timers"] += 1
    return structure


def _complexity_rating(structure: dict) -> str:
    """LOW/MEDIUM/HIGH from the orchestration graph. Thresholds are stated
    heuristics: branching, nesting and long-running elements weigh more than
    plain task count."""
    score = (
        structure["items"]
        + 2 * structure["decisions"]
        + 3 * structure["sub_workflows"]
        + 3 * structure["user_interactions"]
        + 2 * structure["timers"]
    )
    if score >= 25 or structure["items"] >= 20:
        return "HIGH"
    if score >= 10 or structure["items"] >= 8:
        return "MEDIUM"
    return "LOW"


def _workflow_name(body) -> str | None:
    """Single-workflow GET: name at top level, or in link-attribute format."""
    if not isinstance(body, dict):
        return None
    if isinstance(body.get("name"), str) and body["name"]:
        return body["name"]
    for attr in body.get("attributes", []) or []:
        if isinstance(attr, dict) and attr.get("name") == "name" and attr.get("value"):
            return attr["value"]
    return None


# The lifecycle slots a custom resource type binds, in the order the form
# service's MainResourceActions schema names them.
LIFECYCLE_ACTIONS = ("allocate", "create", "read", "update", "delete")


def _runnable_kind(runnable_type: str) -> str:
    """abx, workflow or unknown, from a RunnableItem's type string.

    The form-service schema types it as a bare string, so this reads the
    same spellings the event broker uses for its runnableType and claims
    nothing about any other.
    """
    t = (runnable_type or "").lower()
    if "abx" in t:
        return "abx"
    if "vco" in t or "vro" in t or "workflow" in t:
        return "workflow"
    return "unknown"


def custom_resource_bindings(data: AssessmentData) -> list[dict]:
    """Every runnable a custom resource type or resource action binds.

    Read from the documented shape (custom_forms.json): a type's
    mainActions holds one RunnableItem per lifecycle slot, its
    additionalActions and the standalone resource actions each carry a
    runnableItem. A binding names what runs; whether that runnable exists is
    decided later, once the Orchestrators have been asked.
    """
    design = data.raw.get("blueprints", {})
    bindings: list[dict] = []

    def add(owner_kind: str, owner: dict, action: str, item) -> None:
        if not isinstance(item, dict) or not item.get("id"):
            return
        bindings.append(
            {
                "owner_kind": owner_kind,
                "owner_id": owner.get("id") or "",
                "owner": owner.get("displayName") or owner.get("name") or owner.get("id") or "?",
                "resource_type": owner.get("resourceType") or "",
                "action": action,
                "runnable_id": item["id"],
                "runnable_name": item.get("name") or "",
                "runnable_type": item.get("type") or "",
                "kind": _runnable_kind(item.get("type") or ""),
                "confirmed": None,
            }
        )

    for crt in design.get("custom_resource_types", []) or []:
        if not isinstance(crt, dict):
            continue
        main = crt.get("mainActions") or {}
        if isinstance(main, dict):
            for slot in LIFECYCLE_ACTIONS:
                add("custom resource", crt, slot, main.get(slot))
        for extra in crt.get("additionalActions") or []:
            if isinstance(extra, dict):
                label = extra.get("displayName") or extra.get("name") or "day-2 action"
                add("custom resource", crt, f"day-2: {label}", extra.get("runnableItem"))
    for cra in design.get("custom_resource_actions", []) or []:
        if isinstance(cra, dict):
            add("resource action", cra, "day-2", cra.get("runnableItem"))
    return bindings


def _confirm_bindings(data: AssessmentData, bindings: list[dict], resolved: dict[str, str]) -> None:
    """Fill confirmed and runnable_name from what the run could read.

    An ABX binding is confirmed against the full ABX inventory, so absence
    there is a real absence unless that inventory failed to collect. A
    workflow binding is confirmed only by a successful lookup: an
    Orchestrator that answers 404 may be external or ACL-hidden, so
    unresolved stays None, never False.
    """
    abx_read = not area_gap(data, "extensibility", {"abx_actions"})
    abx_names = {
        a.get("id"): a.get("name") or ""
        for a in data.raw.get("extensibility", {}).get("abx_actions", [])
    }
    for b in bindings:
        rid = b["runnable_id"]
        if b["kind"] == "abx":
            if rid in abx_names:
                b["confirmed"] = True
                b["runnable_name"] = b["runnable_name"] or abx_names[rid]
            elif abx_read:
                b["confirmed"] = False
        elif b["kind"] == "workflow" and rid in resolved:
            b["confirmed"] = True
            b["runnable_name"] = b["runnable_name"] or resolved[rid]
        b["runnable_name"] = b["runnable_name"] or rid


def _known_non_workflow_ids(data: AssessmentData) -> set[str]:
    """Ids the run already accounts for as something other than a workflow.

    The custom-resource UUID scan matches every id in the raw JSON - the
    document's own id, project ids, catalog item ids - and each candidate
    costs one GET per reachable endpoint. Anything already inventoried under
    another identity cannot be a workflow, so it is never probed. Unknown
    ids (form ids, external references) still are: a wasted 404 beats a
    missed workflow reference.
    """
    ids: set[str] = set()
    ids.update(data.derived.get("project_names") or {})
    for bp in data.raw.get("blueprints", {}).get("blueprints", []):
        ids.add(bp.get("id") or "")
    for item in data.raw.get("catalog", {}).get("items", []):
        ids.add(item.get("id") or "")
    for area, keys in (
        ("extensibility", ("subscriptions", "abx_actions")),
        ("blueprints", ("custom_resource_types", "custom_resource_actions")),
        ("governance", ("policies",)),
    ):
        for key in keys:
            for obj in data.raw.get(area, {}).get(key, []):
                if isinstance(obj, dict):
                    ids.add(obj.get("id") or "")
    ids.discard("")
    return ids


def _used_by_map(data: AssessmentData) -> dict[str, list[str]]:
    """workflow id -> what references it (subscriptions, custom resources)."""
    used: dict[str, list[str]] = {}
    for sub in data.raw.get("extensibility", {}).get("subscriptions", []):
        rt = sub.get("runnableType") or ""
        if ("vco" in rt or "vro" in rt) and sub.get("runnableId"):
            used.setdefault(sub["runnableId"], []).append(f"subscription: {sub.get('name', '?')}")
    design = data.raw.get("blueprints", {})
    # A binding read from the documented shape is definite, like a
    # subscription's runnableId; the UUID scan below still catches a
    # reference held somewhere the shape does not name.
    bindings = custom_resource_bindings(data)
    for b in bindings:
        if b["kind"] != "abx":
            label = f"{b['owner_kind']}: {b['owner']}"
            used.setdefault(b["runnable_id"], [])
            if label not in used[b["runnable_id"]]:
                used[b["runnable_id"]].append(label)
    # Only the fuzzy UUID-scan candidates are filtered; a subscription's
    # runnableId above is a definite workflow reference and never dropped.
    # An id a binding declares as an ABX action cannot be a workflow either.
    known = _known_non_workflow_ids(data) | {
        b["runnable_id"] for b in bindings if b["kind"] == "abx"
    }
    for kind, key in (
        ("custom resource", "custom_resource_types"),
        ("resource action", "custom_resource_actions"),
    ):
        for obj in design.get(key, []):
            label = f"{kind}: {obj.get('displayName') or obj.get('name') or obj.get('id', '?')}"
            for wf_id in set(UUID_RE.findall(json.dumps(obj, default=str))) - known:
                used.setdefault(wf_id, [])
                if label not in used[wf_id]:
                    used[wf_id].append(label)
    return used


def _collect_actions(
    client: ApiClient, data: AssessmentData, source: str, api_base: str
) -> tuple[list[dict], int]:
    """Inventory customer actions on one endpoint and analyze their source.

    Actions are the leaf code units in vRO (unlike workflows, which mostly
    orchestrate), so ABX-style static analysis is meaningful here. Built-in
    com.vmware.* modules are excluded.
    """
    try:
        listing, truncated = _fetch_action_list(client, api_base)
    except ApiError as exc:
        log.warning("%s: action listing on %s failed: %s", AREA, api_base, exc)
        data.record_error(AREA, f"actions:{api_base}", str(exc))
        return [], 0
    if truncated:
        # The page budget ran out before any stop condition fired: what
        # follows covers only the actions listed so far, and SYS-001 says so.
        data.record_error(
            AREA,
            f"actions:{api_base}",
            f"action listing stopped after {MAX_ACTION_PAGES} pages; inventory incomplete",
        )

    customer = [a for a in listing if not a["fqn"].startswith(BUILTIN_ACTION_PREFIXES)]
    excluded = len(listing) - len(customer)
    if len(customer) > MAX_ACTION_DETAILS:
        data.record_error(
            AREA,
            f"actions:{api_base}",
            f"analyzed first {MAX_ACTION_DETAILS} of {len(customer)} customer actions",
        )
        customer = customer[:MAX_ACTION_DETAILS]

    out: list[dict] = []
    ps_pending: list[tuple[dict, str]] = []
    js_pending: list[tuple[dict, str]] = []
    for entry in customer:
        action = {
            "id": entry["id"],
            "fqn": entry["fqn"],
            "name": entry["name"],
            "endpoint_source": source,
            "runtime": "javascript",
            "lines": None,
            "analysis": None,
            "issues": [],
            "pedantic_issues": [],
            "source_fingerprint": "",
            "source_sketch": [],
        }
        try:
            detail = client.get(f"{api_base}/api/actions/{entry['id']}")
        except ApiError as exc:
            action["issues"] = [f"detail not readable ({exc.status_code or '?'})"]
            out.append(action)
            continue
        runtime = detail.get("runtime") or ""
        # Polyglot runtimes look like "python:3.10"; classic JS has none.
        action["runtime"] = runtime.split(":")[0].strip().lower() or "javascript"
        script = detail.get("script") or ""
        if not script:
            action["issues"] = ["no inline script (bundle-based action) - not analyzable"]
            out.append(action)
            continue
        analysis = codequality.analyze_script(script, action["runtime"])
        literals = codequality.scan_literals(script, action["runtime"])
        action["lines"] = analysis.get("lines")
        action["analysis"] = {**analysis, "literals": literals}
        _apply_quality(action)
        sketch = codequality.source_sketch(script, action["runtime"])
        action["source_fingerprint"] = sketch["fingerprint"]
        action["source_sketch"] = sketch["sketch"]
        if action["runtime"].startswith("powershell"):
            ps_pending.append((action, script))
        elif action["runtime"].startswith(("javascript", "node")):
            js_pending.append((action, script))
        out.append(action)
    # Swap heuristic metrics for real ones from each language's own parser
    # (one batched subprocess each); heuristics stay when one is unavailable.
    # Node only answers "does this parse" - there is no structural upgrade for
    # JavaScript, so those actions keep their size-only view.
    _upgrade(ps_pending, codequality.parse_powershell_batch)
    _upgrade(js_pending, codequality.parse_javascript_batch)
    return out, excluded


def _apply_quality(action: dict) -> None:
    """(Re)derive an action's issue lists from its analysis. Shared by first
    analysis and by each parser upgrade, so an upgrade can never leave the
    issue lists describing the superseded heuristics. Orchestrator actions
    carry no dependency manifest and no declared entrypoint, hence the empty
    unpinned list and the absent entrypoint argument."""
    analysis = action["analysis"]
    literals = analysis.get("literals") or {}
    action["issues"] = codequality.code_issues(analysis, literals, [])
    action["pedantic_issues"] = codequality.pedantic_issues(analysis)


def _upgrade(pending: list[tuple[dict, str]], parse) -> None:
    metrics = parse([s for _, s in pending]) if pending else None
    if not metrics:
        return
    for (action, _), m in zip(pending, metrics, strict=True):
        if m is None:
            continue
        action["analysis"].update(m)
        _apply_quality(action)


def _fetch_action_list(client: ApiClient, api_base: str) -> tuple[list[dict], bool]:
    """List actions with pagination guards: some builds ignore startIndex and
    return everything, so stop as soon as a page adds nothing new. The second
    return value is True when the page budget ran out first - a truncation
    the caller records as a gap instead of passing off as the full inventory.
    """
    seen: dict[str, dict] = {}
    start = 0
    truncated = True
    for _ in range(MAX_ACTION_PAGES):
        body = client.get(
            f"{api_base}/api/actions",
            params={"maxResult": ACTION_PAGE_SIZE, "startIndex": start},
        )
        links = body.get("link") or []
        new = 0
        for link in links:
            attrs = {
                a.get("name"): a.get("value")
                for a in link.get("attributes", []) or []
                if isinstance(a, dict)
            }
            aid = attrs.get("id")
            if aid and aid not in seen:
                seen[aid] = {
                    "id": aid,
                    "fqn": attrs.get("fqn") or attrs.get("name") or aid,
                    "name": attrs.get("name") or attrs.get("fqn") or aid,
                }
                new += 1
        start += len(links)
        total = body.get("total")
        if not links or new == 0 or (isinstance(total, int) and start >= total):
            truncated = False
            break
    return list(seen.values()), truncated


def _enrich_subscriptions(data: AssessmentData, resolved_names: dict[str, str]) -> None:
    """Fill runnableName (and confirm existence) from resolved lookups."""
    for sub in data.raw.get("extensibility", {}).get("subscriptions", []):
        rt = sub.get("runnableType") or ""
        if "vco" not in rt and "vro" not in rt:
            continue
        name = resolved_names.get(sub.get("runnableId") or "")
        if name:
            if not sub.get("runnableName"):
                sub["runnableName"] = name
            sub["runnableResolved"] = True
        # Not resolved stays unverified (None) - an endpoint may be down.
