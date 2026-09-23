"""HTML report rendering: jinja2 template + inlined mermaid, single output file."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from functools import lru_cache
from importlib import resources

from jinja2 import Environment, PackageLoader
from markupsafe import Markup, escape

from .. import flows
from ..checks.deployments import is_machine
from ..coverage import coverage_rows
from ..identity_map import (
    UNKNOWN_OWNER,
    has_evidence,
    owner_access,
    principal_index,
)
from ..models import (
    ITEM_TYPE_LABELS,
    NEAR_LIMIT_RATIO,
    ZONE_LIMITS,
    AssessmentData,
    Severity,
    area_gap,
    endpoint_status,
    format_amount,
    ip_range_usage,
    secret_rows,
    zone_allocations,
)
from ..tagutil import normalize_tag
from . import diagrams
from .insights import finding_insight
from .naming import naming_inventory

log = logging.getLogger(__name__)

MAX_ROWS_PER_FINDING = 500  # default; overridable per run via max_rows_per_finding

# The nine deployment statuses, said in words. The enum is the deployment
# service's own (its swagger describes it as the deployment's state "with
# respect to its life cycle operations - create/update/delete"), which is why
# no day-2 action appears here: a power off or a resize that fails leaves the
# deployment reading as successful, and is reported from the request history
# instead. A status this map does not know is printed bare rather than
# explained - the same rule the rest of the report follows for a value it
# cannot source.
DEPLOYMENT_STATUS_WORDS = {
    "CREATE_SUCCESSFUL": "Built, and the build finished.",
    "CREATE_INPROGRESS": "Being built now.",
    "CREATE_FAILED": "The build failed part way. Whatever it managed to create is still there.",
    "UPDATE_SUCCESSFUL": "A later change was applied and finished.",
    "UPDATE_INPROGRESS": "A change is running now.",
    "UPDATE_FAILED": "A change failed. The machines are most likely still in service.",
    "DELETE_SUCCESSFUL": "Deleted, and everything it held went with it.",
    "DELETE_INPROGRESS": "Being deleted now.",
    "DELETE_FAILED": "The delete failed. The platform could not remove everything it built.",
}
# Per concern, not per estate: an item is drawn once in each part of its life
# that has something attached, so a cap on the whole set would silently drop
# a whole concern on a large estate.
MAX_FLOW_DIAGRAMS = 100
# Placement diagrams are already filtered to the templates worth looking at,
# so this is a backstop against an estate where hundreds qualify, not a sample.
MAX_PLACEMENT_DIAGRAMS = 60

# Section membership: explicit per-check overrides first, then id prefix.
SECTION_OVERRIDES = {
    "REP-002": "design",  # templates not in Git belong with the templates
}
SECTION_PREFIXES = {
    "infrastructure": ("INF", "PRJ", "TAG"),
    "design": ("BLU", "GOV"),
    "consumption": ("DEP", "CAT"),
    "extensibility": ("EXT", "VRO"),
    "governance": ("APR", "POL"),
    "replatforming": ("REP",),
    "system": ("SYS",),
}

POLICY_TYPE_LABELS = {
    "approval": "Approval Policies",
    "lease": "Lease Policies",
    "action": "Day-2 Action Policies",
    "entitlement": "Content Sharing Policies",
    "limit": "Deployment Limit Policies",
    "quota": "Resource Quota Policies",
}


def _section_for(check_id: str) -> str:
    """Where the finding is rendered."""
    if check_id in SECTION_OVERRIDES:
        return SECTION_OVERRIDES[check_id]
    return _home_section(check_id)


def _home_section(check_id: str) -> str:
    """Which section the finding belongs to, ignoring where it is rendered.

    Hiding a section has to take its findings with it wherever they are shown,
    or hiding Replatforming would leave REP-002 behind in Design and Templates
    - the one check whose display section is overridden.
    """
    for section, prefixes in SECTION_PREFIXES.items():
        if check_id.startswith(prefixes):
            return section
    return "system"


def visible_findings(findings: list, ignore_findings, ignore_sections) -> list:
    """The findings a report with these settings shows.

    Shared with the cli so the run's closing count cannot disagree with the
    report it just wrote.
    """
    ignored = {str(i).strip().upper() for i in ignore_findings or []}
    hidden = {str(s).strip().lower() for s in ignore_sections or []}
    return [
        f
        for f in findings
        if f.check_id.upper() not in ignored and _home_section(f.check_id) not in hidden
    ]


def render_report(data: AssessmentData, output_path: str) -> None:
    html = build_html(data)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log.info("report written to %s (%.1f MB)", output_path, len(html) / 1e6)


@lru_cache(maxsize=1)
def _template():
    """The compiled report template, built once per process.

    Compiling 77 KB of Jinja costs about as much as rendering it does, and
    nothing in the environment carries run state - the filters are pure and the
    data all arrives through render(). Rebuilding it per call charged a
    --redact run for two compiles of the same template and the render tests for
    one apiece.

    autoescape must be unconditional: select_autoescape matches by file
    extension and this template ends in .j2, which silently disabled it.
    """
    env = Environment(
        loader=PackageLoader("vcf_automation_assessment_tool.report", "templates"),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["sev_class"] = lambda s: s.value if isinstance(s, Severity) else str(s)
    env.filters["mark_dates"] = _mark_dates
    env.filters["detail_markup"] = _detail_markup
    env.filters["readable_date"] = _readable_date
    env.filters["plural"] = lambda count, word: word if count == 1 else word + "s"
    return env.get_template("report.html.j2")


def _replacement_view(findings: list) -> dict:
    """Use visible finding evidence so exclusions and redaction also apply here."""
    rows = []
    for finding in findings:
        if finding.check_id != "REP-001":
            continue
        for obj in finding.affected:
            lines = obj.detail.splitlines()
            fields = dict(line.split(": ", 1) for line in lines if ": " in line)
            complexity = lines[0].removeprefix("difficulty=").title()
            count = fields.get("deployments", "Unknown")
            rows.append(
                {
                    "name": obj.name,
                    "project": obj.project,
                    "complexity": complexity,
                    "reason": fields.get("reason", "Review source evidence"),
                    "deployments": int(count) if count.isdecimal() else None,
                    "target": fields.get("target", "Review source content"),
                }
            )
    return {
        "rows": rows,
        "counts": {
            label: sum(r["complexity"] == label for r in rows)
            for label in ("Low", "Medium", "High", "Needs Review")
        },
        "deployments": (
            sum(r["deployments"] for r in rows)
            if all(r["deployments"] is not None for r in rows)
            else None
        ),
    }


def build_html(data: AssessmentData) -> str:
    """The whole report as one string.

    Separate from writing it so a redacted copy can be inspected before it
    reaches the disk: a report that only looks redacted must never exist as a
    file somebody can send on.
    """
    # Ignored findings and hidden sections leave the report but stay in
    # data.findings, so the --json dump still carries them - the same rule
    # built-in subscriptions follow. What was withheld is named in the report
    # header: content the reader cannot see mentioned is a silent edit.
    ignored = {str(i).strip().upper() for i in data.meta.get("ignore_findings") or []}
    hidden_sections = sorted(
        {str(s).strip().lower() for s in data.meta.get("ignore_sections") or []}
    )
    shown = visible_findings(data.findings, ignored, hidden_sections)
    insights = {f.check_id: finding_insight(f) for f in shown}
    coverage = coverage_rows(data)
    suppressed = sorted({f.check_id for f in data.findings if f.check_id.upper() in ignored})
    visible = {key: key not in hidden_sections for key in (*SECTION_PREFIXES, "summary")}

    findings_by_section: dict[str, list] = {s: [] for s in SECTION_PREFIXES}
    for f in shown:
        findings_by_section.setdefault(_section_for(f.check_id), []).append(f)

    # Per-chapter tally for the Findings sub-heading, so the shape of a
    # section's findings reads off the rail without opening a card.
    section_severity_counts = {
        key: {
            sev.value: sum(1 for f in items if f.severity is sev)
            for sev in (Severity.CRITICAL, Severity.WARNING, Severity.INFO)
        }
        for key, items in findings_by_section.items()
    }

    policies_by_type: dict[str, list[dict]] = {}
    for p in data.raw.get("governance", {}).get("policies", []):
        key = (p.get("typeId") or "unknown").rsplit(".", 1)[-1]
        policies_by_type.setdefault(key, []).append(p)
    policies_by_type = {k: _display_sorted(v, "name") for k, v in policies_by_type.items()}

    # A diagram of an item nothing reacts to would show an empty timeline, and
    # at estate scale those rows drown the items where something does happen.
    # Items with no reacting subscription are listed compactly instead, and
    # both groups sort by name so an item can be found without scanning.
    flows = data.derived.get("flows", [])
    reacting = sorted(
        (f for f in flows if f.get("concerns")),
        key=lambda f: (f.get("item_name") or "").casefold(),
    )
    flow_sections = _flow_sections(reacting)
    flows_without_subs = sorted(
        (f for f in flows if not f.get("concerns")),
        key=lambda f: (f.get("item_name") or "").casefold(),
    )
    all_subs = data.raw.get("extensibility", {}).get("subscriptions", [])
    if data.meta.get("include_system_subscriptions"):
        subscriptions = all_subs
    else:
        subscriptions = [s for s in all_subs if not s.get("builtin")]
    subscriptions = _display_sorted(subscriptions, "name")
    hidden_system_subs = len(all_subs) - len(subscriptions)

    from ..checks.deployments import content_names
    from ..checks.governance import subscription_criteria_refs
    from ..placement import tag_consumer_labels, template_placements

    pedantic = bool(data.meta.get("pedantic"))
    estate = _estate_glance(data)
    project_docs = data.raw.get("infrastructure", {}).get("projects") or []
    identity_raw = data.raw.get("identity", {})
    owners = _owner_rollup(
        data.raw.get("deployments", {}).get("deployments", []), project_docs, identity_raw
    )
    tag_assignments = _tag_assignments(data.derived.get("capability_tags", {}))
    tag_consumers = tag_consumer_labels(data)
    criteria_refs = subscription_criteria_refs(data)
    extensibility_view, abx_run_evidence = _abx_run_view(data.raw.get("extensibility", {}))
    extensibility_view = {
        **extensibility_view,
        "abx_actions": _with_signal_counts(
            _display_sorted(extensibility_view.get("abx_actions"), "name"), pedantic
        ),
    }
    # Only the templates whose placement resolution is worth seeing: one a
    # constraint cannot be satisfied on, or one that resolves to a single
    # place. The note carries what was left out, so the reader is never
    # silently short of a template.
    placements, placement_note = template_placements(data)
    placement_diagrams = [
        {"placement": p, "mermaid": diagrams.placement_diagram(p)}
        for p in placements[:MAX_PLACEMENT_DIAGRAMS]
    ]
    placement_truncated = max(0, len(placements) - MAX_PLACEMENT_DIAGRAMS)

    design_raw = data.raw.get("blueprints", {})
    bindings_by_owner: dict[str, list[dict]] = {}
    for b in data.raw.get("vro", {}).get("custom_resource_bindings") or []:
        bindings_by_owner.setdefault(b.get("owner_id") or "", []).append(
            {
                "action": b.get("action", ""),
                "runs": b.get("runnable_name") or b.get("runnable_id", ""),
                "kind": b.get("kind", ""),
                "confirmed": b.get("confirmed"),
            }
        )
    design_view = {
        "property_groups": _display_sorted(design_raw.get("property_groups"), "name"),
        "custom_resource_types": [
            {**c, "bindings": bindings_by_owner.get(c.get("id") or "", [])}
            for c in _display_sorted(
                design_raw.get("custom_resource_types"), "displayName", "resourceType"
            )
        ],
        # Stable display order for same-named day-2 actions on different types.
        "custom_resource_actions": [
            {**c, "bindings": bindings_by_owner.get(c.get("id") or "", [])}
            for c in _display_sorted(
                design_raw.get("custom_resource_actions"),
                "displayName",
                "name",
                secondary="resourceType",
            )
        ],
        "bindings_shown": bool(bindings_by_owner),
    }
    governance_view = {
        **data.raw.get("governance", {}),
        "approval_policies": _display_sorted(
            data.raw.get("governance", {}).get("approval_policies"), "name"
        ),
        # Requests list newest first - the pending ones a reader chases are
        # almost always the recent ones.
        "approval_requests": sorted(
            data.raw.get("governance", {}).get("approval_requests") or [],
            key=lambda a: a.get("createdAt") or "",
            reverse=True,
        ),
    }
    gate_chains, approval_gates_note = _approval_gates(
        data.raw.get("governance", {}).get("approval_policies", []),
        data.derived.get("project_names", {}),
    )
    approval_gates = [
        {"chain": c, "mermaid": diagrams.approval_gates_diagram(c)} for c in gate_chains
    ]

    machine_groups = machines_by_project(
        data.raw.get("deployments", {}).get("deployments", []),
        data.derived.get("project_names", {}),
    )
    infra_raw = data.raw.get("infrastructure", {})
    infra = {
        **infra_raw,
        "cloud_accounts": _display_sorted(
            _with_endpoint_meta(infra_raw.get("cloud_accounts")), "name"
        ),
        "integrations": _display_sorted(_with_endpoint_meta(infra_raw.get("integrations")), "name"),
        "zones": _display_sorted(infra_raw.get("zones"), "name"),
        "network_profiles": _display_sorted(infra_raw.get("network_profiles"), "name"),
        "ip_ranges": _display_sorted(ip_range_usage(infra_raw.get("network_ip_ranges")), "name"),
        "external_ip_ranges": _display_sorted(infra_raw.get("external_network_ip_ranges"), "name"),
        "storage_profiles": _display_sorted(infra_raw.get("storage_profiles"), "name"),
        "projects": _display_sorted(infra_raw.get("projects"), "name"),
        "flavor_profiles": _display_sorted(
            _with_region_labels(infra_raw.get("flavor_profiles"), infra_raw),
            "name",
            secondary="region_label",
        ),
        "image_profiles": _display_sorted(
            _with_region_labels(infra_raw.get("image_profiles"), infra_raw),
            "name",
            secondary="region_label",
        ),
    }

    zone_allocation_rows, zone_allocation_columns = _zone_allocation_view(infra_raw)

    access_patterns = data.derived.get("catalog_access", [])

    # The per-finding row cap travels in meta (set from config/CLI by the cli
    # module) so a --json dump records what the accompanying HTML was capped
    # at; anything unusable falls back to the default rather than erroring.
    cap = data.meta.get("max_rows_per_finding")
    max_rows = cap if isinstance(cap, int) and cap > 0 else MAX_ROWS_PER_FINDING

    html = _template().render(
        report_js=resources.files(__package__)
        .joinpath("static/report.js")
        .read_text(encoding="utf-8"),
        data=data,
        meta=data.meta,
        findings=shown,
        insights=insights,
        replacement=_replacement_view(shown),
        coverage=coverage,
        coverage_limited=sum(r["status"] != "Collected" for r in coverage),
        finding_projects=sorted(
            {a.project for f in shown for a in f.affected if a.project}, key=str.casefold
        ),
        findings_by_section=findings_by_section,
        visible=visible,
        hidden_sections=hidden_sections,
        section_severity_counts=section_severity_counts,
        suppressed_findings=suppressed,
        comparison=_comparison_view(data.derived.get("comparison"), ignored, hidden_sections),
        severity_counts={
            "critical": sum(1 for f in shown if f.severity is Severity.CRITICAL),
            "warning": sum(1 for f in shown if f.severity is Severity.WARNING),
            "info": sum(1 for f in shown if f.severity is Severity.INFO),
        },
        infra=infra,
        naming=naming_inventory(data),
        # Both of these feed a sentence the template writes when a table is
        # absent, so a missing key silently drops the explanation instead of
        # failing loudly.
        storage_profiles_read=not area_gap(data, "infrastructure", {"storage_profiles"}),
        vro_endpoint_phrase=_vro_endpoint_phrase(data.raw.get("vro", {}).get("endpoints")),
        zone_allocations=zone_allocation_rows,
        zone_allocation_columns=zone_allocation_columns,
        zone_allocations_pressured=sum(1 for r in zone_allocation_rows if r["pressured"]),
        capability_tags=data.derived.get("capability_tags", {}),
        blueprints=_display_sorted(data.raw.get("blueprints", {}).get("blueprints"), "name"),
        deployments=data.raw.get("deployments", {}).get("deployments", []),
        catalog_usage=catalog_usage_summary(data.raw.get("catalog", {}).get("items") or []),
        deployment_usage=deployment_usage_summary(
            data.raw.get("deployments", {}).get("deployments", [])
        ),
        owner_usage=owner_usage_summary(owners),
        machines_by_project=machine_groups,
        machine_columns=machine_columns(machine_groups),
        deleted_deployments=_display_sorted(data.raw.get("deployments", {}).get("deleted"), "name"),
        request_outcomes=request_outcome_summary(
            data.raw.get("deployments", {}).get("request_history"), *content_names(data)
        ),
        owner_columns=owner_columns(owners, project_docs, identity_raw),
        identity_groups=_identity_group_rows(identity_raw, data),
        secrets=secret_rows(data),
        secrets_use_known=not area_gap(data, "blueprints"),
        catalog={
            **data.raw.get("catalog", {}),
            "items": _display_sorted(data.raw.get("catalog", {}).get("items"), "name"),
            "sources": _display_sorted(data.raw.get("catalog", {}).get("sources"), "name"),
        },
        governance=governance_view,
        extensibility=extensibility_view,
        design=design_view,
        abx_run_evidence=abx_run_evidence,
        subscriptions=subscriptions,
        hidden_system_subs=hidden_system_subs,
        capability_map=data.derived.get("capability_map", []),
        policies_by_type=policies_by_type,
        policy_type_labels=POLICY_TYPE_LABELS,
        project_names=data.derived.get("project_names", {}),
        estate=estate,
        owners=owners,
        tag_assignments=tag_assignments,
        tag_consumers=tag_consumers,
        criteria_refs=criteria_refs,
        approval_gates=approval_gates,
        approval_gates_note=approval_gates_note,
        catalog_access=access_patterns,
        content_sharing=_display_sorted(data.derived.get("content_sharing"), "name"),
        item_type_labels=ITEM_TYPE_LABELS,
        deployment_status_words=DEPLOYMENT_STATUS_WORDS,
        vro={
            **data.raw.get("vro", {}),
            "workflows": _display_sorted(data.raw.get("vro", {}).get("workflows"), "name"),
            "actions": _with_signal_counts(
                _display_sorted(data.raw.get("vro", {}).get("actions"), "fqn"), pedantic
            ),
        },
        placement_diagrams=placement_diagrams,
        placement_note=placement_note,
        placement_truncated=placement_truncated,
        flow_sections=flow_sections,
        flows_without_subs=flows_without_subs,
        mermaid_js=_load_mermaid(),
        max_rows=max_rows,
    )
    return html


# What each concern's section says before its diagrams. The Request wording
# carries the honest caveat: those events fire for a build, a change and a
# teardown alike, and only a subscription that names the kind can be filed
# under it.
# The heading each section carries. Not derived from the concern title in the
# flow data: "Day 2 Changes" + " Flows" reads as a stutter, and the data's
# title has to stay a plain noun phrase for the JSON dump.
CONCERN_SECTION_TITLES = {
    "provisioning": "Provisioning Flows",
    "day2": "Day 2 Change Flows",
    "disposal": "Disposal Flows",
    "request": "Unplaced Request Flows",
    "other": "Other Event Flows",
}

CONCERN_INTROS = {
    "provisioning": "What runs while a deployment is being built: the request "
    "that starts it, the allocation of a place, and the machines, networks "
    "and storage being provisioned and configured. The request events "
    "(deployment.request.*) also fire when somebody changes a deployment or "
    "takes it away, so a subscription on one of them may run at those times "
    "too. Where a subscription names the kind of request in its conditions, "
    "it is shown in that part of the life instead.",
    "day2": "What runs when somebody changes a deployment after it is built: "
    "a power action, a resize, a reconfiguration, or any other day-2 action "
    "on the deployment or one of its resources.",
    "disposal": "What runs while a deployment is being taken away, and what "
    "has to happen before the resources go: records removed from the CMDB "
    "and from monitoring, accounts and secrets withdrawn, addresses "
    "released.",
    "request": "Subscriptions on a request event whose conditions name more "
    "than one kind of request, or rule out a new deployment without saying "
    "what they leave in. The report will not file them under a part of the "
    "life their own conditions contradict, so they are shown on their own.",
    "other": "Events this report does not place in a stage of a deployment's "
    "life. They are shown so nothing attached to the item is left out.",
}


def _flow_sections(reacting: list[dict]) -> list[dict]:
    """One section per concern, each holding the items that have something in
    it and one diagram for each.

    An item appears in every concern it has subscriptions for, so the reader
    can ask "what happens when this is destroyed" and read one list rather
    than opening every item in turn. The cap is per section for the same
    reason: capping the whole set would drop a late concern entirely.
    """
    sections = []
    for key in flows.CONCERNS:
        items = [(f, c) for f in reacting for c in f["concerns"] if c["key"] == key]
        if not items:
            continue
        shown = items[:MAX_FLOW_DIAGRAMS]
        sections.append(
            {
                "key": key,
                "title": CONCERN_SECTION_TITLES[key],
                "intro": CONCERN_INTROS[key],
                "total": len(items),
                "truncated": len(items) - len(shown),
                "diagrams": [
                    {"flow": f, "concern": c, "mermaid": diagrams.flow_diagram(f, c)}
                    for f, c in shown
                ],
            }
        )
    return sections


@lru_cache(maxsize=1)
def template_source() -> str:
    """The template's own text.

    The redaction audit needs it: a word the report prints whatever the estate
    contains cannot be told apart from a value that leaked, so those words are
    left out of the residue scan instead of being reported as failures.
    """
    return (
        resources.files("vcf_automation_assessment_tool.report")
        .joinpath("templates/report.html.j2")
        .read_text(encoding="utf-8")
    )


_ISO_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")


BULLET = "\u2022 "
# A list of five is quicker to read than to open. Past that it is evidence
# for the reader who has decided to act, and it buries the sentences above it.
MAX_INLINE_BULLETS = 5


def _detail_markup(text: str) -> Markup:
    """An affected object's detail, with a long bullet list folded away.

    The cell keeps white-space: pre-line, so the lines inside the fold need
    no markup of their own.
    """
    lines = (text or "").split("\n")
    out: list[str] = []
    run: list[str] = []

    def flush() -> None:
        if not run:
            return
        body = escape("\n".join(run))
        if len(run) > MAX_INLINE_BULLETS:
            out.append(f'<details class="names"><summary>Show {len(run)}</summary>{body}</details>')
        else:
            out.append(str(body))
        run.clear()

    for line in lines:
        if line.startswith(BULLET):
            run.append(line)
            continue
        flush()
        out.append(str(escape(line)))
    flush()
    return Markup("\n".join(out))


def _mark_dates(text: object) -> Markup:
    """Escape text, then bold ISO dates so they stand out in finding prose.

    Escapes first so the emphasis markup is the only HTML that survives -
    applied to recommendation lines, where a date is always load-bearing
    (currently EXT-006's retained-history floor).
    """
    return Markup(_ISO_DATE_RE.sub(r"<strong>\g<0></strong>", str(escape(str(text)))))


def _display_sorted(items: list | None, *name_keys: str, secondary: str | None = None) -> list:
    """Alphabetical, case-insensitive display order for inventory tables.

    Applied at the render boundary only - raw data and the --json dump keep
    collection order. The first non-empty name key is the label (matching
    what the table shows); `secondary` breaks ties between identically
    labelled rows (unnamed flavor profiles telling apart only by region),
    and the id keeps the order stable beyond that.
    """

    def key(item: dict) -> tuple:
        label = ""
        for k in name_keys:
            value = item.get(k)
            if value:
                label = str(value).casefold()
                break
        tiebreak = str(item.get(secondary) or "").casefold() if secondary else ""
        return (label, tiebreak, str(item.get("id") or ""))

    return sorted(items or [], key=key)


def _with_signal_counts(actions: list | None, pedantic: bool) -> list:
    """Stamp each action with the number of quality signals the report counts.

    Hygiene-level signals are always collected but only count under
    --pedantic, so the table column and the findings never disagree about how
    many signals an action has.
    """
    out = []
    for a in actions or []:
        count = len(a.get("issues") or [])
        if pedantic:
            count += len(a.get("pedantic_issues") or [])
        out.append({**a, "signal_count": count})
    return out


def _abx_run_view(extensibility: dict) -> tuple[dict, dict]:
    """(extensibility view with last_run_label on ABX actions, evidence view).

    Labels only exist when the run history was collected; with a complete
    history an unseen action says "none recorded", with a truncated one the
    cell stays empty - not seen in a partial sample proves nothing. Same
    id-dialect guard as EXT-006: when runs exist but none maps onto any
    inventoried action id, matching cannot be trusted, so the evidence view
    comes back empty and the Last run column stays hidden (a live build
    returned name-like run actionIds where the inventory may hold UUIDs).
    """
    evidence = extensibility.get("abx_run_evidence") or {}
    if not evidence.get("collected"):
        return extensibility, {}
    by_action = evidence.get("by_action") or {}
    action_ids = {a.get("id") for a in extensibility.get("abx_actions", []) if a.get("id")}
    if by_action and action_ids and not (action_ids & set(by_action)):
        log.warning(
            "ABX run history action ids match no inventoried action id; "
            "Last run column and never-run analysis withheld"
        )
        return extensibility, {}
    complete = bool(evidence.get("complete"))
    actions = []
    for a in extensibility.get("abx_actions", []):
        info = by_action.get(a.get("id"))
        if info and info.get("last_millis"):
            day = datetime.fromtimestamp(info["last_millis"] / 1000, tz=UTC).strftime("%Y-%m-%d")
            # Non-breaking space: the cell reads as one token instead of
            # wrapping the state onto its own line in a narrow column.
            label = f"{day} ({info.get('last_state') or '?'})"
        elif info:
            label = f"{info.get('count', 0)} run(s)"
        else:
            label = "none recorded" if complete else ""
        actions.append({**a, "last_run_label": label})
    view = dict(evidence)
    if evidence.get("oldest_run_millis"):
        view["oldest_run_label"] = datetime.fromtimestamp(
            evidence["oldest_run_millis"] / 1000, tz=UTC
        ).strftime("%Y-%m-%d")
    return {**extensibility, "abx_actions": actions}, view


def _with_endpoint_meta(items: list | None) -> list[dict]:
    """Shallow-copied cloud accounts / integrations with status_label and
    tag_label for the inventory tables. status_label stays empty when the
    build's API exposes no health signal on the document (the Status column is
    only shown when at least one row has one)."""
    return [
        {
            **obj,
            "status_label": endpoint_status(obj) or "",
            "tag_label": ", ".join(normalize_tag(t) for t in obj.get("tags") or []),
        }
        for obj in items or []
    ]


def _with_region_labels(profiles: list | None, infra: dict) -> list[dict]:
    """Shallow-copied flavor/image profiles with a region_label field.

    Profiles are per-region objects whose name is optional in the API - a
    real estate rendered 12 of 17 flavor profiles as "(unnamed profile)" and
    held five image profiles all called RHEL9. Cloud account + region is the
    only reliable way to tell such rows apart, resolved via the profile's
    region link against the collected /iaas/api/regions list; falls back to
    the profile's own externalRegionId when regions were not collectable.
    """
    accounts = {a.get("id"): a.get("name", "") for a in infra.get("cloud_accounts", [])}
    regions = {}
    for r in infra.get("regions", []):
        account = accounts.get(r.get("cloudAccountId") or "", "")
        ext = r.get("externalRegionId") or r.get("name") or ""
        regions[r.get("id", "")] = " / ".join(x for x in (account, ext) if x)
    out = []
    for p in profiles or []:
        href = ((p.get("_links") or {}).get("region") or {}).get("href", "")
        rid = href.rstrip("/").rsplit("/", 1)[-1] if href else ""
        label = regions.get(rid) or p.get("externalRegionId") or ""
        out.append({**p, "region_label": label})
    return out


def _allocation_cell(entry: dict, unit: str) -> str:
    """One used-of-limit cell. Says nothing it cannot support: an assignment
    reporting neither a limit nor a use of one prints a dash rather than a
    zero, and a share is only shown when both halves are known."""
    used, limit, ratio = entry["used"], entry["limit"], entry["ratio"]
    suffix = f" {unit}" if unit else ""
    if limit is None:
        return f"{format_amount(used)}{suffix} used, no limit" if used is not None else "-"
    used_text = format_amount(used) if used is not None else "?"
    cell = f"{used_text} / {format_amount(limit)}{suffix}"
    if ratio is None:
        return cell
    if ratio > 1:
        return f"{cell} (over limit)"
    if ratio >= 1:
        return f"{cell} (full)"
    return f"{cell} ({ratio:.0%})"


def _zone_allocation_view(infra: dict) -> tuple[list[dict], list[dict]]:
    """Rows for the project zone allocation table, and the limit columns worth
    showing.

    A column appears only where some assignment sets that limit or has taken
    something against it. The live estate sets no storage limit anywhere and a
    CPU limit on 19 of 423 assignments, so a fixed four-column table would be
    mostly empty cells that read as a collection failure - the same rule the
    endpoint Status and zone tagsToMatch columns follow. A counter sitting at
    zero with no limit beside it is not a use of that quota, so it does not
    earn its column either.
    """
    zone_names = {z.get("id", ""): z.get("name", "") for z in infra.get("zones", [])}
    rows = zone_allocations(infra.get("projects", []), zone_names)
    columns = [
        {"key": key, "label": f"{label} ({unit})" if unit else label}
        for key, _limit_field, _used_field, label, unit in ZONE_LIMITS
        if any(
            r["limits"][key]["limit"] is not None or (r["limits"][key]["used"] or 0) > 0
            for r in rows
        )
    ]
    units = {key: unit for key, _lf, _uf, _label, unit in ZONE_LIMITS}
    view = []
    for row in sorted(
        rows, key=lambda r: ((r["project"] or "").lower(), (r["zone"] or "").lower())
    ):
        view.append(
            {
                **row,
                "cells": [
                    _allocation_cell(row["limits"][c["key"]], units[c["key"]]) for c in columns
                ],
                "pressured": any(
                    (row["limits"][c["key"]]["ratio"] or 0) >= NEAR_LIMIT_RATIO for c in columns
                ),
            }
        )
    return view, columns


MAX_TAG_NAMES_PER_KIND = 12
MAX_APPROVAL_GATE_DIAGRAMS = 12


MAX_GATE_CONTEXTS_SHOWN = 8


def _approval_gates(policies: list[dict], project_names: dict) -> tuple[list[dict], str]:
    """Distinct approval gate chains, grouped like the access map's sharing
    patterns so estate scale stays readable.

    A request passes every approval policy that gates its action within its
    project - organization policies apply everywhere, project policies only
    in their own project - in level order. Actions guarded by an identical
    policy chain fold into one chain, and chains that are STRUCTURALLY
    identical (same actions and, per level, the same enforcement, mode,
    auto-expiry behaviour and criteria-presence) merge into one diagram even
    when the policies differ: the observed live pattern is one same-shaped
    approval policy per project with only the approvers changing, and that
    should draw once, not once per project. A merged gate says how many
    policies it stands for; per-policy approvers stay in the table. Policies
    with no readable action list are never guessed into a chain; they are
    named in the returned note instead (an empty list means "not readable",
    not "gates everything").
    """
    with_actions = [p for p in policies if p.get("actions")]
    unreadable = [p for p in policies if not p.get("actions")]
    org = [p for p in with_actions if not p.get("projectId")]
    by_project: dict[str, list[dict]] = {}
    for p in with_actions:
        if p.get("projectId"):
            by_project.setdefault(p["projectId"], []).append(p)
    pol_by_id = {p["id"]: p for p in with_actions}

    def level_key(p: dict):
        # Coerced: a build serving level as a string ("1") must sort with
        # ints, not TypeError the whole render.
        level = p.get("level")
        try:
            level = int(level)
        except (TypeError, ValueError):
            level = 10**6
        return (level, p.get("name") or "")

    def gate_sig(p: dict) -> tuple:
        return (
            p.get("level"),
            p.get("enforcementType") or "",
            p.get("approvalMode") or "",
            p.get("autoApprovalDecision") or "",
            p.get("autoApprovalExpiry"),
            bool(p.get("scopeCriteria")),
        )

    # Contexts carry the project name apart from its wording so the header
    # can count them ("20 projects: A, B, ...") instead of repeating the word
    # "project" once per name, which is what made the live header a run-on.
    contexts: list[tuple[tuple[str, str], list[dict]]] = []
    for pid, plist in sorted(by_project.items(), key=lambda kv: project_names.get(kv[0], kv[0])):
        contexts.append((("project", project_names.get(pid, pid) or pid), org + plist))
    if org:
        contexts.append((("all", "every other project" if by_project else "all projects"), org))

    grouped: dict[tuple, dict] = {}
    for label, applicable in contexts:
        by_chain: dict[tuple, list[str]] = {}
        for action in sorted({a for p in applicable for a in p["actions"]}):
            gates = sorted((p for p in applicable if action in p["actions"]), key=level_key)
            by_chain.setdefault(tuple(p["id"] for p in gates), []).append(action)
        for gate_ids, actions in sorted(by_chain.items(), key=lambda kv: kv[1]):
            sig = (tuple(actions), tuple(gate_sig(pol_by_id[i]) for i in gate_ids))
            entry = grouped.setdefault(sig, {"contexts": [], "actions": actions, "id_rows": []})
            entry["contexts"].append(label)
            entry["id_rows"].append(gate_ids)

    def context_label(labels: list[tuple[str, str]]) -> str:
        projects = [name for kind, name in labels if kind == "project"]
        parts = []
        if len(projects) == 1:
            parts.append(f"project {projects[0]}")
        elif projects:
            shown = projects[:MAX_GATE_CONTEXTS_SHOWN]
            more = len(projects) - len(shown)
            parts.append(
                f"{len(projects)} projects: "
                + ", ".join(shown)
                + (f" (+{more} more)" if more else "")
            )
        parts += [name for kind, name in labels if kind != "project"]
        return "; ".join(parts)

    chains = []
    for (actions, sigs), entry in grouped.items():
        slots = []
        for pos, (level, enforcement, mode, decision, expiry, has_criteria) in enumerate(sigs):
            ids = {row[pos] for row in entry["id_rows"]}
            slots.append(
                {
                    "count": len(ids),
                    "policy": pol_by_id[next(iter(ids))] if len(ids) == 1 else None,
                    "level": level,
                    "enforcementType": enforcement,
                    "approvalMode": mode,
                    "autoApprovalDecision": decision,
                    "autoApprovalExpiry": expiry,
                    "scope_criteria": has_criteria,
                }
            )
        chains.append(
            {
                "context": context_label(entry["contexts"]),
                "actions": list(actions),
                "gates": slots,
            }
        )
    notes = []
    if len(chains) > MAX_APPROVAL_GATE_DIAGRAMS:
        notes.append(
            f"{len(chains) - MAX_APPROVAL_GATE_DIAGRAMS} more gate chain(s) not shown; "
            "the Approval Policies table above is complete."
        )
        chains = chains[:MAX_APPROVAL_GATE_DIAGRAMS]
    if unreadable:
        names = ", ".join(sorted(p.get("name") or "?" for p in unreadable))
        notes.append(
            f"No readable action list on: {names} - their gates are not drawn "
            "(an unreadable list is not read as gating everything)."
        )
    return chains, " ".join(notes)


def _tag_assignments(capability_tags: dict) -> list[dict]:
    """Group each tag's assignments by object kind, one line per kind.

    The raw list can repeat an object (one per collection path - e.g. a
    fabric network seen by two cloud accounts) and reads as a run-on at
    fabric scale. Objects merge by (kind, name) with their vias folded into
    one annotation; the plain "capability tag" via is implied by the table
    and dropped, while constraint-type vias stay visible. A note shared by
    every member of a multi-name group is hoisted into the group head instead
    of repeating per name (a live estate suffixed all 12 accounts on one tag
    with the same inheritance note). Names cap at MAX_TAG_NAMES_PER_KIND per
    line.
    """
    rows = []
    for tag, uses in sorted(capability_tags.items()):
        merged: dict[tuple, set] = {}
        for u in uses:
            key = (u.get("kind") or "?", u.get("name") or "?")
            merged.setdefault(key, set()).add(u.get("via") or "")
        by_kind: dict[str, list[tuple[str, tuple[str, ...]]]] = {}
        for (kind, name), vias in sorted(merged.items()):
            notes = tuple(sorted(v for v in vias if v and v != "capability tag"))
            by_kind.setdefault(kind, []).append((name, notes))
        lines = []
        for kind, entries in sorted(by_kind.items()):
            note_sets = {notes for _, notes in entries}
            shared = next(iter(note_sets)) if len(note_sets) == 1 else ()
            if shared and len(entries) > 1:
                names = [name for name, _ in entries]
                head = f"{kind} ({len(entries)}; {', '.join(shared)})"
            else:
                names = [
                    f"{name} ({', '.join(notes)})" if notes else name for name, notes in entries
                ]
                head = f"{kind} ({len(entries)})"
            shown = names[:MAX_TAG_NAMES_PER_KIND]
            more = len(names) - len(shown)
            suffix = f" (+{more} more)" if more else ""
            lines.append(f"{head}: {', '.join(shown)}{suffix}")
        rows.append({"tag": tag, "lines": lines})
    return rows


def _vro_endpoint_phrase(endpoints: list[dict] | None) -> str:
    """Where the workflows were looked up, as a phrase a sentence can hold.

    An external endpoint's source is the integration's own name, so the raw
    values ("embedded", "external-vRO") joined by commas read as a broken list
    rather than as the two Orchestrators they name.
    """
    labels = []
    for endpoint in endpoints or []:
        source = (endpoint.get("source") or "").strip()
        if source == "embedded":
            label = "the embedded Orchestrator"
        elif source:
            label = f"the {source} integration"
        else:
            label = "an unnamed integration"
        if not endpoint.get("reachable"):
            label += " (unreachable)"
        labels.append(label)
    if len(labels) < 2:
        return labels[0] if labels else ""
    return f"{', '.join(labels[:-1])} and {labels[-1]}"


def _identity_group_rows(identity: dict, data) -> list[dict]:
    """One row per group a project grants to, expanded or not.

    Groups the organization does not list are kept in the table rather than
    dropped: a grant nobody can verify is worth seeing, and leaving it out
    would make the access column's gaps unexplainable.
    """
    if not (identity or {}).get("collected"):
        return []
    names = data.derived.get("project_names", {})

    def labelled(ids):
        # An id with no name is a project that has gone; show enough of it
        # to be recognisable rather than dropping the grant from the table.
        return ", ".join(names.get(pid) or f"(unknown project {pid[:8]})" for pid in ids)

    rows = [
        {
            "name": g.get("name") or g.get("principal"),
            "projects": labelled(g.get("projects") or []),
            "project_count": len(g.get("projects") or []),
            "members": len(g.get("members") or []),
            "members_note": (
                ""
                if g.get("members_complete")
                else (
                    f"{g.get('members_claimed')} expected"
                    if g.get("members_read")
                    else "not readable"
                )
            ),
            "roles": ", ".join(g.get("elevated_roles") or []),
        }
        for g in identity.get("groups") or []
    ]
    rows += [
        {
            "name": u.get("principal"),
            "projects": labelled(u.get("projects") or []),
            "project_count": len(u.get("projects") or []),
            "members": "",
            "members_note": "group not listed by the organization",
            "roles": "",
        }
        for u in identity.get("unresolved") or []
    ]
    return sorted(rows, key=lambda r: (-r["project_count"], r["name"]))


def _comparison_view(comparison: dict | None, ignored: set[str], hidden_sections=()) -> dict | None:
    """The run-over-run block, minus the findings the report is told to ignore.

    Unchanged findings are counted, not listed: the block exists to show
    movement. An ignored id leaves the block the way it leaves the report,
    or the reader would meet a check id they cannot find below.
    """
    if not comparison:
        return None
    rows = [
        r
        for r in comparison.get("findings", [])
        if r["check_id"].upper() not in ignored
        and _home_section(r["check_id"]) not in hidden_sections
    ]
    return {
        **comparison,
        "rows": [r for r in rows if r["status"] != "unchanged"],
        "unchanged": sum(1 for r in rows if r["status"] == "unchanged"),
        "summary": {
            **{
                status: sum(r["status"] == status for r in rows)
                for status in ("new", "resolved", "changed", "unchanged", "unable_to_reassess")
            },
            "objects_added": sum(len(r["new_names"]) for r in rows),
            "objects_resolved": sum(len(r["resolved_names"]) for r in rows),
        },
    }


def _readable_date(value) -> str:
    """Keep date-only evidence intact; show timestamps with an explicit timezone."""
    text = str(value or "")
    if len(text) <= 10:
        return text
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    zone = stamp.strftime("UTC%z") if stamp.tzinfo else "(timezone unknown)"
    if zone == "UTC+0000":
        zone = "UTC"
    return stamp.strftime("%d %b %Y, %H:%M:%S ") + zone


def machines_by_project(deployments, project_names) -> list[dict]:
    """One row per machine resource, grouped by the deployment's project.

    Only what the collector already keeps, so nothing here costs a call. A
    project the estate no longer lists keeps an id-derived label, the same
    as the access map, rather than swallowing its machines into "(no project)".
    """
    groups: dict[str, list[dict]] = {}
    for dep in deployments or []:
        project_id = dep.get("projectId") or ""
        project = (
            dep.get("projectName")
            or project_names.get(project_id)
            or (f"(unknown project {project_id[:8]})" if project_id else "(no project)")
        )
        for res in dep.get("resources") or []:
            if not is_machine(res.get("type") or ""):
                continue
            groups.setdefault(project, []).append(
                {
                    "machine": res.get("hostname") or res.get("name") or "",
                    "deployment": dep.get("name") or "",
                    "power_state": res.get("powerState") or "",
                    "address": res.get("address") or "",
                    "sync_status": res.get("syncStatus") or "",
                    "owner": dep.get("ownedBy") or "",
                    "created": (dep.get("createdAt") or "")[:10],
                }
            )
    out = []
    for project in sorted(groups, key=str.lower):
        rows = sorted(
            groups[project], key=lambda r: (r["deployment"].lower(), r["machine"].lower())
        )
        out.append({"project": project, "machines": rows})
    return out


def machine_columns(groups: list[dict]) -> dict[str, bool]:
    """Which optional machine columns any row fills. A column nothing fills
    reads as data the collection lost, so it is not drawn (the endpoint
    Status column rule)."""
    rows = [m for g in groups for m in g["machines"]]
    return {
        "address": any(m["address"] for m in rows),
    }


def _owner_rollup(
    deployments: list[dict],
    projects: list[dict] | None = None,
    identity: dict | None = None,
) -> list[dict]:
    """Deployments, machines, last activity and project access per owner.

    Ownership concentration is a bus-factor and handover signal; the owner is
    whatever the deployment records. No identity lookup is attempted - the API
    holds principals that were granted something, not the directory, so it
    cannot say whether an account still exists. What it can say is whether the
    owner still holds a role in the projects their deployments live in, which
    is the actionable half of the question.
    """
    from ..checks.deployments import is_machine

    index = principal_index(projects or [], identity)
    rollup: dict[str, dict] = {}
    for d in deployments:
        owner = d.get("ownedBy") or UNKNOWN_OWNER
        entry = rollup.setdefault(
            owner,
            {
                "owner": owner,
                "deployments": 0,
                "machines": 0,
                "projects": set(),
                "last_activity": "",
            },
        )
        entry["deployments"] += 1
        entry["machines"] += sum(1 for r in d.get("resources", []) if is_machine(r.get("type", "")))
        entry["projects"].add(d.get("projectId") or "")
        # Timestamps are ISO-8601 in UTC, so string order is time order.
        stamp = d.get("lastUpdatedAt") or d.get("createdAt") or ""
        entry["last_activity"] = max(entry["last_activity"], stamp)
    owners = []
    for entry in rollup.values():
        project_ids = entry.pop("projects")
        access, state = "", ""
        if has_evidence(index) and entry["owner"] != UNKNOWN_OWNER:
            access, state = owner_access(entry["owner"], project_ids, index)
        owners.append(
            {
                **entry,
                "last_activity": entry["last_activity"][:10],
                "access": access,
                "access_state": state,
            }
        )
    return sorted(owners, key=lambda e: (-e["deployments"], -e["machines"], e["owner"]))


def owner_columns(
    owners: list[dict],
    projects: list[dict] | None = None,
    identity: dict | None = None,
) -> dict:
    """Which optional owner columns have anything to say, and the caveats the
    access column needs. A column with no data in any row is not rendered."""
    index = principal_index(projects or [], identity)
    return {
        "activity": any(o.get("last_activity") for o in owners),
        "access": any(o.get("access") for o in owners),
        "via_groups": len(index["resolved_groups"]),
        # Named separately because they are the reason some owners can only be
        # reported as undetermined.
        "unreadable_groups": len(index["unreadable_groups"]),
    }


# Items carrying the top share of demand. Three is enough to show whether a
# catalog is one item wearing a hat or a genuinely broad service offering.
CATALOG_CONCENTRATION_ITEMS = 3

# Owners counted in the concentration figure, for the same reason.
OWNER_CONCENTRATION_NAMES = 3


def request_outcome_summary(
    history: dict | None,
    item_names: dict[str, str] | None = None,
    blueprint_names: dict[str, str] | None = None,
) -> dict | None:
    """What the request history says about failure, and over what window.

    None when the history was not collected - which is not the same as a clean
    record, and the report says so where this returns None.
    """
    from ..checks.deployments import request_completed, request_failed, request_target_label

    if not (history or {}).get("collected"):
        return None
    requests = history.get("requests") or []
    by_status: dict[str, int] = {}
    for req in requests:
        status = (req.get("status") or "(none)").upper()
        by_status[status] = by_status.get(status, 0) + 1
    failed = sum(1 for r in requests if request_failed(r.get("status")))
    # The denominator is requests that finished one way or the other. A
    # cancelled or rejected request did not fail, and counting it as one
    # inflates the rate with the platform behaving exactly as instructed.
    completed = sum(1 for r in requests if request_completed(r.get("status")))
    # What failed, grouped by what was asked for: a template failing twenty
    # times is a defect at the source, twenty different ones are an estate
    # problem.
    targets: dict[str, dict] = {}
    for req in requests:
        if not request_completed(req.get("status")):
            continue
        what = request_target_label(req, item_names or {}, blueprint_names or {})
        entry = targets.setdefault(what, {"what": what, "completed": 0, "failed": 0})
        entry["completed"] += 1
        if request_failed(req.get("status")):
            entry["failed"] += 1
    # Volume first, because that is what a fix buys back the most of, but each
    # row carries its own rate: without it a template failing 13 of 18 sits
    # below one that failed 12 of 1165, and the reader has to divide.
    failing = sorted(
        (
            {**t, "rate": round(t["failed"] * 100 / t["completed"]) if t["completed"] else 0}
            for t in targets.values()
            if t["failed"]
        ),
        key=lambda t: (-t["failed"], t["what"]),
    )
    return {
        "total": len(requests),
        "failed": failed,
        "completed": completed,
        "uncounted": len(requests) - completed,
        "failed_pct": round(failed * 100 / completed) if completed else 0,
        "by_status": sorted(by_status.items()),
        "failing_targets": failing[:10],
        "window_from": (history.get("oldest") or "")[:10],
        "deployments_scanned": history.get("deployments_scanned") or 0,
        "deployments_unread": history.get("deployments_unread") or 0,
    }


def deployment_usage_summary(deployments: list[dict]) -> dict | None:
    """The size and health of what is actually running.

    The status table below it answers "in what state"; these answer "how much,
    and how much of it is broken", which is the pair of numbers a stakeholder
    asks for first. None when nothing is deployed.
    """
    from ..checks.deployments import FAILED_STATUSES, is_machine

    if not deployments:
        return None
    failed = sum(
        1
        for d in deployments
        if (d.get("status") or "") in FAILED_STATUSES or (d.get("status") or "").endswith("_FAILED")
    )
    return {
        "deployment_count": len(deployments),
        "machines": sum(
            1
            for d in deployments
            for r in d.get("resources") or []
            if is_machine(r.get("type", ""))
        ),
        "failed": failed,
        "projects": len({d.get("projectId") or "" for d in deployments}),
    }


def owner_usage_summary(owners: list[dict]) -> dict | None:
    """Ownership concentration: the bus-factor number the table implies.

    The table is sorted heaviest-first, so a reader can see one name at the
    top - but not what share it holds, which is the part that matters for
    handover planning. None when nothing is deployed.
    """
    if not owners:
        return None
    counts = sorted((o.get("deployments") or 0 for o in owners), reverse=True)
    total = sum(counts)
    summary = {"owner_count": len(owners), "total_deployments": total}
    # An owner recorded as unknown is a gap in the data, not a person, so it
    # is called out rather than folded into the concentration figure.
    unknown = next(
        (o.get("deployments") or 0 for o in owners if o.get("owner") == UNKNOWN_OWNER), 0
    )
    if unknown:
        summary["unknown_owner_deployments"] = unknown
    if not total:
        return summary
    summary["top_owner"] = owners[0].get("owner")
    summary["top_owner_pct"] = round(counts[0] * 100 / total)
    # "the top 3 owners hold 100%" says nothing about an estate with three
    # owners - the same rule the catalog concentration follows.
    if len(counts) > OWNER_CONCENTRATION_NAMES:
        summary["concentration_names"] = OWNER_CONCENTRATION_NAMES
        summary["concentration_pct"] = round(sum(counts[:OWNER_CONCENTRATION_NAMES]) * 100 / total)
    return summary


def catalog_usage_summary(items: list[dict]) -> dict | None:
    """The four numbers a stakeholder wants from the catalog table.

    None when there is nothing ordered to summarise: percentages of zero read
    as facts about the estate rather than as an absence of data.
    """
    if not items:
        return None
    counts = sorted((i.get("deployment_count") or 0 for i in items), reverse=True)
    total = sum(counts)
    failed = sum(i.get("deployment_failed_count") or 0 for i in items)
    never = sum(1 for c in counts if not c)
    summary = {
        "item_count": len(items),
        "never_ordered": never,
        "total_deployments": total,
        "failed_deployments": failed,
    }
    if total:
        summary["failed_pct"] = round(failed * 100 / total)
        # "the top 3 items account for 100%" says nothing when the catalog
        # holds three items. Concentration is only a claim about a catalog
        # wide enough for demand to concentrate within it.
        if len(counts) > CATALOG_CONCENTRATION_ITEMS:
            top = sum(counts[:CATALOG_CONCENTRATION_ITEMS])
            summary["concentration_items"] = CATALOG_CONCENTRATION_ITEMS
            summary["concentration_pct"] = round(top * 100 / total)
    return summary


def _estate_glance(data) -> list[dict]:
    """Plain size-and-shape numbers for the executive summary strip.

    A tile whose area produced no data at all is omitted rather than showing
    a false zero: an area can still fail even though every one is collected.
    """
    from ..checks.deployments import is_machine

    # Keyed on the raw area each tile counts, so a tile is dropped exactly
    # when its area returned nothing at all.
    missing = {
        area
        for area in (
            "infrastructure",
            "deployments",
            "catalog",
            "blueprints",
            "extensibility",
            "vro",
            "governance",
        )
        if area not in data.raw
    }
    infra = data.raw.get("infrastructure", {})
    ext = data.raw.get("extensibility", {})
    deployments = data.raw.get("deployments", {}).get("deployments", [])
    machines = sum(
        1 for d in deployments for r in d.get("resources", []) if is_machine(r.get("type", ""))
    )
    tiles = [
        ("infrastructure", "Projects", len(infra.get("projects", []))),
        ("infrastructure", "Cloud zones", len(infra.get("zones", []))),
        ("deployments", "Deployments", len(deployments)),
        ("deployments", "Machines", machines),
        ("catalog", "Catalog items", len(data.raw.get("catalog", {}).get("items", []))),
        ("blueprints", "Templates", len(data.raw.get("blueprints", {}).get("blueprints", []))),
        (
            "extensibility",
            "Subscriptions",
            sum(1 for s in ext.get("subscriptions", []) if not s.get("builtin")),
        ),
        ("extensibility", "ABX actions", len(ext.get("abx_actions", []))),
        ("vro", "Orchestrator actions", len(data.raw.get("vro", {}).get("actions", []))),
        ("governance", "Policies", len(data.raw.get("governance", {}).get("policies", []))),
    ]
    return [{"label": label, "value": value} for area, label, value in tiles if area not in missing]


@lru_cache(maxsize=1)
def _load_mermaid() -> str | None:
    """Vendored mermaid.min.js, inlined so the report works air-gapped.

    Cached: it is 2.5 MB of package data that cannot change while the process
    lives, and every render used to read and decode it again.

    Returns None when the static file was not bundled; the template then falls
    back to showing raw mermaid source in <pre> blocks.
    """
    try:
        ref = resources.files("vcf_automation_assessment_tool.report") / "static" / "mermaid.min.js"
        return ref.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        log.warning("mermaid.min.js not bundled; diagrams will render as source text")
        return None
