"""Assessment coverage and comparability, independent of report presentation."""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

from .models import AssessmentData

AREA_LABELS = {
    "infrastructure": "Infrastructure and projects",
    "identity": "Group membership",
    "deployments": "Deployments and resources",
    "blueprints": "Templates and design",
    "catalog": "Catalog",
    "governance": "Policies and approvals",
    "extensibility": "Subscriptions and ABX",
    "vro": "Orchestrator",
}

# Deliberately conservative area-level dependencies. A partial area must not
# turn a withheld check into a resolution, even when its exact endpoint is unknown.
DEPENDENCIES = {
    "INF": {"infrastructure"},
    "PRJ": {"infrastructure"},
    "TAG": {"infrastructure", "blueprints", "catalog", "governance"},
    "DEP": {"deployments"},
    "CAT": {"catalog", "deployments", "governance", "infrastructure"},
    "BLU": {"blueprints"},
    "EXT": {"extensibility", "blueprints", "infrastructure", "vro"},
    "VRO": {"vro", "extensibility"},
    "APR": {"governance"},
    "POL": {"governance", "infrastructure", "catalog"},
    "REP": {"catalog", "blueprints", "extensibility", "vro", "infrastructure"},
    "SYS": set(AREA_LABELS),
}

CHECK_DEPENDENCIES = {
    "INF-007": {"infrastructure", "blueprints"},
    "PRJ-001": {"infrastructure", "deployments", "blueprints"},
    "PRJ-003": {"infrastructure", "identity"},
    "DEP-002": {"deployments", "blueprints", "catalog"},
    "DEP-009": {"deployments", "infrastructure", "identity"},
    "CAT-001": {"catalog", "deployments"},
    "CAT-002": {"catalog"},
    "CAT-003": {"catalog"},
    "EXT-003": {"extensibility"},
    "EXT-004": {"extensibility"},
    "EXT-006": {"extensibility"},
    "EXT-008": {"extensibility"},
    "REP-002": {"blueprints"},
}


@lru_cache(maxsize=1)
def ruleset_signature() -> str:
    """Fingerprint assessment code, including shared helpers and collectors.

    A presentation-only change does not invalidate an otherwise comparable run.
    The fingerprint also detects definition changes before a release version changes.
    """
    root = Path(__file__).parent
    paths = list(root.glob("*.py"))
    for directory in ("checks", "collectors"):
        paths.extend((root / directory).glob("*.py"))
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_text(encoding="utf-8").replace("\r\n", "\n").encode())
    return digest.hexdigest()


def coverage_rows(data: AssessmentData) -> list[dict]:
    """Known limitations, including optional collections that produced no error."""
    rows = []
    for area, label in AREA_LABELS.items():
        raw = data.raw.get(area)
        errors = [e for e in data.errors if e.get("area") == area]
        notes = [str(e.get("item") or "collection") for e in errors]
        status = "Collected" if isinstance(raw, dict) else "Not assessed"
        if errors:
            has_records = isinstance(raw, dict) and any(
                isinstance(v, list) and v for v in raw.values()
            )
            status = "Partial" if has_records else "Unavailable"
        raw = raw if isinstance(raw, dict) else {}
        if area == "identity":
            if not raw.get("collected") and not errors:
                status = "Not assessed"
                notes.append("Disabled, or no resolvable organisation/group grants to expand")
            elif raw.get("unresolved") or any(
                not g.get("members_complete", g.get("members_read", False))
                for g in raw.get("groups") or []
            ):
                status = "Partial"
                notes.append("Some group memberships could not be established")
        if area == "catalog" and raw.get("admin_scope") is False:
            status = "Partial"
            notes.append("Entitlement-scoped access; the item list may be incomplete")
        if area == "vro" and any(not w.get("resolved") for w in raw.get("workflows") or []):
            status = "Partial"
            notes.append("Some referenced workflows could not be resolved")
        if not notes:
            notes.append(
                "No collection errors recorded; access and API visibility still apply"
                if status == "Collected"
                else "No collection evidence available"
            )
        prefixes = sorted(
            {p for p, areas in DEPENDENCIES.items() if area in areas and p != "SYS"}
            | {
                check_id.split("-")[0]
                for check_id, areas in CHECK_DEPENDENCIES.items()
                if area in areas
            }
        )
        rows.append(
            {
                "area": area,
                "label": label,
                "status": status,
                "reason": "; ".join(notes),
                "checks": ", ".join(prefixes),
            }
        )

    history = data.raw.get("deployments", {}).get("request_history") or {}
    rows.append(
        {
            "area": "request_history",
            "label": "Deployment request history",
            "status": ("Partial" if history.get("deployments_unread") else "Collected")
            if history.get("collected")
            else "Not assessed",
            "reason": (
                f"{history.get('deployments_scanned', 0)} deployments scanned; "
                f"{history.get('deployments_unread', 0)} unread or outside the collection limit. "
                "Only retained requests are available."
            )
            if history.get("collected")
            else "Optional request-history collection was not completed",
            "checks": "DEP-008",
        }
    )
    evidence = data.raw.get("extensibility", {}).get("abx_run_evidence") or {}
    rows.append(
        {
            "area": "abx_runs",
            "label": "ABX run history",
            "status": "Collected"
            if evidence.get("complete")
            else ("Partial" if evidence.get("collected") else "Not assessed"),
            "reason": (
                "Only retained run records are available; absence does not prove "
                "an action never ran"
            ),
            "checks": "EXT-006",
        }
    )
    analysis_errors = [e for e in data.errors if e.get("area") in {"checks", "analysis"}]
    if analysis_errors:
        rows.append(
            {
                "area": "analysis",
                "label": "Assessment analysis",
                "status": "Partial",
                "reason": "; ".join(str(e.get("item", "analysis")) for e in analysis_errors),
                "checks": "Results may be incomplete",
            }
        )
    return rows


def comparison_limits(data: AssessmentData, previous: dict, check_id: str) -> list[str]:
    """Why the absence or appearance of a finding cannot be interpreted as change."""
    before_meta = previous.get("meta") or {}
    reasons = []
    if not before_meta.get("url") or before_meta.get("url") != data.meta.get("url"):
        reasons.append("The assessment targets differ or are unknown")
    for key, label, default in (
        ("projects_filter", "Project scope", []),
        ("pedantic", "Code-quality settings", False),
        ("request_history", "Request-history collection", False),
        ("request_history_limit", "Request-history limit", 0),
        ("group_membership", "Group-membership collection", True),
        ("powershell_parser", "PowerShell analysis", None),
        ("javascript_parser", "JavaScript analysis", None),
    ):
        before = before_meta.get(key, default)
        now = data.meta.get(key, default)
        if key == "projects_filter":
            before, now = sorted(before or []), sorted(now or [])
        if before != now:
            reasons.append(f"{label} changed")
    before_rules = before_meta.get("assessment_ruleset")
    now_rules = data.meta.get("assessment_ruleset")
    if not before_rules or not now_rules:
        reasons.append("Check-definition compatibility is unknown; generate a new baseline")
    elif before_rules != now_rules:
        reasons.append("Assessment definitions changed; generate a new baseline")

    # Collection errors are the evidence for SYS-001 itself, not a reason to
    # withhold its comparison when access is restored in the next run.
    if check_id == "SYS-001":
        if any(area not in data.raw for area in AREA_LABELS):
            reasons.append("Current run lacks required collection evidence")
        return reasons

    areas = CHECK_DEPENDENCIES.get(
        check_id, DEPENDENCIES.get(check_id.split("-")[0], set(AREA_LABELS))
    )
    # A check failure can prevent a finding regardless of collector coverage.
    current = {"raw": data.raw, "errors": data.errors}
    for label, snapshot in (("Previous", previous), ("Current", current)):
        errors = snapshot.get("errors") or []
        if any(e.get("area") in areas | {"analysis", "checks"} for e in errors):
            reasons.append(f"{label} run has collection or analysis gaps affecting this check")
        raw = snapshot.get("raw") or {}
        if any(area not in raw for area in areas):
            reasons.append(f"{label} run lacks required collection evidence")
        if "catalog" in areas and raw.get("catalog", {}).get("admin_scope") is False:
            reasons.append(f"{label} catalog visibility is limited")
        if "identity" in areas:
            identity = raw.get("identity") or {}
            if (
                not identity.get("collected")
                or identity.get("unresolved")
                or any(
                    not g.get("members_complete", g.get("members_read", False))
                    for g in identity.get("groups") or []
                )
            ):
                reasons.append(f"{label} group membership is incomplete or not assessed")
        if "vro" in areas and any(
            not w.get("resolved") for w in raw.get("vro", {}).get("workflows") or []
        ):
            reasons.append(f"{label} referenced workflow evidence is incomplete")
        if check_id == "DEP-008":
            history = raw.get("deployments", {}).get("request_history") or {}
            if not history.get("collected") or history.get("deployments_unread"):
                reasons.append(f"{label} request history is incomplete or not assessed")
        if check_id == "EXT-006":
            if not (raw.get("extensibility", {}).get("abx_run_evidence") or {}).get("complete"):
                reasons.append(f"{label} ABX run evidence is incomplete or not assessed")
    return reasons
