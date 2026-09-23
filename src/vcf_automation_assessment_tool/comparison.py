"""What changed since an earlier run, read from that run's --json dump.

A run is a snapshot. Two dumps hold everything needed to say which findings
appeared, which were resolved and which grew or shrank, and how the estate's
counts moved. Nothing here reaches the API: the previous run is a file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .checks.deployments import is_machine
from .coverage import comparison_limits
from .models import AssessmentData

# Inventory counts worth putting side by side. (label, area, key); machines
# are counted from the deployments' resources rather than read from a key.
INVENTORY = (
    ("Deployments", "deployments", "deployments"),
    ("Machines", "deployments", None),
    ("Catalog items", "catalog", "items"),
    ("Cloud templates", "blueprints", "blueprints"),
    ("Subscriptions", "extensibility", "subscriptions"),
    ("ABX actions", "extensibility", "abx_actions"),
    ("Projects", "infrastructure", "projects"),
    ("Cloud accounts", "infrastructure", "cloud_accounts"),
    ("Secrets", "infrastructure", "secrets"),
)

STATUS_ORDER = {"unable_to_reassess": 0, "new": 1, "resolved": 2, "changed": 3, "unchanged": 4}


def load_previous(path: str) -> dict:
    """The earlier dump, or a ValueError that says what is wrong with it."""
    try:
        with open(path, encoding="utf-8") as fh:
            previous = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not a JSON dump: {exc}") from exc
    if not isinstance(previous, dict) or not isinstance(previous.get("findings"), list):
        raise ValueError(f"{path} is not a --json dump of this tool (no findings list)")
    if not isinstance(previous.get("meta"), dict):
        raise ValueError(f"{path} is not a --json dump of this tool (no meta)")
    return previous


def _identity(obj: dict) -> str:
    """One object across two runs: its id where the platform gave one, else its name."""
    kind = obj.get("kind") or ""
    key = obj.get("id") or obj.get("name") or ""
    return f"{kind}:{key}"


def _index(findings: list[Any]) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for f in findings:
        if isinstance(f, dict):
            check_id, title, severity = (
                f.get("check_id", ""),
                f.get("title", ""),
                f.get("severity", ""),
            )
            affected = [a for a in f.get("affected") or [] if isinstance(a, dict)]
        else:
            check_id, title = f.check_id, f.title
            severity = f.severity.value
            affected = [vars(a) for a in f.affected]
        if not check_id:
            continue
        objects = {_identity(a): a.get("name") or a.get("id") or "" for a in affected}
        index[check_id] = {"title": title, "severity": severity, "objects": objects}
    return index


def inventory_counts(raw: dict) -> dict[str, int | None]:
    """A count per INVENTORY label, None where the dump holds no such list."""
    counts: dict[str, int | None] = {}
    for label, area, key in INVENTORY:
        area_raw = raw.get(area) if isinstance(raw, dict) else None
        if not isinstance(area_raw, dict):
            counts[label] = None
            continue
        if key is None:
            deployments = area_raw.get("deployments")
            if not isinstance(deployments, list):
                counts[label] = None
                continue
            counts[label] = sum(
                1
                for d in deployments
                if isinstance(d, dict)
                for r in d.get("resources") or []
                if isinstance(r, dict) and is_machine(r.get("type") or "")
            )
            continue
        items = area_raw.get(key)
        counts[label] = len(items) if isinstance(items, list) else None
    return counts


def compare_runs(data: AssessmentData, previous: dict) -> dict:
    """The difference between this run and an earlier dump.

    Findings are matched by check id and their objects by id, or by name
    where the platform gave none. A finding present now and absent before is
    new; the reverse is resolved only with comparable assessment evidence.
    Missing data, changed scope or definitions must never imply improvement.
    """
    before = _index(previous.get("findings") or [])
    now = _index(data.findings)
    rows = []
    objects_added = objects_resolved = 0
    for check_id in sorted(set(before) | set(now)):
        b = before.get(check_id)
        n = now.get(check_id)
        b_objects = b["objects"] if b else {}
        n_objects = n["objects"] if n else {}
        new_ids = sorted(set(n_objects) - set(b_objects), key=lambda k: n_objects[k].lower())
        gone_ids = sorted(set(b_objects) - set(n_objects), key=lambda k: b_objects[k].lower())
        reasons = comparison_limits(data, previous, check_id)
        if reasons:
            status = "unable_to_reassess"
            new_ids, gone_ids = [], []
        elif b is None:
            status = "new"
        elif n is None:
            status = "resolved"
        elif new_ids or gone_ids or b["severity"] != n["severity"]:
            status = "changed"
        else:
            status = "unchanged"
        objects_added += len(new_ids)
        objects_resolved += len(gone_ids)
        rows.append(
            {
                "check_id": check_id,
                "title": (n or b)["title"],
                "severity": (n or b)["severity"],
                "status": status,
                "before": len(b_objects) if b else 0,
                "now": len(n_objects) if n else 0,
                "new_names": [n_objects[k] for k in new_ids],
                "resolved_names": [b_objects[k] for k in gone_ids],
                "reasons": reasons,
            }
        )
    rows.sort(key=lambda r: (STATUS_ORDER[r["status"]], r["check_id"]))

    prev_counts = inventory_counts(previous.get("raw") or {})
    now_counts = inventory_counts(data.raw)
    scope_changed = (
        not previous.get("meta", {}).get("url")
        or previous["meta"].get("url") != data.meta.get("url")
        or sorted(previous["meta"].get("projects_filter") or [])
        != sorted(data.meta.get("projects_filter") or [])
    )
    incomplete_areas = {e.get("area") for e in (previous.get("errors") or []) + data.errors}
    inventory = [
        {
            "label": label,
            "before": prev_counts[label],
            "now": now_counts[label],
            "delta": now_counts[label] - prev_counts[label],
        }
        for label, area, _key in INVENTORY
        if not scope_changed
        and area not in incomplete_areas
        and not (
            area == "catalog"
            and (
                previous.get("raw", {}).get("catalog", {}).get("admin_scope") is False
                or data.raw.get("catalog", {}).get("admin_scope") is False
            )
        )
        and prev_counts[label] is not None
        and now_counts[label] is not None
    ]

    prev_meta = previous.get("meta") or {}
    return {
        "previous": {
            "generated_at": str(prev_meta.get("generated_at") or ""),
            "tool_version": str(prev_meta.get("tool_version") or ""),
            "same_target": bool(prev_meta.get("url"))
            and prev_meta.get("url") == data.meta.get("url"),
        },
        "summary": {
            "unable_to_reassess": sum(1 for r in rows if r["status"] == "unable_to_reassess"),
            "new": sum(1 for r in rows if r["status"] == "new"),
            "resolved": sum(1 for r in rows if r["status"] == "resolved"),
            "changed": sum(1 for r in rows if r["status"] == "changed"),
            "unchanged": sum(1 for r in rows if r["status"] == "unchanged"),
            "objects_added": objects_added,
            "objects_resolved": objects_resolved,
        },
        "findings": rows,
        "inventory": inventory,
    }


def previous_path_problem(path: str | None) -> str | None:
    """Why a --compare path cannot be used, or None. Checked before login so
    a bad file fails in the first second rather than after a collection."""
    if not path:
        return None
    if not Path(path).is_file():
        return f"compare file not found: {path}"
    try:
        load_previous(path)
    except (OSError, ValueError) as exc:
        return str(exc)
    return None
