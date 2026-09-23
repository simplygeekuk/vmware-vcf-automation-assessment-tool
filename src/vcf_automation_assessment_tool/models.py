"""Data shapes shared by collectors, checks and the renderer."""

from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass, field
from typing import Any

# Friendly names for catalog item types, matching what the Service Broker UI
# shows; unknown types fall back to the raw type id. Shared by the renderer
# (item tables) and checks that explain a deployment's origin.
ITEM_TYPE_LABELS = {
    "com.vmw.blueprint": "VCF Automation template",
    "com.vmw.vro.workflow": "Automation Orchestrator workflow",
    "com.vmw.abx.action": "ABX action",
    "com.vmw.codestream.pipeline": "Code Stream pipeline",
    "com.vmw.terraform.configuration": "Terraform configuration",
    "com.vmw.marketplace.item": "Marketplace item",
}

# Status values that count as healthy for cloud accounts / integrations.
# Anything else that a build reports (FAILED, ERROR, UNAVAILABLE, ...) is a
# finding; a document with no health signal at all is unknown, never assumed OK.
# MAINTENANCE belongs here because maintenance mode is a deliberate operator
# state rather than an outage: it stays visible in the report's Status column,
# but INF-003 keeps its CRITICAL grade for genuinely unhealthy endpoints only.
OK_ENDPOINT_STATUSES = {"OK", "ACTIVE", "AVAILABLE", "READY", "MAINTENANCE"}


def endpoint_status(obj: dict) -> str | None:
    """Best-effort health of a cloud account or integration document.

    Two shapes are read, strings first. The public IaaS model documents no
    status field; the top-level string candidates below cover builds carrying
    one, but none has yet been observed populated on a live document. The top-level "healthy" and
    "inMaintenanceMode" booleans are documented in the 8.x CloudAccount model
    and appear in this estate's own API docs example payload (2026-08-06);
    whether this build actually populates them is confirmed only by a run that
    shows a filled Status column. Return None when the document exposes
    neither shape, and callers must stay silent then: absence is unknown, never
    healthy. Shared by the renderer (Status column) and INF-003 so both read
    the same fields.
    """
    # Strings are read from the top-level document only, for the same reason
    # as the booleans below: the properties bags hold provider settings, and
    # a provider key like state: "ENABLED" is not the endpoint's own health.
    # A bag string not in the OK allowlist would have fired INF-003 at
    # CRITICAL over configuration, not health.
    for key in ("status", "state"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    # Booleans are read on the top-level document only: the properties bags
    # hold provider settings, where such a key would not be the endpoint's own.
    healthy = obj.get("healthy")
    if isinstance(healthy, bool):
        if not healthy:
            return "UNHEALTHY"
        return "MAINTENANCE" if obj.get("inMaintenanceMode") is True else "OK"
    # Maintenance mode is a positive signal on its own, but a False value says
    # nothing about health, so it falls through to unknown.
    if obj.get("inMaintenanceMode") is True:
        return "MAINTENANCE"
    return None


# The per-zone limits a project sets on the Provisioning tab, paired with the
# allocation counters the same document reports. Both halves come from the
# IaaS ZoneAssignment model (confirmed against this build's own swagger,
# 2026-08-27). A limit of 0 means unlimited in that model, so it reads here as
# no limit rather than as a limit nothing can fit inside. Shared by the
# renderer (allocation table) and the PRJ-004/005 checks so the table and the
# findings can never disagree about what is full.
ZONE_LIMITS = (
    ("instances", "maxNumberInstances", "allocatedInstancesCount", "Instances", ""),
    ("memory", "memoryLimitMB", "allocatedMemoryMB", "Memory", "MB"),
    ("cpu", "cpuLimit", "allocatedCpu", "CPU", ""),
    ("storage", "storageLimitGB", "allocatedStorageGB", "Storage", "GB"),
)

# At or above this share of a limit, the zone is worth naming before it stops
# a build rather than after.
NEAR_LIMIT_RATIO = 0.8


def _amount(value: Any) -> float | None:
    """Numbers only. A missing or non-numeric counter is unknown, and unknown
    never becomes 0: a zero would read as an empty zone and could put a
    project in a finding it does not belong in."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def format_amount(value: float) -> str:
    """Whole numbers without a trailing .0 - allocatedStorageGB is the one
    counter the API reports as a float, and 110.0 GB next to 110 instances
    reads as two different kinds of number. Shared by the renderer's table
    cells and the PRJ-004/005 finding detail so both spell a quota the same."""
    return f"{value:,.0f}" if float(value).is_integer() else f"{value:,.1f}"


def ip_range_usage(ranges: list[dict]) -> list[dict]:
    """One row per internal IP range, with the platform's own counters.

    NetworkIPRange documents totalNumberOfIPs, numberOfAllocatedIPs and
    numberOfAvailableIPs (IaaS API). ratio is allocated over total and is
    None whenever either is unknown, so nothing downstream can read a
    percentage the data does not support. Shared by the IP Ranges table
    and INF-005/INF-006 so the two cannot disagree.
    """
    rows = []
    for r in ranges or []:
        if not isinstance(r, dict):
            continue
        total = _amount(r.get("totalNumberOfIPs"))
        allocated = _amount(r.get("numberOfAllocatedIPs"))
        available = _amount(r.get("numberOfAvailableIPs"))
        ratio = allocated / total if allocated is not None and total else None
        rows.append(
            {
                "id": r.get("id") or "",
                "name": r.get("name") or "",
                "ip_version": r.get("ipVersion") or "",
                "start": r.get("startIPAddress") or "",
                "end": r.get("endIPAddress") or "",
                "total": total,
                "allocated": allocated,
                "available": available,
                "ratio": ratio,
            }
        )
    return rows


# A template reads a platform secret as ${secret.<name>}: the binding the
# Secrets feature documents for cloud template properties. Names only; a
# template never holds the value.
SECRET_REF_RE = re.compile(r"\$\{secret\.([A-Za-z0-9_.\-]+)\}")


def secret_rows(data: AssessmentData) -> list[dict]:
    """One row per platform secret with its scope and what reads it.

    Scope comes from the secret's own document; projectIds is capped at ten
    by the API, so ten ids are written as "10 or more projects". Use is the
    templates whose content names the secret plus property groups whose
    properties do. Shared by the Secrets table and INF-007 so they agree.
    """
    raw = data.raw.get("infrastructure", {}).get("secrets") or []
    project_names = data.derived.get("project_names", {})
    readers: dict[str, list[str]] = {}
    for bp in data.raw.get("blueprints", {}).get("blueprints", []) or []:
        for name in bp.get("secret_refs") or []:
            readers.setdefault(name, []).append(bp.get("name") or "?")
    for pg in data.raw.get("blueprints", {}).get("property_groups", []) or []:
        blob = json.dumps(pg.get("properties") or {}, default=str)
        for name in set(SECRET_REF_RE.findall(blob)):
            readers.setdefault(name, []).append(f"property group {pg.get('name') or '?'}")
    rows = []
    for s in raw:
        if s.get("orgScoped"):
            scope = "organization"
        else:
            ids = s.get("projectIds") or ([s["projectId"]] if s.get("projectId") else [])
            names = [
                project_names.get(i) or s.get("projectName") or f"(unknown project {i[:8]})"
                for i in ids
            ]
            if len(ids) >= 10:
                scope = "10 or more projects"
            else:
                scope = ", ".join(sorted(set(names))) or "(no project)"
        used_by = sorted(set(readers.get(s.get("name") or "", [])), key=str.lower)
        rows.append(
            {
                "id": s.get("id", ""),
                "name": s.get("name", ""),
                "description": s.get("description", ""),
                "scope": scope,
                "created_by": s.get("createdBy", ""),
                "updated": (s.get("updatedAt") or s.get("createdAt") or "")[:10],
                "used_by": used_by,
            }
        )
    return sorted(rows, key=lambda r: r["name"].lower())


def zone_allocations(projects: list[dict], zone_names: dict[str, str]) -> list[dict]:
    """One row per project-to-zone assignment, with each limit resolved against
    what the platform reports as allocated.

    Every row carries a "limits" dict keyed by the short names in ZONE_LIMITS,
    each holding used, limit and ratio. limit is None when the assignment sets
    none; ratio is None whenever either half is unknown, so a caller can never
    read a percentage the data does not support.
    """
    rows = []
    for project in projects:
        for assignment in project.get("zones") or []:
            # zoneId only: the assignment's own "id" is the composite
            # "<projectId>-<zoneId>" and would never resolve to a zone name.
            zone_id = assignment.get("zoneId") or ""
            limits = {}
            for key, limit_field, used_field, _label, _unit in ZONE_LIMITS:
                used = _amount(assignment.get(used_field))
                limit = _amount(assignment.get(limit_field))
                if not limit:  # 0 and None both mean no limit is set
                    limit = None
                ratio = used / limit if used is not None and limit else None
                limits[key] = {"used": used, "limit": limit, "ratio": ratio}
            rows.append(
                {
                    "project_id": project.get("id", ""),
                    "project": project.get("name", ""),
                    "zone_id": zone_id,
                    "zone": zone_names.get(zone_id)
                    or (f"(unknown zone {zone_id[:8]})" if zone_id else "(no zone id)"),
                    "limits": limits,
                }
            )
    return rows


class Severity(enum.Enum):
    CRITICAL = "critical"  # broken today
    WARNING = "warning"  # cleanup strongly recommended
    INFO = "info"  # awareness / inventory

    @property
    def order(self) -> int:
        return {"critical": 0, "warning": 1, "info": 2}[self.value]


@dataclass(frozen=True)
class AffectedObject:
    kind: str  # "deployment", "catalog-item", "tag", "blueprint", ...
    id: str
    name: str
    project: str | None = None
    detail: str | None = None  # e.g. "status=CREATE_FAILED since 2024-11-02"


@dataclass
class Finding:
    check_id: str  # e.g. "DEP-001"
    title: str
    severity: Severity
    recommendation: str
    affected: list[AffectedObject] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.affected)


@dataclass
class AssessmentData:
    """Single container passed collectors -> checks -> renderer."""

    meta: dict = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)  # JSON-serializable payloads per area
    derived: dict[str, Any] = field(default_factory=dict)  # tag maps, counters, flows
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)  # collection gaps (403/404/...)

    def record_error(self, area: str, item: str, error: str) -> None:
        self.errors.append({"area": area, "item": item, "error": error})

    def to_json_dict(self) -> dict:
        return {
            "meta": self.meta,
            "raw": self.raw,
            "derived": self.derived,
            "findings": [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "recommendation": f.recommendation,
                    "count": f.count,
                    "affected": [vars(a) for a in f.affected],
                }
                for f in self.findings
            ],
            "errors": self.errors,
        }


def area_gap(data: AssessmentData, area: str, items: set[str] | None = None) -> bool:
    """True when a collection gap undermines evidence a check depends on.

    Absence-of-data claims ("no deployments reference this", "no policy covers
    that") are only honest when the data was actually read. A skipped area
    (item "skipped"), a crashed collector (item "collector") and a failed fetch
    all count as gaps; `items` narrows the fetch-failure test to the
    collections the caller reads, so an unrelated endpoint's 403 does not
    silence a check that never looks at it.
    """
    for e in data.errors:
        if e.get("area") != area:
            continue
        item = e.get("item")
        if item in ("skipped", "collector") or items is None or item in items:
            return True
    return False
