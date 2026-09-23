"""Configured naming evidence, without guessing precedence or historic compliance."""

import re

from ..checks.deployments import is_machine
from ..models import area_gap


def naming_inventory(data):
    infra = data.raw.get("infrastructure", {})
    projects = infra.get("projects", [])
    wanted = set(data.meta.get("projects_filter") or [])
    if wanted:
        projects = [p for p in projects if p.get("id") in wanted or p.get("name") in wanted]
    names = {p.get("id"): p.get("name") or p.get("id") for p in infra.get("projects", [])}
    profiles = infra.get("naming_profiles", [])
    rows = []
    hosts = {}
    machine_counts = {}
    deployments_read = isinstance(data.raw.get("deployments", {}).get("deployments"), list)
    for dep in data.raw.get("deployments", {}).get("deployments", []):
        for res in dep.get("resources", []):
            if is_machine(res.get("type", "")):
                pid = dep.get("projectId")
                machine_counts[pid] = machine_counts.get(pid, 0) + 1
                if res.get("hostname"):
                    hosts.setdefault(pid, set()).add(res["hostname"])

    def add(project, source, pattern="", profile=None, template=None, assignment=None):
        template = template or {}
        assignment = assignment or {}
        details = []
        for key, label in (("active", "Assignment active"), ("defaultOrg", "Organisation default")):
            if key in assignment:
                details.append(f"{label}: {assignment[key]}")
        for key, label in (
            ("staticPattern", "Static pattern"),
            ("resourceDefault", "Resource default"),
            ("uniqueName", "Unique name"),
            ("startCounter", "Start counter"),
            ("incrementStep", "Increment"),
        ):
            if key in template:
                details.append(f"{label}: {template[key]}")
        for counter in template.get("counters", []):
            pid = counter.get("projectId")
            if project.get("id") and pid and pid != project["id"]:
                continue
            details.append(
                f"Counter ({names.get(pid, pid) or 'scope not reported'}): "
                f"{counter.get('currentCounter', 'unknown')}; "
                f"active: {counter.get('active', 'unknown')}"
            )
        refs = re.findall(r"\$\{([^{}]+)\}", pattern)
        refs = sorted({r for r in refs if not set(r) <= {"#"}})
        if refs:
            details.append("Referenced expressions: " + ", ".join(refs))
        pid = project.get("id")
        if not pid:
            example_status = "No project assignment"
        elif not deployments_read:
            example_status = "Deployment data not collected"
        elif machine_counts.get(pid):
            example_status = f"Collected machines without hostnames: {machine_counts[pid]}"
        elif area_gap(data, "deployments"):
            example_status = "Deployment collection incomplete"
        else:
            example_status = "No machines collected for this project"
        rows.append(
            {
                "project": project.get("name") or project.get("id") or "Not assigned",
                "source": source,
                "profile": (profile or {}).get("name") or "",
                "resource": template.get("resourceTypeName")
                or template.get("resourceType")
                or ("Not reported" if profile else "Machine"),
                "pattern": pattern or "Not reported",
                "details": details,
                "example_status": example_status,
                "examples": sorted(hosts.get(project.get("id"), []), key=str.casefold)[:3],
            }
        )

    for project in sorted(projects, key=lambda p: (p.get("name") or "").casefold()):
        found = False
        if project.get("machineNamingTemplate"):
            add(project, "Project template", project["machineNamingTemplate"])
            found = True
        for profile in profiles:
            for assignment in profile.get("projects", []):
                if assignment.get("projectId") != project.get("id"):
                    continue
                found = True
                for template in profile.get("templates") or [{}]:
                    add(
                        project,
                        "Custom naming profile",
                        template.get("pattern", ""),
                        profile,
                        template,
                        assignment,
                    )
        if not found:
            add(project, "Not determined")
    # Organisation defaults and unassigned profiles remain visible as configuration;
    # they are not silently treated as effective assignments to every project.
    if not wanted:
        for profile in profiles:
            assignments = profile.get("projects") or [{}]
            for assignment in assignments:
                if assignment.get("projectId") in names and assignment.get("projectId"):
                    continue
                project = {
                    "id": assignment.get("projectId"),
                    "name": assignment.get("projectName")
                    or assignment.get("projectId")
                    or ("Organisation default" if assignment.get("defaultOrg") else "Not assigned"),
                }
                for template in profile.get("templates") or [{}]:
                    add(
                        project,
                        "Custom naming profile",
                        template.get("pattern", ""),
                        profile,
                        template,
                        assignment,
                    )
    complete = "naming_profiles" in infra and not area_gap(
        data, "infrastructure", {"naming_profiles"}
    )
    return {
        "rows": rows,
        "complete": complete,
        "hostnames_missing": bool(machine_counts) and not hosts,
    }
