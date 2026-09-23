"""Replatforming-readiness checks (REP-001, REP-002, REP-003).

These support the business decision to replace VCF Automation with other
tooling (Terraform, GitLab CI/CD, OpenShift, ...). Ratings are heuristics from
statically observable facts - they inform scoping, they do not replace an
engineering review.
"""

from __future__ import annotations

from ..flows import flow_topics
from ..models import AffectedObject, AssessmentData, Finding, Severity, area_gap
from . import check

# Resource types that map ~1:1 onto Terraform infrastructure providers.
PORTABLE_TYPES = {
    "Cloud.Machine",
    "Cloud.vSphere.Machine",
    "Cloud.Network",
    "Cloud.vSphere.Network",
    "Cloud.vSphere.Disk",
    "Cloud.Volume",
    "Cloud.NSX.Network",
    "Cloud.NSX.SecurityGroup",
    "Cloud.NSX.LoadBalancer",
    "Cloud.SecurityGroup",
    "Cloud.LoadBalancer",
}


def _blueprints(data: AssessmentData) -> list[dict]:
    return data.raw.get("blueprints", {}).get("blueprints", [])


@check
def rep_001_replatforming_matrix(data: AssessmentData) -> list[Finding]:
    flows = data.derived.get("flows", [])
    if not flows:
        return []
    blueprints = {b["id"]: b for b in _blueprints(data)}
    incomplete = any(
        area_gap(data, area) or not isinstance(data.raw.get(area, {}).get(key), list)
        for area, key in (("blueprints", "blueprints"), ("extensibility", "subscriptions"))
    )
    deployments_unknown = area_gap(data, "deployments") or not isinstance(
        data.raw.get("deployments", {}).get("deployments"), list
    )

    affected = []
    for flow in flows:
        bp = blueprints.get(flow.get("blueprint_id") or "")
        resource_types = (bp.get("resource_types") or []) if bp else []
        quality = (bp or {}).get("quality") or {}

        # How much extensibility hangs off the item, not where in its life it
        # hangs: the concern split the diagrams use makes no difference here.
        topics = flow_topics(flow)
        abx_hooks = sum(
            1 for t in topics for s in t["subscriptions"] if "abx" in (s.get("runnableType") or "")
        )
        vro_hooks = sum(
            1
            for t in topics
            for s in t["subscriptions"]
            if "vco" in (s.get("runnableType") or "") or "vro" in (s.get("runnableType") or "")
        )
        custom_types = [t for t in resource_types if t and t not in PORTABLE_TYPES]

        reasons = []
        if vro_hooks or any(t.startswith(("Custom.", "VRO.")) for t in resource_types):
            difficulty = "HIGH"
            reasons.append("Orchestrator dependency")
        elif abx_hooks or custom_types or len(resource_types) > 5:
            difficulty = "MEDIUM"
            if abx_hooks:
                reasons.append("ABX lifecycle hooks")
            if custom_types:
                reasons.append("Resource mapping needs review")
            if len(resource_types) > 5:
                reasons.append("More than five resource types")
        else:
            difficulty = "LOW"
            reasons.append("Standard infrastructure resources; no observed hooks")
        if incomplete or not bp or not resource_types:
            difficulty = "NEEDS REVIEW"
            reasons = ["Template/resource details or subscription evidence incomplete"]

        targets = []
        if resource_types:
            targets.append("Review Terraform provider mappings")
        if quality.get("cloud_config_blocks"):
            targets.append("retain cloud-init configuration")
        if abx_hooks:
            targets.append("review hooks for GitLab CI or AAP")
        if vro_hooks:
            targets.append("review Orchestrator dependencies before choosing a target")

        detail = "\n".join(
            [
                f"difficulty={difficulty}",
                f"reason: {'; '.join(reasons)}",
                f"resources: {', '.join(resource_types) or 'unknown'}",
                f"hooks: {abx_hooks} ABX, {vro_hooks} Orchestrator",
                "deployments: "
                + ("Unknown" if deployments_unknown else str(flow.get("deployment_count", 0))),
                f"target: {'; '.join(targets) or 'Review source content before choosing a target'}",
            ]
        )
        affected.append(
            AffectedObject(
                kind="catalog-item",
                id=flow["item_id"],
                name=flow["item_name"],
                project=", ".join(flow.get("projects", [])) or None,
                detail=detail,
            )
        )

    # Highest-effort first so the scoping conversation starts at the hard end.
    order = {"NEEDS REVIEW": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    affected.sort(key=lambda a: order.get(a.detail.split("\n")[0].split("=")[1], 3))
    return [
        Finding(
            check_id="REP-001",
            title="Catalog replacement complexity",
            severity=Severity.INFO,
            recommendation=(
                "Validate each suggested approach before planning a migration.\n"
                "Complexity describes content conversion, not the effort to migrate "
                "live deployments. "
                "Needs review means evidence is incomplete.\n"
                "Plan separately whether to import, rebuild or retire existing deployments."
            ),
            affected=affected,
        )
    ]


@check
def rep_002_content_not_in_git(data: AssessmentData) -> list[Finding]:
    affected = [
        AffectedObject(
            kind="blueprint",
            id=b["id"],
            name=b["name"],
            project=b.get("projectName") or b.get("projectId"),
            detail="no linked content source; an external Git copy may exist",
        )
        for b in _blueprints(data)
        if not b.get("contentSourceId")
    ]
    if not affected:
        return []
    return [
        Finding(
            check_id="REP-002",
            title="Templates without a linked content source",
            severity=Severity.WARNING,
            recommendation=(
                "Confirm whether a maintained Git copy exists; export templates where needed.\n"
                "Verify that the saved version matches the deployed content before conversion."
            ),
            affected=affected,
        )
    ]


# ABX code quality (EXT-003) and template hardcoding (BLU-003) are health
# findings and always on, so they are not part of this opt-in family.


@check
def rep_003_vro_dependency_surface(data: AssessmentData) -> list[Finding]:
    ext = data.raw.get("extensibility", {})
    design = data.raw.get("blueprints", {})
    project_names = data.derived.get("project_names", {})
    affected = []
    seen_ids: set[str] = set()

    def add(obj: AffectedObject) -> None:
        # The form-service lists can return the same object more than once;
        # identical ids are one dependency, not two.
        if obj.id and obj.id in seen_ids:
            return
        seen_ids.add(obj.id)
        affected.append(obj)

    for s in ext.get("subscriptions", []):
        if s.get("builtin"):
            continue
        if "vco" in (s.get("runnableType") or "") or "vro" in (s.get("runnableType") or ""):
            workflow = s.get("runnableName") or s.get("runnableId") or "?"
            detail = f"subscription on {s.get('eventTopicId', '?')}"
            # The subscription is usually named after its workflow - only
            # repeat the workflow when it actually adds information.
            if workflow != s.get("name"):
                detail += f"\nworkflow: {workflow}"
            add(
                AffectedObject(
                    kind="subscription",
                    id=s.get("id", ""),
                    name=s.get("name", ""),
                    detail=detail,
                )
            )
    for crt in design.get("custom_resource_types", []):
        pid = crt.get("projectId") or ""
        add(
            AffectedObject(
                kind="custom-resource-type",
                id=crt.get("id", ""),
                name=crt.get("displayName") or crt.get("resourceType", ""),
                project=project_names.get(pid, pid) or None,
                detail="custom resource type - lifecycle backed by Orchestrator workflows",
            )
        )
    for cra in design.get("custom_resource_actions", []):
        pid = cra.get("projectId") or ""
        resource_type = cra.get("resourceType") or ""
        add(
            AffectedObject(
                kind="custom-resource-action",
                id=cra.get("id", ""),
                name=cra.get("displayName") or cra.get("name", ""),
                project=project_names.get(pid, pid) or None,
                detail=(
                    f"custom day-2 action{' on ' + resource_type if resource_type else ''}"
                    " - backed by an Orchestrator workflow"
                ),
            )
        )
    if not affected:
        return []
    return [
        Finding(
            check_id="REP-003",
            title="Orchestrator dependencies",
            severity=Severity.INFO,
            recommendation=(
                "Export and review referenced workflows, actions and plug-in dependencies.\n"
                "Choose what to port, redesign or retire. Runtime language alone does not "
                "establish portability.\n"
                "Workflow internals are not assessed here; resolved names appear in Extensibility."
            ),
            affected=affected,
        )
    ]
