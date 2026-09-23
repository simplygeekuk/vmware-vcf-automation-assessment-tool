"""Evidence-driven capability -> replacement-solution map.

Each row states an VCF Automation capability the environment actually uses
(with counts as evidence), a recommended replacement, alternatives, and the
migration caveat. Rows with no usage evidence are omitted - the map describes
this environment, not the product's feature list.

The recommendations target the proposed stack: OpenShift, GitLab,
Ansible Automation Platform (AAP) and Terraform, with ServiceNow or a similar
service management portal as the request/approval front door. Division of labour:
Terraform for declarative provisioning and state, AAP for configuration,
day-2 and event-driven work, GitLab as orchestrator, OpenShift as the
container platform. No VMware products are recommended, and the existing
hypervisor/network estate is referenced generically.
"""

from __future__ import annotations

from .models import AssessmentData


def _row(capability, evidence, recommended, alternatives, notes) -> dict:
    return {
        "capability": capability,
        "evidence": evidence,
        "recommended": recommended,
        "alternatives": alternatives,
        "notes": notes,
    }


def build_capability_map(data: AssessmentData) -> None:
    infra = data.raw.get("infrastructure", {})
    gov = data.raw.get("governance", {})
    ext = data.raw.get("extensibility", {})
    design = data.raw.get("blueprints", {})
    blueprints = design.get("blueprints", [])
    deployments = data.raw.get("deployments", {}).get("deployments", [])
    items = data.raw.get("catalog", {}).get("items", [])

    subs = [s for s in ext.get("subscriptions", []) if not s.get("builtin")]
    abx_subs = [s for s in subs if "abx" in (s.get("runnableType") or "")]
    vro_subs = [
        s
        for s in subs
        if "vco" in (s.get("runnableType") or "") or "vro" in (s.get("runnableType") or "")
    ]
    abx_actions = ext.get("abx_actions", [])
    approval_policies = gov.get("approval_policies", [])
    lease_policies = [
        p for p in gov.get("policies", []) if "lease" in (p.get("typeId") or "").lower()
    ]
    custom_actions = design.get("custom_resource_actions", [])
    custom_types = design.get("custom_resource_types", [])
    capability_tags = data.derived.get("capability_tags", {})

    rows: list[dict] = []

    if blueprints or deployments:
        rows.append(
            _row(
                "VM & network provisioning (cloud templates)",
                f"{len(blueprints)} template(s), {len(deployments)} active deployment(s)",
                "Terraform via GitLab CI; AAP for configuration.",
                "OpenShift Virtualization for workloads moving onto the container platform",
                "Plan state import, rebuild or retirement for existing deployments.",
            )
        )
    if items:
        rows.append(
            _row(
                "Self-service catalog & request UX",
                f"{len(items)} catalog item(s)",
                "ServiceNow or a similar service management portal, connected to GitLab or AAP.",
                "AAP job template surveys for technical requesters",
                "Integrate request submission, approvals and execution status.",
            )
        )
    if capability_tags or infra.get("zones"):
        rows.append(
            _row(
                "Placement (capability tags, cloud zones, profiles)",
                f"{len(capability_tags)} tag(s), {len(infra.get('zones', []))} zone(s)",
                "Terraform environment modules and matching AAP inventories.",
                "OpenShift scheduler (nodeSelectors/taints) for containerized workloads",
                "Translate tag-based placement rules into explicit environment selection.",
            )
        )
    if infra.get("image_profiles"):
        rows.append(
            _row(
                "Image mappings (golden images per region)",
                f"{len(infra['image_profiles'])} image profile(s)",
                "GitLab image-build pipelines producing versioned VM templates.",
                "OpenShift ImageStreams for container images",
                "Assign ownership for image versions and patching.",
            )
        )
    if infra.get("flavor_profiles"):
        rows.append(
            _row(
                "Flavor mappings (t-shirt sizing)",
                f"{len(infra['flavor_profiles'])} flavor profile(s)",
                "Terraform variables or AAP survey choices.",
                "",
                "Preserve size names and validate CPU/memory mappings.",
            )
        )
    if abx_subs or vro_subs:
        rows.append(
            _row(
                "Lifecycle extensibility (event subscriptions)",
                f"{len(subs)} custom subscription(s): "
                f"{len(abx_subs)} ABX, {len(vro_subs)} Orchestrator",
                "GitLab stages for pipeline hooks; Event-Driven Ansible for external events.",
                "",
                "Preserve blocking behaviour, event timing and failure handling.",
            )
        )
    if abx_actions:
        runtimes = sorted({a.get("runtime", "?") for a in abx_actions if a.get("runtime")})
        rows.append(
            _row(
                "ABX actions (serverless scripts)",
                f"{len(abx_actions)} action(s), runtimes: {', '.join(runtimes) or '?'}",
                "GitLab CI jobs or AAP job templates.",
                "OpenShift Jobs/Knative functions",
                "Review dependencies, credentials and packaged code before assuming portability.",
            )
        )
    if vro_subs or custom_types or custom_actions:
        rows.append(
            _row(
                "Orchestrator workflows (subscriptions, custom resources, day-2)",
                f"{len(vro_subs)} subscription(s), {len(custom_types)} custom type(s), "
                f"{len(custom_actions)} custom action(s)",
                "GitLab or AAP after workflow review (REP-003).",
                "",
                "Inspect actions, sub-workflows and plug-ins before sizing replacement work.",
            )
        )
    if approval_policies:
        rows.append(
            _row(
                "Approvals",
                f"{len(approval_policies)} approval polic(ies)",
                "ServiceNow or a similar service management portal for request approvals.",
                "",
                "Use GitLab/AAP execution gates separately; preserve approvers and audit history.",
            )
        )
    if lease_policies:
        rows.append(
            _row(
                "Leases & expiry",
                f"{len(lease_policies)} lease polic(ies)",
                "Scheduled GitLab terraform destroy jobs or AAP expiry workflows.",
                "",
                "Rebuild expiry notices, exceptions and authorised deletion controls.",
            )
        )
    if custom_actions:
        rows.append(
            _row(
                "Day-2 actions (resize, snapshot, custom operations)",
                f"{len(custom_actions)} custom day-2 action(s)",
                "AAP job templates triggered through the service management portal.",
                "OpenShift/K8s operators for containerized workloads",
                "Preserve permissions, input validation and operation status.",
            )
        )
    if infra.get("projects"):
        rows.append(
            _row(
                "Projects (multi-tenancy, RBAC, zone assignment)",
                f"{len(infra['projects'])} project(s)",
                "GitLab groups and AAP teams with environment permissions.",
                "OpenShift projects/namespaces with ResourceQuotas",
                "Map access, placement and quotas separately; validate isolation.",
            )
        )
    if design.get("property_groups"):
        rows.append(
            _row(
                "Property groups (shared configuration)",
                f"{len(design['property_groups'])} property group(s)",
                "Terraform variables and AAP group_vars; credentials in a secret store.",
                "",
                "Separate secrets from ordinary configuration and preserve access controls.",
            )
        )

    data.derived["capability_map"] = rows
