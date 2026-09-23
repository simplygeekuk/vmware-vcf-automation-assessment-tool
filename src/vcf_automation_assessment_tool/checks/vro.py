"""vRO checks (VRO-001 actions, VRO-002 workflow complexity)."""

from __future__ import annotations

from ..models import AffectedObject, AssessmentData, Finding, Severity
from . import action_issues, check


@check
def vro_001_action_code_quality(data: AssessmentData) -> list[Finding]:
    actions = data.raw.get("vro", {}).get("actions", [])
    affected = []
    for a in actions:
        issues = action_issues(a, data)
        if not issues:
            continue
        # Slash-form FQNs (com.simplygeek.ad/addComputer) already isolate the
        # module before the slash; the dot-rsplit is only for dotted-form
        # FQNs, where the last segment is the action name. Applying both
        # collapsed every module to its vendor root.
        fqn = a.get("fqn", "")
        module = fqn.rsplit("/", 1)[0] if "/" in fqn else fqn.rsplit(".", 1)[0]
        detail = "\n".join([f"runtime: {a.get('runtime', '?')}"] + [f"• {i}" for i in issues])
        affected.append(
            AffectedObject(
                kind="vro-action",
                id=a.get("id", ""),
                name=a.get("fqn") or a.get("name", ""),
                project=module or None,
                detail=detail,
            )
        )
    if not affected:
        return []
    return [
        Finding(
            check_id="VRO-001",
            title="Orchestrator actions with code-quality signals",
            severity=Severity.WARNING,
            recommendation=(
                "Review the flagged Orchestrator action code and fix confirmed "
                "defects.\n"
                "The signals are error handling that hides the error, addresses and "
                "web links written into the code, values that look like passwords, "
                "and likely faults such as a repeated dictionary key or a test that "
                "is always true. The ABX check looks for the same things.\n"
                "Python is read in full, JavaScript is checked for syntax when node "
                "is available on the computer that runs the report, and built-in "
                "com.vmware.* modules are left out."
            ),
            affected=affected,
        )
    ]


@check
def vro_002_complex_workflows(data: AssessmentData) -> list[Finding]:
    workflows = data.raw.get("vro", {}).get("workflows", [])
    affected = []
    for wf in workflows:
        structure = wf.get("structure")
        if not structure or wf.get("complexity") != "HIGH":
            continue
        notes = [
            f"{structure['items']} item(s), {structure['decisions']} decision(s), "
            f"{structure['sub_workflows']} sub-workflow call(s), "
            f"{structure['scriptable_tasks']} scriptable task(s)"
        ]
        if structure["user_interactions"]:
            notes.append(
                f"• {structure['user_interactions']} user-interaction step(s) - blocks "
                "on human input; no pipeline equivalent without process redesign"
            )
        if structure["timers"]:
            notes.append(
                f"• {structure['timers']} waiting timer(s)/event(s) - long-running "
                "state that pipelines do not hold"
            )
        notes.append(f"used by: {', '.join(wf.get('used_by', [])) or '?'}")
        affected.append(
            AffectedObject(
                kind="vro-workflow",
                id=wf.get("id", ""),
                name=wf.get("name", ""),
                detail="\n".join(notes),
            )
        )
    if not affected:
        return []
    return [
        Finding(
            check_id="VRO-002",
            title="Complex Orchestrator workflows (orchestration graph)",
            severity=Severity.INFO,
            recommendation=(
                "Prioritise these complex workflows for design review before making "
                "changes.\n"
                "The rating comes from the shape of the workflow (how many steps, "
                "how much branching, how many sub-workflows, and any step that "
                "waits for a person or a timer), not from its scripts.\n"
                "A step that waits for a person or a timer holds part of a business "
                "process, not just code."
            ),
            affected=affected,
        )
    ]
