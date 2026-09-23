"""Evidence labels and operational priorities; never infer business criticality."""

from __future__ import annotations

from ..models import Severity

OBSERVED_FAILURES = {
    "DEP-001",
    "DEP-003",
    "DEP-007",
    "DEP-008",
    "DEP-010",
    "INF-003",
    "CAT-002",
}
REVIEW_CANDIDATES = {
    "CAT-001",
    "PRJ-001",
    "PRJ-002",
    "INF-004",
    "INF-007",
    "EXT-002",
    "EXT-006",
    "BLU-002",
    "TAG-003",
    "REP-002",
    "POL-001",
    "POL-003",
    "POL-004",
    "POL-005",
    "POL-006",
}
FIRST = {
    "SYS-001",
    "INF-003",
    "INF-005",
    "PRJ-004",
    "TAG-001",
    "TAG-004",
    "TAG-005",
    "DEP-003",
    "DEP-001",
    "DEP-010",
    "DEP-004",
    "EXT-009",
}
IMPACTS = {
    "REP-001": "Conversion complexity and deployment migration are separate planning concerns.",
    "REP-002": "A maintained source copy supports recovery and replacement planning.",
    "REP-003": "Workflow and plug-in dependencies can change the replacement approach and effort.",
    "SYS-001": (
        "Missing evidence can hide issues and prevent reliable comparison with earlier runs."
    ),
    "INF-003": "An unhealthy connection can interrupt operations that depend on that endpoint.",
    "INF-005": "Provisioning that needs an address from an exhausted range can fail.",
    "INF-006": "Limited address capacity can prevent subsequent provisioning requests.",
    "PRJ-004": "A request placed in the affected project and zone can exceed its configured quota.",
    "PRJ-005": "The affected project and zone have limited remaining quota.",
    "PRJ-006": "The project has no assigned cloud zone for zone-based provisioning.",
    "TAG-001": (
        "Required placement constraints cannot be satisfied by the collected infrastructure."
    ),
    "TAG-004": "A requesting project may have no eligible placement for the selected template.",
    "TAG-005": "Individually matching constraints may still have no common placement.",
    "DEP-001": (
        "A lifecycle operation failed; this alone does not establish a current service outage."
    ),
    "DEP-003": "The platform records missing resources; validate the actual state before recovery.",
    "DEP-004": "Requests may be waiting on an operation that has stopped progressing.",
    "DEP-007": "Historical deletion failures warrant review; they do not prove a current outage.",
    "DEP-008": (
        "Retained request failures identify operations to investigate, including retried failures."
    ),
    "DEP-010": "Failed deployments still hold machines that may be running or consuming capacity.",
    "CAT-001": (
        "Unneeded items add maintenance work, but lack of current "
        "deployments is not proof of disuse."
    ),
    "CAT-002": "Catalog content may not reflect the latest source content.",
    "BLU-003": "Hardcoded values can reduce portability or expose sensitive configuration.",
    "EXT-002": (
        "Disabled subscriptions may be intentional or may leave expected automation inactive."
    ),
    "EXT-003": (
        "Static analysis identifies code to inspect; a signal does not prove a runtime failure."
    ),
    "VRO-001": (
        "Static analysis identifies code to inspect; a signal does not prove a runtime failure."
    ),
    "EXT-006": (
        "An action may be unnecessary, but retained history does not cover every past execution."
    ),
    "EXT-009": "An unresolved ABX binding may prevent a custom resource operation from completing.",
}
VERIFICATIONS = {
    "REP-001": "Review the source content and validate a representative conversion with its owner.",
    "REP-002": "Compare the maintained source copy with the current template content.",
    "REP-003": "Record the replacement approach for each required workflow and dependency.",
    "DEP-001": (
        "Inspect the failed operation and resource state, then confirm an approved retry completes."
    ),
    "DEP-003": (
        "Reconcile the resource with the provider and confirm the "
        "platform reports its expected state."
    ),
    "INF-003": "Confirm the connection reports healthy and validate an affected operation.",
    "INF-005": (
        "Confirm available addresses, then validate an approved "
        "provisioning request on that network."
    ),
    "PRJ-004": (
        "Confirm quota headroom for the project and zone, then validate an approved request."
    ),
    "CAT-001": (
        "Record the service owner's decision; retained items may "
        "correctly remain on this review list."
    ),
    "CAT-002": "Repeat the import and confirm its completion and expected catalog content.",
    "EXT-006": (
        "Confirm the owner's usage decision; absence of retained runs is "
        "not a retirement criterion alone."
    ),
}


def finding_insight(finding) -> dict:
    check_id = finding.check_id
    if check_id in OBSERVED_FAILURES:
        evidence = "Observed failure"
    elif check_id in REVIEW_CANDIDATES or finding.severity is Severity.INFO:
        evidence = "Review candidate"
    else:
        evidence = "Potential issue"
    if check_id in FIRST or finding.severity is Severity.CRITICAL:
        priority = "Investigate first"
    elif evidence == "Review candidate" or finding.severity is Severity.INFO:
        priority = "Owner review"
    else:
        priority = "Plan follow-up"
    default_impact = (
        "Confirm whether this configuration is intentional and still needed before changing it."
        if evidence == "Review candidate"
        else "The affected objects need technical review to establish their operational impact."
    )
    default_verification = (
        "Record the owner's decision and any accepted exception; a review "
        "candidate need not be removed."
        if evidence == "Review candidate"
        else "Validate the affected behaviour in the platform, then repeat the assessment "
        "with comparable scope."
    )
    projects = sorted({a.project for a in finding.affected if a.project}, key=str.casefold)
    return {
        "evidence": evidence,
        "priority": priority,
        "impact": IMPACTS.get(check_id, default_impact),
        "verification": VERIFICATIONS.get(check_id, default_verification),
        "projects": projects,
    }
