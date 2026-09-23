"""Governance collector: policies (with definition backfill) and approval
requests. Every sub-collector is best-effort.

"approval_requests" are the inbox items people approve or reject
(/approval/api/approvals) - a healthy estate with approval POLICIES can
legitimately hold zero of them; the policies themselves are in "policies"
and the slimmed "approval_policies".
"""

from __future__ import annotations

import logging

from ..client import ApiClient, ApiError
from ..models import AssessmentData

log = logging.getLogger(__name__)

AREA = "governance"


def collect(client: ApiClient, data: AssessmentData) -> None:
    raw: dict = {}

    def fetch(key: str, path: str, params: dict | None = None) -> list:
        try:
            items = list(client.iter_paged(path, params))
            log.info("%s: %d %s", AREA, len(items), key)
            raw[key] = items
            return items
        except ApiError as exc:
            log.warning("%s: %s unavailable: %s", AREA, key, exc)
            data.record_error(AREA, key, str(exc))
            raw[key] = []
            return []

    policies = fetch("policies", "/policy/api/policies")
    _ensure_policy_definitions(client, data, policies)
    approvals = fetch("approval_requests", "/approval/api/approvals")

    raw["approval_policies"] = [
        _slim_approval_policy(p)
        for p in policies
        if (p.get("typeId") or "") == "com.vmware.policy.approval"
    ]
    raw["approval_requests"] = [_slim_approval(a) for a in approvals]
    data.raw[AREA] = raw


def _ensure_policy_definitions(client: ApiClient, data: AssessmentData, policies: list) -> None:
    """Backfill definitions for policies the list endpoint returned as
    summaries.

    POL-001 grouping and content-sharing resolution both read the definition;
    some builds only include it in the per-id detail response.
    """
    missing = [
        p for p in policies if isinstance(p, dict) and not p.get("definition") and p.get("id")
    ]
    for p in missing:
        try:
            detail = client.get(f"/policy/api/policies/{p.get('id')}")
        except ApiError as exc:
            data.record_error(AREA, f"policy:{p.get('name') or p.get('id')}", str(exc))
            continue
        if isinstance(detail, dict):
            p.update({k: v for k, v in detail.items() if v is not None})
    if missing:
        log.info("%s: fetched %d policy definition detail(s)", AREA, len(missing))


def _slim_approval_policy(policy: dict) -> dict:
    d = policy.get("definition") or {}
    return {
        "id": policy.get("id", ""),
        "name": policy.get("name", ""),
        "enforcementType": policy.get("enforcementType", ""),
        "projectId": policy.get("projectId") or "",
        "scopeCriteria": policy.get("scopeCriteria") or {},
        "level": d.get("level"),
        "approvalMode": d.get("approvalMode", ""),
        "approverType": d.get("approverType", ""),
        "approvers": d.get("approvers") or [],
        "autoApprovalDecision": d.get("autoApprovalDecision", ""),
        "autoApprovalExpiry": d.get("autoApprovalExpiry"),
        "actions": d.get("actions") or [],
    }


def _slim_approval(approval: dict) -> dict:
    # Field names vary a little across 8.x builds; probe the common spellings.
    def nested_name(key: str) -> str:
        value = approval.get(key)
        return value.get("name", "") if isinstance(value, dict) else ""

    return {
        "id": approval.get("id", ""),
        "status": (approval.get("status") or approval.get("state") or "").upper(),
        "requestedBy": approval.get("requestedBy") or approval.get("requester") or "",
        "createdAt": approval.get("createdAt") or approval.get("createdOn") or "",
        "deploymentName": approval.get("deploymentName") or nested_name("deployment"),
        "policyName": approval.get("policyName") or nested_name("policy"),
        "actionName": approval.get("actionName") or approval.get("requestType") or "",
        "approvers": approval.get("approvers") or [],
    }
