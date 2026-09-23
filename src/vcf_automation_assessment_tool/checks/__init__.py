"""Check registry: a check is a pure function AssessmentData -> list[Finding]."""

from __future__ import annotations

import logging
from collections.abc import Callable

from ..coverage import ruleset_signature
from ..models import AssessmentData, Finding

log = logging.getLogger(__name__)

CHECKS: list[Callable[[AssessmentData], list[Finding]]] = []


def check(fn: Callable[[AssessmentData], list[Finding]]):
    CHECKS.append(fn)
    return fn


def action_issues(action: dict, data: AssessmentData) -> list[str]:
    """One action's reportable code-quality issues.

    Hygiene-level signals are collected on every run and always present in the
    JSON dump, but they only reach the report under --pedantic: untidy code
    that works is not something most estates can act on, and burying the real
    defects under it was the failure mode this split exists to avoid.
    """
    issues = list(action.get("issues") or [])
    if data.meta.get("pedantic"):
        issues += action.get("pedantic_issues") or []
    return issues


def run_checks(data: AssessmentData) -> None:
    data.meta["assessment_ruleset"] = ruleset_signature()
    # Importing the modules populates the registry.
    from . import (  # noqa: F401
        blueprints,
        catalog,
        deployments,
        governance,
        infrastructure,
        replatforming,
        system,
        vro,
    )

    for fn in CHECKS:
        try:
            findings = fn(data) or []
        except Exception as exc:  # one broken check must not kill the report
            log.exception("Check %s failed", fn.__name__)
            data.record_error("checks", fn.__name__, f"{type(exc).__name__}: {exc}")
            continue
        data.findings.extend(findings)
    # Severity first, then check id: a count-descending tiebreak was tried
    # here and read as unordered (EXT-005, EXT-006, EXT-002, VRO-002... in
    # one severity band) because the id is what the eye scans for.
    data.findings.sort(key=lambda f: (f.severity.order, f.check_id))
