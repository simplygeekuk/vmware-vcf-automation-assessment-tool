"""Collectors: each pulls one area of the platform into AssessmentData.raw.

Run order matters: catalog counts deployments, flows need blueprints + catalog +
governance, so the orchestrator runs them in the order below.
"""

from __future__ import annotations

from . import (
    blueprints,
    catalog,
    deployments,
    extensibility,
    governance,
    identity,
    infrastructure,
    vro,
)

COLLECTORS = [
    ("infrastructure", infrastructure.collect),
    # identity reads the projects infrastructure collected: it expands only
    # the groups those projects actually grant to.
    ("identity", identity.collect),
    ("deployments", deployments.collect),
    ("blueprints", blueprints.collect),
    ("catalog", catalog.collect),
    ("governance", governance.collect),
    ("extensibility", extensibility.collect),
    # vro runs last: it needs integrations (infrastructure), subscriptions
    # (extensibility, which it enriches with workflow names) and custom
    # resources (blueprints).
    ("vro", vro.collect),
]
