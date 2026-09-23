"""System checks: collection gaps (SYS-001)."""

from __future__ import annotations

from ..models import AffectedObject, AssessmentData, Finding, Severity
from . import check


@check
def sys_001_collection_gaps(data: AssessmentData) -> list[Finding]:
    if not data.errors:
        return []
    affected = [
        AffectedObject(
            kind="collection-gap",
            id=f"{e['area']}:{e['item']}",
            name=f"{e['area']} / {e['item']}",
            detail=e["error"][:200],
        )
        for e in data.errors
    ]
    return [
        Finding(
            check_id="SYS-001",
            title="Assessment incomplete: some data could not be collected",
            severity=Severity.WARNING,
            recommendation=(
                "Resolve the collection errors and rerun the assessment.\n"
                "Full coverage usually needs Organization Owner and "
                "Assembler/Service Broker admin roles. Missing services can also "
                "cause errors; affected findings may be incomplete."
            ),
            affected=affected,
        )
    ]
