"""EXT-008: ABX actions on a runtime the platform has removed or deprecated."""

from vcf_automation_assessment_tool.checks.governance import (
    abx_runtime_support,
    ext_008_abx_actions_on_unsupported_runtimes,
)
from vcf_automation_assessment_tool.models import AssessmentData


def _data(actions):
    data = AssessmentData()
    data.raw["extensibility"] = {"abx_actions": actions}
    data.derived["project_names"] = {"p1": "Platform"}
    return data


def test_support_table_reads_major_minor_and_leaves_the_unknown_alone():
    assert abx_runtime_support("python", "3.7.12")[0] == "removed"
    assert abx_runtime_support("python", "3.10")[0] == "current"
    assert abx_runtime_support("nodejs", "18.19.0")[0] == "deprecated"
    assert abx_runtime_support("nodejs", "20")[0] == "current"
    assert abx_runtime_support("powershell", "7.2.5")[0] == "removed"
    # Newer than the notes describe, an unknown runtime, or no version: no claim.
    assert abx_runtime_support("python", "3.12")[0] == "unknown"
    assert abx_runtime_support("java", "17")[0] == "unknown"
    assert abx_runtime_support("python", "")[0] == "unknown"


def test_ext008_lists_removed_before_deprecated_and_skips_the_rest():
    data = _data(
        [
            {
                "id": "a1",
                "name": "old-py",
                "projectId": "p1",
                "runtime": "python",
                "runtimeVersion": "3.7",
            },
            {
                "id": "a2",
                "name": "node18",
                "projectId": "p1",
                "runtime": "nodejs",
                "runtimeVersion": "18.0.0",
                "provider": "on-prem",
            },
            {
                "id": "a3",
                "name": "fine",
                "projectId": "p1",
                "runtime": "python",
                "runtimeVersion": "3.10",
            },
            {
                "id": "a4",
                "name": "unversioned",
                "projectId": "p1",
                "runtime": "python",
                "runtimeVersion": "",
            },
        ]
    )
    findings = ext_008_abx_actions_on_unsupported_runtimes(data)
    assert len(findings) == 1
    assert [o.name for o in findings[0].affected] == ["old-py", "node18"]
    assert "removed in 8.14" in findings[0].affected[0].detail
    assert "provider on-prem" in findings[0].affected[1].detail
    assert findings[0].affected[0].project == "Platform"


def test_ext008_is_silent_with_nothing_to_say():
    assert ext_008_abx_actions_on_unsupported_runtimes(_data([])) == []
