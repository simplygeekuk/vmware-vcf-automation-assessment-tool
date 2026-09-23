"""The deployment's project id, whichever way the build returns it.

Deployments are fetched with expand=project. On the live 8.18.1 build that
nests the project and leaves the top-level projectId empty, so reading only
the top level collapsed every project id in the estate to "". Nothing crashed
and nothing looked obviously wrong - projectName was read from the expanded
object all along - but every project-scoped comparison quietly compared
against nothing: ownership access never resolved and PRJ-001 called 59
populated projects empty.
"""

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.collectors.deployments import _slim
from vcf_automation_assessment_tool.identity_map import owner_access, principal_index
from vcf_automation_assessment_tool.models import AssessmentData


def test_the_id_is_taken_from_the_expanded_project_when_the_top_level_is_empty():
    slimmed = _slim(
        {
            "id": "d1",
            "name": "web",
            "project": {"id": "p1", "name": "Platform"},
            "resources": [],
        }
    )
    assert slimmed["projectId"] == "p1"
    assert slimmed["projectName"] == "Platform"


def test_the_top_level_id_is_still_honoured_when_the_build_populates_it():
    slimmed = _slim(
        {
            "id": "d1",
            "name": "web",
            "projectId": "p1",
            "projectName": "Platform",
            "resources": [],
        }
    )
    assert slimmed["projectId"] == "p1"
    assert slimmed["projectName"] == "Platform"


def test_neither_present_stays_empty_rather_than_inventing_one():
    slimmed = _slim({"id": "d1", "name": "web", "resources": []})
    assert slimmed["projectId"] == ""
    assert slimmed["projectName"] == ""


def test_an_owner_granted_on_their_project_resolves_once_the_id_survives():
    """The regression this guards: with the id empty, the owner held a grant in
    "p1" and their deployment claimed to be in "", so every owner on the estate
    read as having access only to other projects."""
    projects = [{"id": "p1", "name": "Platform", "members": [{"email": "alice"}]}]
    index = principal_index(projects, {})
    slimmed = _slim(
        {"id": "d1", "name": "web", "project": {"id": "p1", "name": "Platform"}, "resources": []}
    )
    label, state = owner_access("alice", {slimmed["projectId"]}, index)
    assert (label, state) == ("member", "granted")


def test_a_project_holding_deployments_is_not_reported_as_unused():
    """PRJ-001 compared project ids against a set of one empty string."""
    data = AssessmentData()
    data.raw["infrastructure"] = {
        "projects": [{"id": "p1", "name": "Platform"}, {"id": "p2", "name": "Empty"}]
    }
    data.raw["deployments"] = {
        "deployments": [
            _slim(
                {
                    "id": "d1",
                    "name": "web",
                    "project": {"id": "p1", "name": "Platform"},
                    "resources": [],
                }
            )
        ],
        "deleted": [],
        "request_history": {"collected": False},
    }
    data.raw["blueprints"] = {"blueprints": []}
    run_checks(data)

    prj_001 = next(f for f in data.findings if f.check_id == "PRJ-001")
    assert [a.name for a in prj_001.affected] == ["Empty"]
