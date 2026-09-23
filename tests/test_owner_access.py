"""Last activity and project access on the Deployments by Owner table.

The access column is the closest the API gets to "has this person left", and
it deliberately stops short of saying so: project member lists name groups
without expanding them, so an owner with no individual grant may still reach
the project through one. Every test here pins that restraint.
"""

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.flows import build_flows
from vcf_automation_assessment_tool.report.renderer import (
    _owner_rollup,
    owner_columns,
    render_report,
)


def _project(pid, **roles):
    return {"id": pid, "name": pid, **roles}


def _deployment(owner, project, updated="2025-01-01T00:00:00Z"):
    return {
        "ownedBy": owner,
        "projectId": project,
        "lastUpdatedAt": updated,
        "resources": [],
    }


def test_a_named_member_of_their_own_project_reports_that_role():
    owners = _owner_rollup(
        [_deployment("alice", "p1")],
        [_project("p1", members=[{"email": "alice", "type": "user"}])],
    )
    assert owners[0]["access"] == "member"


def test_the_strongest_role_wins_when_an_owner_holds_several():
    """A viewer grant says nothing extra once the same person administers the
    project, and the column has room for one answer."""
    owners = _owner_rollup(
        [_deployment("alice", "p1")],
        [
            _project(
                "p1",
                administrators=[{"email": "alice"}],
                viewers=[{"email": "alice"}],
            )
        ],
    )
    assert owners[0]["access"] == "administrator"


def test_a_grant_elsewhere_is_not_a_grant_here():
    """Holding a role in some other project does not let somebody act on the
    deployments they own in this one."""
    owners = _owner_rollup(
        [_deployment("bob", "p1")],
        [
            _project("p1", members=[{"email": "alice"}]),
            _project("p2", members=[{"email": "bob"}]),
        ],
    )
    assert owners[0]["access"] == "other projects only"


def test_an_owner_nobody_names_and_no_group_covers_has_no_grant():
    owners = _owner_rollup(
        [_deployment("carol", "p1")],
        [_project("p1", members=[{"email": "alice"}])],
    )
    assert owners[0]["access"] == "no grant found"
    assert owners[0]["access_state"] == "none"


def test_the_domain_is_not_required_to_match():
    """ownedBy and a project principal's email are both usernames, but the
    builds do not agree on whether they carry the domain."""
    owners = _owner_rollup(
        [_deployment("alice", "p1")],
        [_project("p1", members=[{"email": "ALICE@corp.local"}])],
    )
    assert owners[0]["access"] == "member"


def test_group_only_membership_withholds_the_column_entirely():
    """With nothing but groups on the project lists, every owner would read as
    ungranted - which says more about the API than about the estate."""
    projects = [_project("p1", members=[{"email": "platform-team", "type": "group"}])]
    owners = _owner_rollup([_deployment("alice", "p1")], projects)
    assert owners[0]["access"] == ""
    columns = owner_columns(owners, projects)
    assert columns["access"] is False
    assert columns["unreadable_groups"] == 1


def test_a_group_that_expanded_grants_its_members_the_project_role():
    """The whole point: most access on an AD estate arrives this way."""
    projects = [_project("p1", members=[{"email": "platform-team@x@x", "type": "group"}])]
    identity = {
        "collected": True,
        "groups": [
            {
                "principal": "platform-team@x@x",
                "name": "platform-team@x",
                "projects": ["p1"],
                "members": ["alice@x"],
                "members_read": True,
            }
        ],
        "unresolved": [],
    }
    owners = _owner_rollup([_deployment("alice", "p1")], projects, identity)
    assert owners[0]["access"] == "member (via platform-team@x)"
    assert owners[0]["access_state"] == "granted"


def test_an_unreadable_group_leaves_only_that_project_undetermined():
    """Doubt belongs where the unreadable grant is, not everywhere. Poisoning
    every owner would leave the finding unable to fire at all."""
    projects = [
        _project("p1", members=[{"email": "ghost@x@x", "type": "group"}]),
        _project("p2", members=[{"email": "alice"}]),
    ]
    identity = {"collected": True, "groups": [], "unresolved": [{"principal": "ghost@x@x"}]}
    owners = _owner_rollup(
        [_deployment("carol", "p1"), _deployment("dave", "p2")], projects, identity
    )
    by_owner = {o["owner"]: o for o in owners}
    assert by_owner["carol"]["access"] == "not determined"
    assert by_owner["carol"]["access_state"] == "unresolved"
    # p2 carries no unreadable grant, so dave's absence from it means something.
    assert by_owner["dave"]["access_state"] == "none"


def test_unreadable_projects_withhold_the_column():
    """No project documents means the lists were never seen, not that nobody
    is a member."""
    owners = _owner_rollup([_deployment("alice", "p1")], [])
    assert owners[0]["access"] == ""
    assert owner_columns(owners, [])["access"] is False


def test_the_unknown_owner_row_makes_no_access_claim():
    """ "(unknown)" is a gap in the deployment record, not a person to look up."""
    owners = _owner_rollup(
        [{"projectId": "p1", "resources": []}],
        [_project("p1", members=[{"email": "alice"}])],
    )
    assert owners[0]["owner"] == "(unknown)"
    assert owners[0]["access"] == ""


def test_last_activity_is_the_newest_touch_across_what_they_own():
    owners = _owner_rollup(
        [
            _deployment("alice", "p1", updated="2024-03-04T09:00:00Z"),
            _deployment("alice", "p1", updated="2026-07-01T09:00:00Z"),
            _deployment("alice", "p1", updated="2025-05-05T09:00:00Z"),
        ],
        [],
    )
    assert owners[0]["last_activity"] == "2026-07-01"


def test_last_activity_falls_back_to_creation_and_stays_empty_without_either():
    """A deployment nothing has touched since it was created still has a date;
    one carrying neither timestamp must not invent one."""
    dated = _owner_rollup([{"ownedBy": "a", "createdAt": "2025-02-03T00:00:00Z"}], [])
    assert dated[0]["last_activity"] == "2025-02-03"
    undated = _owner_rollup([{"ownedBy": "b"}], [])
    assert undated[0]["last_activity"] == ""
    assert owner_columns(undated, [])["activity"] is False


def test_the_columns_reach_the_report(sample_data, tmp_path):
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "owners.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    table = html[html.index("Deployments by Owner") :]
    table = table[: table.index("</table>")]
    assert "<th>Last activity</th>" in table
    assert "<th>Project access</th>" in table
    # alice is named on Platform; bob is reached through a group.
    assert "member" in table
    assert "via platform-team@x" in table
    # The caveat travels with the column, not as a general disclaimer.
    assert "could not be checked" in html
