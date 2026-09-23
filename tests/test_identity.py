"""Group expansion: the collector, and the two findings that depend on it.

Most access on an AD estate arrives through groups - on the live run, 322 of
the 380 grants across 69 projects went to groups against 58 to named users.
These tests pin what getting that right means: expanding what can be expanded,
refusing to draw conclusions about what cannot, and reading the several
spellings of one group as one group.
"""

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.client import ApiError
from vcf_automation_assessment_tool.collectors import identity as collector
from vcf_automation_assessment_tool.identity_map import principal_index
from vcf_automation_assessment_tool.models import AssessmentData


class FakeClient:
    """Serves canned pages and records what was asked for."""

    def __init__(self, pages: dict, fail: set[str] | None = None):
        self.pages = pages
        self.fail = fail or set()
        self.calls: list[str] = []

    def iter_csp(self, path, params=None, page_size=None):
        self.calls.append(path)
        if path in self.fail:
            raise ApiError(f"GET {path} -> HTTP 403", status_code=403)
        yield from self.pages.get(path, [])


ORG = "org-1"
GROUPS_PATH = f"/csp/gateway/am/api/orgs/{ORG}/groups"


def _project(pid="p1", **roles):
    return {"id": pid, "name": pid, "orgId": ORG, **roles}


def _group(gid, display, users=1, roles=None):
    return {
        "id": gid,
        "displayName": display,
        "domain": display.split("@")[-1],
        "usersCount": users,
        "organizationRoles": [{"name": r} for r in (roles or ["org_member"])],
    }


def _data(projects):
    data = AssessmentData()
    data.raw["infrastructure"] = {"projects": projects}
    return data


def test_only_groups_a_project_grants_to_are_expanded():
    """The organization's list is a directory - on the live estate the whole
    of it would have been thousands of calls for people no project grants
    anything to."""
    projects = [_project(members=[{"email": "team-a@x@x", "type": "group"}])]
    client = FakeClient(
        {
            GROUPS_PATH: [_group("g1", "team-a@x"), _group("g2", "team-b@x")],
            f"{GROUPS_PATH}/g1/users": [{"username": "alice@x"}],
            f"{GROUPS_PATH}/g2/users": [{"username": "bob@x"}],
        }
    )
    collector.collect(client, _data(projects))

    assert f"{GROUPS_PATH}/g1/users" in client.calls
    assert f"{GROUPS_PATH}/g2/users" not in client.calls


def test_the_doubled_domain_a_project_writes_still_matches_the_group():
    """A project names a group as name@domain@domain; the group's own
    displayName carries the domain once."""
    projects = [_project(administrators=[{"email": "team-a@X.PRI@X.PRI", "type": "group"}])]
    client = FakeClient(
        {
            GROUPS_PATH: [_group("g1", "team-a@x.pri")],
            f"{GROUPS_PATH}/g1/users": [{"username": "alice@x"}],
        }
    )
    data = _data(projects)
    collector.collect(client, data)

    groups = data.raw["identity"]["groups"]
    assert [g["name"] for g in groups] == ["team-a@x.pri"]
    assert groups[0]["members"] == ["alice@x"]


def test_one_group_spelled_three_ways_is_one_group():
    """A live estate wrote the same group as name@domain@domain on one project,
    lower case with the domain once on another, and both on a third. Read per
    spelling it was fetched three times, listed three times, and its fifteen
    members counted three times over thirteen projects nobody could see
    together."""
    projects = [
        _project("p1", members=[{"email": "team-a@X.PRI@X.PRI", "type": "group"}]),
        _project("p2", members=[{"email": "team-a@x.pri", "type": "group"}]),
        _project("p3", viewers=[{"email": "team-a@x.pri@x.pri", "type": "group"}]),
    ]
    client = FakeClient(
        {
            GROUPS_PATH: [_group("g1", "team-a@x.pri")],
            f"{GROUPS_PATH}/g1/users": [{"username": "alice@x"}],
        }
    )
    data = _data(projects)
    collector.collect(client, data)

    groups = data.raw["identity"]["groups"]
    assert len(groups) == 1
    assert groups[0]["projects"] == ["p1", "p2", "p3"]
    # And expanded once: merging after the fetch would still cost three calls.
    assert client.calls.count(f"{GROUPS_PATH}/g1/users") == 1


def test_spellings_of_an_unlistable_group_are_also_one_row():
    """Nothing resolves these, so the spelling is all there is to merge on."""
    projects = [
        _project("p1", members=[{"email": "ghost@X.PRI@X.PRI", "type": "group"}]),
        _project("p2", members=[{"email": "ghost@x.pri", "type": "group"}]),
    ]
    client = FakeClient({GROUPS_PATH: [_group("g1", "team-a@x.pri")]})
    data = _data(projects)
    collector.collect(client, data)

    unresolved = data.raw["identity"]["unresolved"]
    assert len(unresolved) == 1
    assert unresolved[0]["projects"] == ["p1", "p2"]
    assert unresolved[0]["principal"].lower() == "ghost@x.pri"


def test_two_different_domains_are_not_collapsed():
    """Only a repeated domain is the platform's convention. Anything else is
    somebody's actual principal and is left exactly as it was written."""
    assert collector.canonical_principal("svc@one@two") == "svc@one@two"
    assert collector.canonical_principal("svc@x.pri@X.PRI") == "svc@x.pri"


def test_a_group_the_organization_does_not_list_is_recorded_not_dropped():
    projects = [_project(members=[{"email": "ghost@x@x", "type": "group"}])]
    client = FakeClient({GROUPS_PATH: [_group("g1", "team-a@x")]})
    data = _data(projects)
    collector.collect(client, data)

    assert data.raw["identity"]["groups"] == []
    # Recorded with the domain written once: the doubling is the project
    # service's convention, and a reader of the report cannot know that.
    assert data.raw["identity"]["unresolved"] == [{"principal": "ghost@x", "projects": ["p1"]}]


def test_a_short_expansion_is_marked_incomplete():
    """The platform states its own member count. Where the expansion returns
    fewer, absence from the list proves nothing about anybody."""
    projects = [_project(members=[{"email": "team-a@x@x", "type": "group"}])]
    client = FakeClient(
        {
            GROUPS_PATH: [_group("g1", "team-a@x", users=9)],
            f"{GROUPS_PATH}/g1/users": [{"username": "alice@x"}],
        }
    )
    data = _data(projects)
    collector.collect(client, data)

    group = data.raw["identity"]["groups"][0]
    assert group["members_read"] is True
    assert group["members_complete"] is False
    assert group["members_claimed"] == 9


def test_an_expansion_that_403s_is_read_as_unknown_not_as_empty():
    projects = [_project(members=[{"email": "team-a@x@x", "type": "group"}])]
    client = FakeClient({GROUPS_PATH: [_group("g1", "team-a@x")]}, fail={f"{GROUPS_PATH}/g1/users"})
    data = _data(projects)
    collector.collect(client, data)

    group = data.raw["identity"]["groups"][0]
    assert group["members_read"] is False
    assert group["members"] == []
    assert any(e["area"] == "identity" for e in data.errors)


def test_no_rights_to_the_org_list_degrades_to_collecting_nothing():
    """A narrow assessment account must end up knowing nothing here, never
    knowing that nobody has access."""
    projects = [_project(members=[{"email": "team-a@x@x", "type": "group"}])]
    client = FakeClient({}, fail={GROUPS_PATH})
    data = _data(projects)
    collector.collect(client, data)

    assert data.raw["identity"]["collected"] is False
    assert any(e["item"] == "org groups" for e in data.errors)


def test_baseline_roles_are_separated_from_elevated_ones():
    """Every synced group carries org_member and the service user roles, so
    those say nothing; only what is above them does."""
    projects = [_project(members=[{"email": "team-a@x@x", "type": "group"}])]
    client = FakeClient(
        {
            GROUPS_PATH: [
                {
                    **_group("g1", "team-a@x"),
                    "organizationRoles": [{"name": "org_member"}],
                    "serviceRoles": [
                        {"serviceRoleNames": ["automationservice:user", "catalog:admin"]}
                    ],
                }
            ],
            f"{GROUPS_PATH}/g1/users": [{"username": "alice@x"}],
        }
    )
    data = _data(projects)
    collector.collect(client, data)

    group = data.raw["identity"]["groups"][0]
    assert group["roles"] == ["automationservice:user", "catalog:admin", "org_member"]
    assert group["elevated_roles"] == ["catalog:admin"]


# --------------------------------------------------------------- findings


def _estate(owner_project, projects, identity, owner="carol"):
    data = AssessmentData()
    data.raw["infrastructure"] = {"projects": projects}
    data.raw["identity"] = identity
    data.raw["deployments"] = {
        "deployments": [
            {
                "id": "d1",
                "name": "thing",
                "status": "CREATE_SUCCESSFUL",
                "projectId": owner_project,
                "projectName": owner_project,
                "ownedBy": owner,
                "resources": [],
            }
        ],
        "deleted": [],
        "request_history": {"collected": False},
    }
    data.derived["project_names"] = {p["id"]: p["name"] for p in projects}
    run_checks(data)
    return data.findings


def _get(findings, check_id):
    return next((f for f in findings if f.check_id == check_id), None)


def test_dep_009_flags_an_owner_with_no_grant_anywhere():
    findings = _estate(
        "p1",
        [_project("p1", members=[{"email": "alice"}])],
        {"collected": True, "groups": [], "unresolved": []},
    )
    finding = _get(findings, "DEP-009")
    assert finding and [a.name for a in finding.affected] == ["carol"]
    # The wording must not turn a missing grant into a claim about a person.
    assert "not evidence an account was deleted" in finding.recommendation


def test_dep_009_is_silent_for_an_owner_a_group_covers():
    findings = _estate(
        "p1",
        [_project("p1", members=[{"email": "team@x@x", "type": "group"}])],
        {
            "collected": True,
            "groups": [
                {
                    "principal": "team@x@x",
                    "name": "team@x",
                    "projects": ["p1"],
                    "members": ["carol@x"],
                    "members_read": True,
                }
            ],
            "unresolved": [],
        },
    )
    assert _get(findings, "DEP-009") is None


def test_dep_009_is_silent_where_a_group_could_not_be_expanded():
    findings = _estate(
        "p1",
        [_project("p1", members=[{"email": "ghost@x@x", "type": "group"}])],
        {"collected": True, "groups": [], "unresolved": [{"principal": "ghost@x@x"}]},
    )
    assert _get(findings, "DEP-009") is None


def test_dep_009_is_silent_when_groups_were_never_expanded():
    """Without expansion this would flag nearly every owner on an AD estate."""
    findings = _estate(
        "p1",
        [_project("p1", members=[{"email": "alice"}])],
        {"collected": False, "groups": [], "unresolved": []},
    )
    assert _get(findings, "DEP-009") is None


def test_dep_009_leaves_service_accounts_alone():
    """The assessment's own identity owns whatever it created."""
    findings = _estate(
        "p1",
        [_project("p1", members=[{"email": "alice"}])],
        {"collected": True, "groups": [], "unresolved": []},
        owner="configurationadmin",
    )
    assert _get(findings, "DEP-009") is None


def test_prj_003_reports_unlistable_groups_without_calling_them_stale():
    findings = _estate(
        "p1",
        [_project("p1", members=[{"email": "ghost@x@x", "type": "group"}])],
        {
            "collected": True,
            "groups": [],
            "unresolved": [{"principal": "ghost@x@x", "projects": ["p1"]}],
        },
    )
    finding = _get(findings, "PRJ-003")
    assert finding and finding.affected[0].name == "ghost@x@x"
    text = finding.recommendation.lower()
    assert "stale" not in text and "deleted" not in text
    # It points at the thing the operator can actually check.
    assert "identity source" in text


def test_the_index_treats_a_group_grant_as_a_grant():
    projects = [_project("p1", administrators=[{"email": "team@x@x", "type": "group"}])]
    identity = {
        "collected": True,
        "groups": [
            {
                "principal": "team@x@x",
                "name": "team@x",
                "projects": ["p1"],
                "members": ["alice@x"],
                "members_read": True,
            }
        ],
        "unresolved": [],
    }
    index = principal_index(projects, identity)
    assert index["by_identity"]["alice@x"]["p1"] == ("administrator", "team@x")
    assert index["resolved_groups"] == ["team@x"]
    assert index["unreadable_groups"] == []


def test_one_unexpandable_group_spelled_twice_is_counted_once():
    """The ownership table's note counts these and PRJ-003 lists them. Counted
    per spelling the two numbers describe the same groups and disagree."""
    projects = [
        _project("p1", members=[{"email": "ghost@X.PRI@X.PRI", "type": "group"}]),
        _project("p2", members=[{"email": "ghost@x.pri", "type": "group"}]),
    ]
    index = principal_index(projects, {"collected": True, "groups": [], "unresolved": []})
    assert len(index["unreadable_groups"]) == 1
