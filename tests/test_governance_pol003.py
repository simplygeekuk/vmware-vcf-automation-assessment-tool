"""Focused tests for the overlapping-policy governance check."""

import pytest

from vcf_automation_assessment_tool.checks.governance import (
    _criteria_project_refs,
    _criteria_summary,
    _day2_overlap_lines,
    _grant_shape,
    _grants_covered,
    _is_day2_action_policy,
    _listed,
    _policy_grants,
    pol_003_overlapping_policies,
)
from vcf_automation_assessment_tool.models import AssessmentData, Severity

ACTION_TYPE = "com.vmware.policy.deployment.action"
APPROVAL_TYPE = "com.vmware.policy.deployment.approval"
LEASE_TYPE = "com.vmware.policy.deployment.lease"


def _policy(
    policy_id,
    name,
    *,
    type_id=ACTION_TYPE,
    project_id=None,
    definition=None,
    scope=None,
    enforcement_type="HARD",
):
    policy = {
        "id": policy_id,
        "name": name,
        "typeId": type_id,
        "enforcementType": enforcement_type,
    }
    if project_id is not None:
        policy["projectId"] = project_id
    if definition is not None:
        policy["definition"] = definition
    if scope is not None:
        policy["scopeCriteria"] = scope
    return policy


def _plain(*actions):
    return {"actions": list(actions)}


def _allowed(*entries):
    return {"allowedActions": list(entries)}


def _entry(actions, authorities=None):
    entry = {"actions": actions}
    if authorities is not None:
        entry["authorities"] = authorities
    return entry


def _data(policies, projects=None):
    data = AssessmentData()
    data.raw["governance"] = {"policies": policies}
    data.derived["project_names"] = (
        projects
        if projects is not None
        else {
            "p1": "Alpha",
            "p2": "Beta",
            "p3": "Gamma",
        }
    )
    return data


def test_criteria_project_refs_unions_supported_alternatives_case_insensitively():
    scope = {
        "MATCHEXPRESSION": {
            "or": [
                {"key": "project.name", "operator": "EQUALS", "value": "Alpha"},
                {"key": "projectId", "operator": "in", "value": ["p2", "p3"]},
            ]
        }
    }

    assert _criteria_project_refs(scope) == ({"Alpha", "p2", "p3"}, True)


@pytest.mark.parametrize(
    "clause",
    [
        {"key": "project.name", "operator": "contains", "value": "Alpha"},
        {"key": "deployment.name", "operator": "equals", "value": "Alpha"},
        {"key": "projectName", "operator": "equals", "value": ["Alpha"]},
        {"key": "projectName", "operator": "in", "value": ["Alpha", 1]},
        {"key": 1, "operator": "equals", "value": "Alpha"},
    ],
)
def test_criteria_project_refs_marks_unsupported_clauses_partly_evaluated(clause):
    scope = {
        "and": [
            {"key": "projectName", "operator": "equals", "value": "Beta"},
            clause,
        ]
    }

    assert _criteria_project_refs(scope) == ({"Beta"}, False)


def test_criteria_project_refs_drops_multiple_project_bearing_and_branches():
    scope = {
        "and": [
            {"key": "project.name", "operator": "equals", "value": "Alpha"},
            {
                "or": [
                    {"key": "projectId", "operator": "eq", "value": "p2"},
                    {"key": "projectId", "operator": "eq", "value": "p3"},
                ]
            },
        ]
    }

    assert _criteria_project_refs(scope) == (set(), False)


@pytest.mark.parametrize(
    "scope",
    [
        {"not": {"key": "project.name", "operator": "eq", "value": "Alpha"}},
        {"nor": [{"key": "project.name", "operator": "eq", "value": "Alpha"}]},
        "not a criteria object",
    ],
)
def test_criteria_project_refs_does_not_descend_unknown_or_negated_shapes(scope):
    assert _criteria_project_refs(scope) == (set(), False)


@pytest.mark.parametrize(
    ("type_id", "expected"),
    [
        (ACTION_TYPE, True),
        ("action", True),
        (APPROVAL_TYPE, False),
        ("com.example.action.extra", False),
        (None, False),
    ],
)
def test_is_day2_action_policy_checks_the_type_id_tail(type_id, expected):
    assert _is_day2_action_policy(type_id) is expected


def test_policy_grants_reads_allowed_actions_and_preserves_audiences():
    policy = {
        "definition": _allowed(
            _entry(["Delete", "Resize", "Delete"], ["USER:admin", "GROUP:operators"]),
            _entry(["PowerOff"]),
        )
    }

    assert _policy_grants(policy) == [
        (
            frozenset({"USER:admin", "GROUP:operators"}),
            frozenset({"Delete", "Resize"}),
        ),
        (frozenset(), frozenset({"PowerOff"})),
    ]


def test_policy_grants_supports_the_plain_legacy_shape():
    assert _policy_grants({"definition": _plain("Delete", "Resize", "Delete")}) == [
        (frozenset(), frozenset({"Delete", "Resize"}))
    ]


def test_policy_grants_prefers_allowed_actions_when_both_shapes_are_present():
    definition = _allowed(_entry(["Delete"], ["USER:admin"]))
    definition["actions"] = ["Resize"]

    assert _policy_grants({"definition": definition}) == [
        (frozenset({"USER:admin"}), frozenset({"Delete"}))
    ]


@pytest.mark.parametrize(
    "definition",
    [
        None,
        {},
        {"actions": []},
        {"actions": "Delete"},
        {"actions": ["Delete", {"id": "Resize"}]},
        {"allowedActions": "not-a-list"},
        {"allowedActions": ["not-an-entry"]},
        _allowed(_entry([])),
        _allowed(_entry(["Delete"], "USER:admin")),
        _allowed(_entry(["Delete", 1], ["USER:admin"])),
    ],
)
def test_policy_grants_rejects_ambiguous_or_malformed_definitions(definition):
    policy = {} if definition is None else {"definition": definition}
    assert _policy_grants(policy) is None


def test_policy_grants_treats_an_empty_allowed_actions_collection_as_ambiguous():
    assert _policy_grants({"definition": {"allowedActions": []}}) is None


def test_grants_covered_combines_org_entries_for_each_authority():
    org_grants = [
        (frozenset({"USER:admin"}), frozenset({"Delete"})),
        (frozenset({"USER:admin", "GROUP:ops"}), frozenset({"Resize"})),
    ]
    project_grants = [
        (frozenset({"USER:admin"}), frozenset({"Delete", "Resize"})),
    ]

    assert _grants_covered(project_grants, org_grants) == (True, set())


def test_grants_covered_requires_actions_for_every_project_authority():
    org_grants = [(frozenset({"USER:admin"}), frozenset({"Delete", "Resize"}))]
    project_grants = [
        (frozenset({"USER:admin", "GROUP:ops"}), frozenset({"Delete", "Resize"})),
    ]

    assert _grants_covered(project_grants, org_grants) == (False, {"Delete", "Resize"})


def test_grants_covered_matches_unattributed_grants_only_to_unattributed_grants():
    actions = frozenset({"Delete"})

    assert _grants_covered([(frozenset(), actions)], [(frozenset(), actions)]) == (True, set())
    assert _grants_covered([(frozenset(), actions)], [(frozenset({"USER:admin"}), actions)]) == (
        False,
        {"Delete"},
    )
    assert _grants_covered([(frozenset({"USER:admin"}), actions)], [(frozenset(), actions)]) == (
        False,
        {"Delete"},
    )


@pytest.mark.parametrize(
    ("grants", "expected"),
    [
        ([(frozenset(), frozenset({"Delete"}))], "plain"),
        ([(frozenset({"USER:admin"}), frozenset({"Delete"}))], "attributed"),
        (
            [
                (frozenset(), frozenset({"Delete"})),
                (frozenset({"USER:admin"}), frozenset({"Resize"})),
            ],
            None,
        ),
    ],
)
def test_grant_shape_requires_a_consistent_audience_style(grants, expected):
    assert _grant_shape(grants) == expected


def test_listed_orders_by_project_and_caps_the_output():
    members = [("Zulu", "Third"), ("Alpha", "Second"), ("Alpha", "First")]

    assert _listed(members, cap=2) == ("\n\u2022 First (Alpha)\n\u2022 Second (Alpha)\nand 1 more.")


def test_day2_overlap_lines_buckets_equal_enforcement_grants_and_unreadable_policies():
    org = _policy(
        "org",
        "Org",
        definition=_allowed(_entry(["Delete", "Resize"], ["USER:admin"])),
    )
    overlaps = [
        _policy(
            "covered",
            "Covered",
            project_id="p1",
            definition=_allowed(_entry(["Delete"], ["USER:admin"])),
        ),
        _policy(
            "adds",
            "Adds actions",
            project_id="p2",
            definition=_allowed(_entry(["Delete", "Snapshot"], ["USER:admin"])),
        ),
        _policy("unreadable", "Unreadable", project_id="p3"),
    ]

    lines = _day2_overlap_lines(org, overlaps, {"p1": "Alpha", "p2": "Beta", "p3": "Gamma"})

    assert lines == [
        "grant nothing this policy does not already grant, delete candidates under "
        "the platform's union merging:\n\u2022 Covered (Alpha)",
        "still grant something this policy does not, so deleting one revokes what "
        "it grants:\n\u2022 Adds actions (Beta): 1 action(s)",
        "not compared (definition shape not readable):\n\u2022 Unreadable (Gamma)",
    ]


def test_day2_overlap_lines_classifies_enforcement_precedence_before_reading_grants():
    hard_org = _policy("org", "Hard org", definition=_plain("Delete"))
    soft_copy = _policy("soft", "Soft copy", project_id="p1", enforcement_type="SOFT")
    custom_copy = _policy("custom", "Custom copy", project_id="p2", enforcement_type="CUSTOM")

    assert _day2_overlap_lines(
        hard_org, [soft_copy, custom_copy], {"p1": "Alpha", "p2": "Beta"}
    ) == [
        "SOFT copies made inert by this HARD policy (hard supersedes soft):\n"
        "\u2022 Soft copy (Alpha)",
        "not compared (enforcement types differ outside the documented HARD/SOFT pair):\n"
        "\u2022 Custom copy (Beta)",
    ]

    soft_org = _policy("org", "Soft org", definition=_plain("Delete"), enforcement_type="SOFT")
    hard_copy = _policy("hard", "Hard copy", project_id="p1")
    assert _day2_overlap_lines(soft_org, [hard_copy], {"p1": "Alpha"}) == [
        "HARD copies that displace this SOFT policy for their project:\n\u2022 Hard copy (Alpha)"
    ]


def test_day2_overlap_lines_reports_when_org_definition_is_unreadable():
    overlap = _policy("copy", "Copy", project_id="p1", definition=_plain("Delete"))
    assert _day2_overlap_lines(_policy("org", "Org"), [overlap], {"p1": "Alpha"}) == [
        "not compared (this policy's own definition shape is not readable):\n\u2022 Copy (Alpha)"
    ]


@pytest.mark.parametrize(
    ("org_definition", "copy_definition"),
    [
        (_plain("Delete"), _allowed(_entry(["Delete"], ["USER:admin"]))),
        (
            _allowed(
                _entry(["Delete"], ["USER:admin"]),
                _entry(["Resize"]),
            ),
            _allowed(_entry(["Delete"], ["USER:admin"])),
        ),
    ],
)
def test_day2_overlap_lines_does_not_compare_incompatible_audience_shapes(
    org_definition, copy_definition
):
    org = _policy("org", "Org", definition=org_definition)
    overlap = _policy("copy", "Copy", project_id="p1", definition=copy_definition)

    assert _day2_overlap_lines(org, [overlap], {"p1": "Alpha"}) == [
        "not compared (one policy names the users and groups it grants to and the "
        "other does not):\n\u2022 Copy (Alpha)"
    ]


def test_pol_003_reports_audience_aware_day2_verdicts_for_same_type_overlaps():
    policies = [
        _policy(
            "org",
            "Org actions",
            definition=_allowed(_entry(["Delete", "Resize"], ["USER:admin"])),
        ),
        _policy(
            "alpha",
            "Alpha actions",
            project_id="p1",
            definition=_allowed(_entry(["Delete"], ["USER:admin"])),
        ),
        _policy(
            "beta",
            "Beta actions",
            project_id="p2",
            definition=_allowed(_entry(["Resize"], ["GROUP:ops"])),
        ),
        _policy("lease", "Alpha lease", type_id=LEASE_TYPE, project_id="p1"),
        _policy("missing", "Missing project", project_id="missing"),
    ]

    findings = pol_003_overlapping_policies(_data(policies))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "POL-003"
    assert finding.severity is Severity.INFO
    assert finding.title == "Projects covered by overlapping policies of the same type"
    assert [row.name for row in finding.affected] == ["Org actions"]
    row = finding.affected[0]
    assert row.kind == "policy"
    assert row.id == "org"
    assert "HARD day-2 action policy scoped to the whole organization" in row.detail
    assert "2 project-scoped day-2 action policy(ies)" in row.detail
    assert "delete candidates" in row.detail
    assert "Alpha actions (Alpha)" in row.detail
    # The actions it would revoke are counted; the full list stays in the JSON dump.
    assert "Beta actions (Beta): 1 action(s)" in row.detail
    assert "Alpha lease" not in row.detail
    assert "Missing project" not in row.detail
    assert "Grants are compared per audience" in finding.recommendation


def test_pol_003_resolves_scope_criteria_and_labels_partial_evaluation():
    scope = {
        "and": [
            {
                "or": [
                    {"key": "project.name", "operator": "equals", "value": "Alpha"},
                    {"key": "project.id", "operator": "eq", "value": "p2"},
                ]
            },
            {"key": "deployment.name", "operator": "contains", "value": "prod"},
        ]
    }
    policies = [
        _policy("org", "Scoped org", definition=_plain("Delete"), scope=scope),
        _policy("alpha", "For Alpha", project_id="p1", definition=_plain("Delete")),
        _policy("beta", "For Beta", project_id="p2", definition=_plain("Delete")),
        _policy("gamma", "For Gamma", project_id="p3", definition=_plain("Delete")),
    ]

    row = pol_003_overlapping_policies(_data(policies))[0].affected[0]

    assert "2 project(s) via scope criteria, criteria only partly evaluated" in row.detail
    assert "\u2022 For Alpha (Alpha)\n\u2022 For Beta (Beta)" in row.detail
    assert "For Gamma" not in row.detail


def test_pol_003_does_not_apply_day2_grant_semantics_to_approval_policies():
    policies = [
        _policy(
            "org",
            "Org approvals",
            type_id=APPROVAL_TYPE,
            definition=_plain("Delete"),
        ),
        _policy(
            "project",
            "Project approvals",
            type_id=APPROVAL_TYPE,
            project_id="p1",
            definition=_plain("Delete"),
            enforcement_type="SOFT",
        ),
    ]

    detail = pol_003_overlapping_policies(_data(policies))[0].affected[0].detail

    assert "project-scoped approval policy(ies)" in detail
    assert "enforcement differs between the overlapping policies" in detail
    assert "delete candidates" not in detail


def test_pol_003_orders_org_policies_by_overlap_count_then_name():
    policies = [
        _policy("org-z", "Zulu", definition=_plain("Delete")),
        _policy(
            "org-a",
            "Alpha",
            definition=_plain("Delete"),
            scope={"key": "projectId", "operator": "equals", "value": "p1"},
        ),
        _policy("org-b", "Beta", definition=_plain("Delete")),
        _policy("p1", "Project one", project_id="p1", definition=_plain("Delete")),
        _policy("p2", "Project two", project_id="p2", definition=_plain("Delete")),
    ]

    affected = pol_003_overlapping_policies(_data(policies))[0].affected

    assert [row.name for row in affected] == ["Beta", "Zulu", "Alpha"]


@pytest.mark.parametrize(
    ("projects", "scope"),
    [
        ({}, None),
        (None, {"key": "projectName", "operator": "equals", "value": "Not present"}),
        (None, {"key": "deployment.name", "operator": "contains", "value": "prod"}),
    ],
)
def test_pol_003_stays_silent_without_reliable_known_project_coverage(projects, scope):
    policies = [
        _policy("org", "Org", definition=_plain("Delete"), scope=scope),
        _policy("copy", "Copy", project_id="p1", definition=_plain("Delete")),
    ]

    assert pol_003_overlapping_policies(_data(policies, projects=projects)) == []


def test_pol_003_caps_the_overlap_member_list():
    projects = {f"p{i:02}": f"Project {i:02}" for i in range(10)}
    policies = [_policy("org", "Org", definition=_plain("Delete"))]
    policies.extend(
        _policy(f"copy-{i}", f"Copy {i:02}", project_id=pid, definition=_plain("Delete"))
        for i, pid in enumerate(projects)
    )

    detail = pol_003_overlapping_policies(_data(policies, projects=projects))[0].affected[0].detail

    assert "\u2022 Copy 07 (Project 07)\nand 2 more." in detail
    assert "Copy 08" not in detail


def test_criteria_summary_reads_the_shapes_the_live_build_uses():
    """A policy's own criteria block narrows what it acts on. The shapes here
    are copied from the live documents: a resource tag, a requester test and a
    catalog item id, wrapped in and/or groups."""
    tagged = {
        "criteria": {
            "matchExpression": [
                {
                    "key": "resources",
                    "operator": "hasAny",
                    "value": {
                        "matchExpression": [
                            {
                                "key": "properties.tags",
                                "operator": "hasAny",
                                "value": {
                                    "matchExpression": [
                                        {"key": "key", "operator": "eq", "value": "Archive-Period"}
                                    ]
                                },
                            }
                        ]
                    },
                }
            ]
        }
    }
    assert _criteria_summary(tagged) == (
        "applies only where the deployment carries the tag Archive-Period"
    )

    requester = {
        "criteria": {
            "matchExpression": [
                {
                    "and": [
                        {"key": "requestedBy", "operator": "notEq", "value": "configurationadmin"},
                    ]
                }
            ]
        }
    }
    assert _criteria_summary(requester) == (
        "applies only where the requester is not configurationadmin"
    )

    item = {
        "criteria": {"matchExpression": [{"key": "catalogItemId", "operator": "eq", "value": "i1"}]}
    }
    assert _criteria_summary(item, {"i1": "Update tags"}) == (
        "applies only where the catalog item is Update tags"
    )
    assert "1 named in the policy" in _criteria_summary(item)

    # A clause this walk does not know must widen the wording, never be dropped.
    unknown = {
        "criteria": {"matchExpression": [{"key": "somethingNew", "operator": "eq", "value": "x"}]}
    }
    assert _criteria_summary(unknown) == "applies only to the deployments its own criteria match"
    assert _criteria_summary({}) == ""


def test_pol_003_does_not_compare_a_policy_narrowed_by_its_own_criteria():
    """Live report, 2026-08-26: an organization-wide day-2 policy that acts only
    on deployments tagged Archive-Period was reported as governing every project
    alongside 25 project-scoped copies. It governs what its criteria match, so
    the overlap cannot be read from the two documents."""
    org = _policy("org", "Archived-Deployment-Day2", definition=_plain("Delete"))
    org["criteria"] = {
        "matchExpression": [
            {
                "key": "resources",
                "operator": "hasAny",
                "value": {
                    "matchExpression": [
                        {
                            "key": "properties.tags",
                            "operator": "hasAny",
                            "value": {
                                "matchExpression": [
                                    {"key": "key", "operator": "eq", "value": "Archive-Period"}
                                ]
                            },
                        }
                    ]
                },
            }
        ]
    }
    copy = _policy("copy", "Alpha day-2", project_id="p1", definition=_plain("Delete"))
    data = AssessmentData()
    data.derived["project_names"] = {"p1": "Alpha"}
    data.raw["governance"] = {"policies": [org, copy]}

    assert pol_003_overlapping_policies(data) == []

    # With a second, unnarrowed organization policy the finding exists, and the
    # one left out is named rather than dropped in silence.
    wide = _policy("wide", "Every project day-2", definition=_plain("Delete", "Resize"))
    data.raw["governance"] = {"policies": [org, wide, copy]}
    (finding,) = pol_003_overlapping_policies(data)
    assert [row.name for row in finding.affected] == ["Every project day-2"]
    assert "NOT COMPARED" in finding.recommendation
    assert "Archived-Deployment-Day2" in finding.recommendation
    assert "carries the tag Archive-Period" in finding.recommendation


def test_pol_003_says_when_an_organization_policy_grants_to_named_accounts():
    """Live report: an organization-wide policy granting only to the
    configurationadmin service account read as governing everything a project
    holds, next to project policies that grant to their members."""
    org = _policy("org", "Automation-Day2")
    org["definition"] = {
        "allowedActions": [
            {"actions": ["Deployment.Delete"], "authorities": ["USER:svc-automation"]}
        ]
    }
    copy = _policy("copy", "Alpha day-2", project_id="p1", definition=_plain("Deployment.Delete"))
    data = AssessmentData()
    data.derived["project_names"] = {"p1": "Alpha"}
    data.raw["governance"] = {"policies": [org, copy]}

    (finding,) = pol_003_overlapping_policies(data)
    assert "grants only to svc-automation (user)" in finding.affected[0].detail

    # A role covers whoever holds it, so nothing is claimed about named accounts.
    org["definition"] = {
        "allowedActions": [{"actions": ["Deployment.Delete"], "authorities": ["ROLE:member"]}]
    }
    (finding,) = pol_003_overlapping_policies(data)
    assert "grants only to" not in finding.affected[0].detail


def test_pol_003_leaves_out_an_organization_policy_for_accounts_no_copy_names():
    """Live report, 2026-08-26: Automation-Day2 grants to one service account and
    the 25 project copies grant to their members. Day-2 grants accumulate per
    audience, so neither decides anything for the other and the pair is not an
    overlap to resolve."""
    org = _policy("org", "Automation-Day2")
    org["definition"] = _allowed(_entry(["Deployment.Delete"], ["USER:configurationadmin"]))
    copy = _policy("copy", "Alpha day-2", project_id="p1")
    copy["definition"] = _allowed(_entry(["Deployment.Delete"], ["ROLE:member"]))
    data = AssessmentData()
    data.derived["project_names"] = {"p1": "Alpha"}
    data.raw["governance"] = {"policies": [org, copy]}

    assert pol_003_overlapping_policies(data) == []

    # The same account on both sides is a real overlap and stays reported.
    copy["definition"] = _allowed(
        _entry(["Deployment.Delete", "Deployment.Resize"], ["USER:configurationadmin"])
    )
    (finding,) = pol_003_overlapping_policies(data)
    assert [row.name for row in finding.affected] == ["Automation-Day2"]

    # A role on the organization policy covers whoever holds it, including the
    # people a project policy names, so nothing is skipped on that basis.
    org["definition"] = _allowed(_entry(["Deployment.Delete"], ["ROLE:administrator"]))
    copy["definition"] = _allowed(_entry(["Deployment.Delete"], ["ROLE:member"]))
    (finding,) = pol_003_overlapping_policies(data)
    assert [row.name for row in finding.affected] == ["Automation-Day2"]
