"""Catalog access: how items group into sharing patterns."""

from vcf_automation_assessment_tool.access import build_catalog_access
from vcf_automation_assessment_tool.models import AssessmentData


def _data(items, project_names, policies=None, sources=None):
    data = AssessmentData()
    data.raw["catalog"] = {"items": items, "sources": sources or []}
    data.raw["governance"] = {"policies": policies or []}
    data.derived["project_names"] = project_names
    return data


def _sharing_policy(policy_id, name, project_id, content):
    return {
        "id": policy_id,
        "name": name,
        "typeId": "com.vmware.policy.catalog.entitlement",
        "enforcementType": "HARD",
        "projectId": project_id,
        "definition": {"entitledUsers": [{"userType": "USER", "items": content}]},
    }


def _item(i, name, projects):
    return {"id": i, "name": name, "sourceName": "src", "projectIds": projects}


def test_identical_sharing_sets_group_into_one_pattern():
    data = _data(
        [
            _item("a", "Alpha", ["p1", "p2"]),
            _item("b", "Beta", ["p2", "p1"]),  # same set, different order
            _item("c", "Gamma", ["p1"]),
            _item("d", "Delta", []),
        ],
        {"p1": "Platform", "p2": "Dev", "p3": "Sec"},
    )
    build_catalog_access(data)
    patterns = data.derived["catalog_access"]
    assert len(patterns) == 3
    # Widest sharing first, unshared last.
    assert [p["project_names"] for p in patterns] == [["Dev", "Platform"], ["Platform"], []]
    assert [i["name"] for i in patterns[0]["items"]] == ["Alpha", "Beta"]
    # p3 exists, so 2-of-3 projects is not "all projects".
    assert patterns[0]["all_projects"] is False


def test_unknown_project_id_labelled_not_leaked():
    # Live lesson: a sharing grant pointed at a deleted project and its raw
    # UUID rendered in the access map. Unknown ids get a readable label, in
    # both the pattern names and the policy scope column.
    stale = "320196fd-d907-4a60-8eef-259e4d803494"
    data = _data(
        [_item("a", "Alpha", [])],
        {"p1": "Platform"},
        policies=[
            _sharing_policy(
                "pol1", "Stale share", stale, [{"type": "CATALOG_ITEM_IDENTIFIER", "id": "a"}]
            )
        ],
    )
    build_catalog_access(data)
    names = data.derived["catalog_access"][0]["project_names"]
    assert names == ["(unknown project 320196fd)"]
    assert stale not in " ".join(names)
    assert data.derived["content_sharing"][0]["scope"] == "(unknown project 320196fd)"


def test_all_projects_flag_set_when_set_covers_every_project():
    data = _data([_item("a", "Alpha", ["p1", "p2"])], {"p1": "Platform", "p2": "Dev"})
    build_catalog_access(data)
    assert data.derived["catalog_access"][0]["all_projects"] is True


def test_org_scoped_source_policy_shares_with_every_project():
    # Content sharing policy with no projectId = org scope; a whole-source
    # grant expands to every item imported from that source.
    items = [_item("a", "Alpha", []), _item("b", "Beta", [])]
    for i in items:
        i["sourceId"] = "s1"
    policy = _sharing_policy(
        "csp1", "share-all", "", [{"id": "s1", "type": "CATALOG_SOURCE_IDENTIFIER"}]
    )
    data = _data(
        items,
        {"p1": "Platform", "p2": "Dev"},
        policies=[policy],
        sources=[{"id": "s1", "name": "VM Templates"}],
    )
    build_catalog_access(data)
    assert items[0]["projectIds"] == ["p1", "p2"]
    patterns = data.derived["catalog_access"]
    assert len(patterns) == 1 and patterns[0]["all_projects"] is True
    row = data.derived["content_sharing"][0]
    assert row["scope"] == "organization"
    assert row["shares"] == ["source: VM Templates"]


def test_project_scoped_item_policy_shares_one_item():
    items = [_item("a", "Alpha", []), _item("b", "Beta", [])]
    policy = _sharing_policy(
        "csp2", "share-alpha", "p1", [{"id": "a", "type": "CATALOG_ITEM_IDENTIFIER"}]
    )
    data = _data(items, {"p1": "Platform", "p2": "Dev"}, policies=[policy])
    build_catalog_access(data)
    assert items[0]["projectIds"] == ["p1"]
    assert items[1]["projectIds"] == []
    row = data.derived["content_sharing"][0]
    assert row["scope"] == "Platform"
    assert row["shares"] == ["item: Alpha"]


def test_sharing_policies_alone_are_evidence():
    # A visible sharing policy makes empty projectIds a real "unshared" even
    # without entitlements - the map and the unshared pattern must render.
    items = [_item("a", "Alpha", []), _item("b", "Beta", [])]
    policy = _sharing_policy(
        "csp3", "share-alpha", "p1", [{"id": "a", "type": "CATALOG_ITEM_IDENTIFIER"}]
    )
    data = _data(items, {"p1": "Platform"}, policies=[policy])
    build_catalog_access(data)
    patterns = data.derived["catalog_access"]
    assert [p["project_names"] for p in patterns] == [["Platform"], []]


def test_no_map_when_sharing_field_unpopulated():
    # No item carries projectIds and entitlements were never confirmed: the
    # map must not render every item as "not requestable".
    data = _data([_item("a", "Alpha", []), _item("b", "Beta", [])], {"p1": "Platform"})
    build_catalog_access(data)
    assert data.derived["catalog_access"] == []


def test_unshared_pattern_kept_when_entitlements_confirmed_it():
    data = _data([_item("a", "Alpha", [])], {"p1": "Platform"})
    data.raw["catalog"]["entitlements_collected"] = True
    build_catalog_access(data)
    patterns = data.derived["catalog_access"]
    assert len(patterns) == 1
    assert patterns[0]["project_names"] == []


def test_org_share_with_unread_projects_withholds_the_map():
    """An org-scoped sharing policy grants to every project; with the project
    list unread that grant is unexpandable, so an empty projectIds must not
    render as "not requestable" - evidence is withheld instead."""
    from vcf_automation_assessment_tool.access import build_catalog_access, has_sharing_evidence
    from vcf_automation_assessment_tool.models import AssessmentData

    d = AssessmentData()
    d.raw["catalog"] = {"items": [{"id": "i1", "name": "Item", "sourceId": "s1"}]}
    d.raw["governance"] = {
        "policies": [
            {
                "id": "pol",
                "name": "org-share",
                "typeId": "com.vmware.policy.catalog.entitlement",
                "definition": {
                    "entitledUsers": [
                        {"items": [{"type": "CATALOG_SOURCE_IDENTIFIER", "id": "s1"}]}
                    ]
                },
            }
        ]
    }
    assert has_sharing_evidence(d) is False
    build_catalog_access(d)
    assert d.derived["catalog_access"] == []
    # With the project list present the same policy expands normally.
    d.derived["project_names"] = {"p1": "Platform"}
    assert has_sharing_evidence(d) is True
    build_catalog_access(d)
    assert d.derived["catalog_access"][0]["project_names"] == ["Platform"]


def test_malformed_policy_definitions_degrade_instead_of_crashing():
    """A string definition, a null entitledUsers element, or a string content
    entry must not take down the analysis phase after a full collection."""
    from vcf_automation_assessment_tool.access import build_catalog_access
    from vcf_automation_assessment_tool.models import AssessmentData

    d = AssessmentData()
    d.derived["project_names"] = {"p1": "Platform"}
    d.raw["catalog"] = {"items": [{"id": "i1", "name": "Item", "sourceId": "s1"}]}
    d.raw["governance"] = {
        "policies": [
            {
                "id": "a",
                "name": "summary-only",
                "typeId": "x.catalog.entitlement",
                "definition": "unexpanded summary",
            },
            {
                "id": "b",
                "name": "null-user",
                "typeId": "x.catalog.entitlement",
                "definition": {"entitledUsers": [None]},
            },
            {
                "id": "c",
                "name": "string-item",
                "typeId": "x.catalog.entitlement",
                "definition": {"entitledUsers": [{"items": ["not-a-dict"]}]},
            },
        ]
    }
    build_catalog_access(d)  # must not raise
    assert len(d.derived["content_sharing"]) == 3
