"""Flow building: topic applicability per catalog item type."""

from vcf_automation_assessment_tool.flows import _topic_applies, build_flows, flow_topics
from vcf_automation_assessment_tool.models import AssessmentData


def make_data(item_type, resource_types=None, topics=("compute.provision.post",)):
    data = AssessmentData()
    data.raw["catalog"] = {
        "items": [
            {
                "id": "ci1",
                "name": "Item",
                "type": item_type,
                "sourceName": "",
                "projectIds": [],
                "deployment_count": 0,
            }
        ]
    }
    if resource_types is not None:
        data.raw["blueprints"] = {
            "blueprints": [{"id": "ci1", "name": "Item", "resource_types": resource_types}]
        }
    data.raw["extensibility"] = {
        "subscriptions": [
            {
                "id": f"s-{t}",
                "name": f"sub-{t}",
                "eventTopicId": t,
                "blocking": False,
                "disabled": False,
                "runnableType": "extensibility.vco",
                "runnableId": "wf1",
                "runnableName": "wf",
                "criteria": "",
                "scope": "global",
                "criteria_blueprint_ids": [],
                "criteria_project_ids": [],
                "builtin": False,
            }
            for t in topics
        ]
    }
    return data


def topic_names(data):
    build_flows(data)
    return {t["topic"] for t in flow_topics(data.derived["flows"][0])}


def test_vro_workflow_item_never_gets_resource_topics():
    data = make_data(
        "com.vmw.vro.workflow",
        topics=("compute.provision.post", "network.configure", "deployment.request.pre"),
    )
    assert topic_names(data) == {"deployment.request.pre"}


def test_abx_item_never_gets_resource_topics():
    data = make_data("com.vmw.abx.actions", topics=("compute.provision.pre",))
    assert topic_names(data) == set()


def test_design_time_topics_never_attach_even_to_machine_items():
    # blueprint.* fires on template authoring (edit/version/release), not when
    # the item is ordered - a machine blueprint must not pick these up.
    data = make_data(
        "com.vmw.blueprint",
        resource_types=["Cloud.vSphere.Machine"],
        topics=("blueprint.version.configuration", "deployment.request.pre"),
    )
    assert topic_names(data) == {"deployment.request.pre"}


def test_blueprint_with_machine_gets_compute_topics():
    data = make_data(
        "com.vmw.blueprint",
        resource_types=["Cloud.vSphere.Machine"],
        topics=("compute.provision.post", "network.configure"),
    )
    assert topic_names(data) == {"compute.provision.post", "network.configure"}


def test_network_only_blueprint_excludes_compute():
    data = make_data(
        "com.vmw.blueprint",
        resource_types=["Cloud.NSX.Network"],
        topics=("compute.provision.post", "network.configure"),
    )
    assert topic_names(data) == {"network.configure"}


def test_unresolved_blueprint_keeps_topics_as_conditional():
    data = make_data("com.vmw.blueprint", topics=("compute.provision.post",))
    build_flows(data)
    topics = flow_topics(data.derived["flows"][0])
    assert [t["topic"] for t in topics] == ["compute.provision.post"]
    assert topics[0]["subscriptions"][0]["match"] == "unverified"


def test_topic_applies_unit():
    assert _topic_applies("deployment.request.pre", "com.vmw.vro.workflow", None) is True
    assert (
        _topic_applies("blueprint.version.configuration", "com.vmw.blueprint", ["Cloud.Machine"])
        is False
    )
    assert _topic_applies("compute.provision.pre", "com.vmw.vro.workflow", None) is False
    assert _topic_applies("compute.provision.pre", "com.vmw.blueprint", None) is None
    assert _topic_applies("compute.provision.pre", "com.vmw.blueprint", ["Cloud.Machine"]) is True
    assert (
        _topic_applies("storage.allocation.pre", "com.vmw.blueprint", ["Cloud.vSphere.Disk"])
        is True
    )
    assert _topic_applies("compute.provision.pre", "com.vmw.blueprint", ["Cloud.Network"]) is False


def test_unreadable_template_stays_unknown_never_defines_nothing():
    """None = could not read the template (conditional edge), [] = parsed and
    genuinely defines no resources (topic excluded). Conflating them turned
    one failed blueprint GET into a confident exclusion."""
    from vcf_automation_assessment_tool.collectors.blueprints import _resource_types
    from vcf_automation_assessment_tool.flows import _topic_applies

    assert _resource_types("a: [unclosed") is None
    assert _resource_types("just a scalar") is None
    assert _resource_types("inputs: {}\n") is None  # no resources mapping
    assert _resource_types("resources:\n  vm:\n    type: Cloud.vSphere.Machine\n") == [
        "Cloud.vSphere.Machine"
    ]
    assert _resource_types("resources: {}\n") == []

    assert _topic_applies("compute.provision.pre", "com.vmw.blueprint", None) is None
    assert _topic_applies("compute.provision.pre", "com.vmw.blueprint", []) is False


def negation_data():
    """A vRO-workflow day-2 item beside a template item, and a subscription
    that excludes the sentinel the platform stamps on no-template items."""
    data = AssessmentData()
    data.raw["catalog"] = {
        "items": [
            {
                "id": "item-vro",
                "name": "Restart Service",
                "type": "com.vmw.vro.workflow",
                "sourceName": "",
                "projectIds": [],
                "deployment_count": 1,
            },
            {
                "id": "item-bp",
                "name": "Linux VM",
                "type": "com.vmw.blueprint",
                "sourceName": "",
                "projectIds": [],
                "deployment_count": 1,
            },
        ]
    }
    data.raw["blueprints"] = {
        "blueprints": [
            {"id": "bp-1", "name": "Linux VM", "resource_types": ["Cloud.vSphere.Machine"]}
        ]
    }
    data.raw["deployments"] = {
        "deployments": [
            {"catalogItemId": "item-vro", "blueprintId": "inline-blueprint"},
            {"catalogItemId": "item-bp", "blueprintId": "bp-1"},
        ]
    }
    data.raw["extensibility"] = {
        "subscriptions": [
            {
                "id": "s1",
                "name": "guard",
                "eventTopicId": "deployment.request.pre",
                "blocking": False,
                "disabled": False,
                "runnableType": "extensibility.vco",
                "runnableId": "wf1",
                "runnableName": "wf",
                "builtin": False,
                "criteria": 'event.data.blueprintId != "inline-blueprint"',
                "scope": "blueprint",
                "criteria_blueprint_ids": [],
                "criteria_project_ids": [],
                "criteria_blueprint_eq": [],
                "criteria_blueprint_ne": ["inline-blueprint"],
                "criteria_project_eq": [],
                "criteria_project_ne": [],
            }
        ]
    }
    return data


def matched_subs(data):
    build_flows(data)
    return {
        f["item_name"]: [
            (s["name"], s["match"]) for t in flow_topics(f) for s in t["subscriptions"]
        ]
        for f in data.derived["flows"]
    }


def set_criteria(data, criteria, eq, ne):
    sub = data.raw["extensibility"]["subscriptions"][0]
    sub["criteria"] = criteria
    sub["criteria_blueprint_eq"] = eq
    sub["criteria_blueprint_ne"] = ne
    sub["criteria_blueprint_ids"] = eq
    return sub


def test_negated_criteria_excludes_the_item_it_names():
    # The reported bug: a `blueprintId != "inline-blueprint"` guard parsed to
    # nothing, fell through to the conditional scope, and was then drawn on
    # every catalog item including the vRO-workflow ones it excludes.
    assert matched_subs(negation_data())["Restart Service"] == []


def test_negated_criteria_confirms_the_items_it_does_not_name():
    # And it must stay solid, not dashed, on items it definitely fires for.
    assert matched_subs(negation_data())["Linux VM"] == [("guard", "confirmed")]


def test_no_template_sentinel_is_learned_for_never_deployed_items():
    # An item of the same kind with no deployments of its own still carries
    # the sentinel the rest of the estate shows.
    data = negation_data()
    data.raw["catalog"]["items"].append(
        {
            "id": "item-vro2",
            "name": "Never Requested",
            "type": "com.vmw.vro.workflow",
            "sourceName": "",
            "projectIds": [],
            "deployment_count": 0,
        }
    )
    assert matched_subs(data)["Never Requested"] == []


def test_allow_list_cannot_match_an_item_that_has_no_template():
    # A blueprint-scoped subscription can never fire for a vRO-workflow item;
    # it used to render there as a conditional edge.
    data = negation_data()
    set_criteria(data, "event.data.blueprintId == 'bp-1'", ["bp-1"], [])
    subs = matched_subs(data)
    assert subs["Restart Service"] == []
    assert subs["Linux VM"] == [("guard", "confirmed")]


def test_mixed_negation_and_equality_is_not_read_as_the_equality_alone():
    # `!= sentinel || == bp-1` matches Linux VM on both halves, and the vRO
    # item on neither. Reading only the `==` half inverted the expression.
    data = negation_data()
    set_criteria(
        data,
        "event.data.blueprintId != 'inline-blueprint' || event.data.blueprintId == 'bp-1'",
        ["bp-1"],
        ["inline-blueprint"],
    )
    subs = matched_subs(data)
    assert subs["Restart Service"] == []
    assert subs["Linux VM"] == [("guard", "confirmed")]


def test_legacy_subscription_without_comparison_keys_keeps_its_allow_list():
    """Subscriptions collected before negation was parsed carry only
    criteria_blueprint_ids. Reading the absent equals key as "no constraint"
    would turn a narrowly targeted subscription into a match on every item."""
    data = negation_data()
    sub = set_criteria(data, "event.data.blueprintId == 'bp-1'", ["bp-1"], [])
    for key in (
        "criteria_blueprint_eq",
        "criteria_blueprint_ne",
        "criteria_project_eq",
        "criteria_project_ne",
    ):
        del sub[key]
    subs = matched_subs(data)
    assert subs["Restart Service"] == []
    assert subs["Linux VM"] == [("guard", "confirmed")]


def test_undecidable_criteria_is_still_shown_as_conditional():
    # No evidence of what the item's blueprintId would be: include it, but
    # never claim the match.
    data = negation_data()
    data.raw["deployments"] = {"deployments": []}
    data.raw["blueprints"] = {"blueprints": []}
    set_criteria(data, "event.data.blueprintId != 'inline-blueprint'", [], ["inline-blueprint"])
    assert matched_subs(data)["Linux VM"] == [("guard", "unverified")]


def test_partly_read_criteria_excludes_but_never_confirms():
    """The live shape: `blueprintId != sentinel && eventType == 'X'`. The
    sentinel settles it for a no-template item (one false clause under an
    outermost AND), but eventType is unread, so a template item can only ever
    be conditional."""
    data = negation_data()
    sub = set_criteria(
        data,
        'event.data.blueprintId != "inline-blueprint"'
        " && event.data.eventType == 'CREATE_DEPLOYMENT'",
        [],
        ["inline-blueprint"],
    )
    sub["criteria_fully_read"] = False
    sub["criteria_top_level_or"] = False
    subs = matched_subs(data)
    assert subs["Restart Service"] == []
    assert subs["Linux VM"] == [("guard", "unverified")]


def test_top_level_or_blocks_a_confident_exclusion():
    # `blueprintId != sentinel || eventType == 'X'` still fires for a
    # no-template item when the second clause holds, so it must be shown.
    data = negation_data()
    sub = set_criteria(
        data,
        'event.data.blueprintId != "inline-blueprint"'
        " || event.data.eventType == 'CREATE_DEPLOYMENT'",
        [],
        ["inline-blueprint"],
    )
    sub["criteria_fully_read"] = False
    sub["criteria_top_level_or"] = True
    assert matched_subs(data)["Restart Service"] == [("guard", "unverified")]


def test_fully_read_disjunction_of_one_field_still_excludes():
    """The reported bug: `blueprintId == A || blueprintId == B` is a top-level
    disjunction whose every branch this parser read, and `_decide` already
    treats the equals list as a set. Reversing the exclusion drew
    "Delete Windows Server - WIS" on every catalog item in the live report,
    the RHEL ones included."""
    data = negation_data()
    sub = set_criteria(
        data,
        "event.data.blueprintId == 'bp-other' || event.data.blueprintId == 'bp-second'",
        ["bp-other", "bp-second"],
        [],
    )
    sub["criteria_fully_read"] = True
    sub["criteria_top_level_or"] = True
    subs = matched_subs(data)
    assert subs["Linux VM"] == []
    assert subs["Restart Service"] == []


def test_fully_read_disjunction_still_matches_the_item_it_names():
    data = negation_data()
    sub = set_criteria(
        data,
        "event.data.blueprintId == 'bp-1' || event.data.blueprintId == 'bp-second'",
        ["bp-1", "bp-second"],
        [],
    )
    sub["criteria_fully_read"] = True
    sub["criteria_top_level_or"] = True
    assert matched_subs(data)["Linux VM"] == [("guard", "confirmed")]


def test_disjunction_across_both_fields_blocks_the_exclusion():
    """`blueprintId == A || projectId == B` is read in full, but only the
    blueprint half decides the verdict. The project half can fire on its own,
    so the subscription must still be shown."""
    data = negation_data()
    sub = set_criteria(
        data,
        "event.data.blueprintId == 'bp-other' || event.data.projectId == 'p1'",
        ["bp-other"],
        [],
    )
    sub["criteria_project_eq"] = ["p1"]
    sub["criteria_fully_read"] = True
    sub["criteria_top_level_or"] = True
    assert matched_subs(data)["Linux VM"] == [("guard", "unverified")]


def test_topic_concern_map():
    from vcf_automation_assessment_tool.flows import topic_concern

    assert topic_concern("compute.allocation.pre") == "provisioning"
    assert topic_concern("compute.post.provision") == "provisioning"
    assert topic_concern("network.configure") == "provisioning"
    assert topic_concern("custom.resource.provision.post") == "provisioning"
    assert topic_concern("compute.removal.pre") == "disposal"
    assert topic_concern("kubernetes.cluster.removal.post") == "disposal"
    assert topic_concern("deployment.purge") == "disposal"
    assert topic_concern("deployment.action.pre") == "day2"
    assert topic_concern("deployment.resource.action.post") == "day2"
    # A day-2 topic some builds spell with a ".request." segment is still
    # day 2, not a request topic.
    assert topic_concern("deployment.action.request.pre") == "day2"
    assert topic_concern("deployment.resource.action.request.post") == "day2"
    assert topic_concern("deployment.request.pre") == "request"
    assert topic_concern("deployment.approval") == "request"
    # Nothing is pushed into the nearest plausible stage.
    assert topic_concern("kubernetes.cluster.state.monitoring") == "other"
    assert topic_concern("unknown") == "other"


def test_request_concern_reads_the_event_type():
    from vcf_automation_assessment_tool.flows import _request_concern

    # Nothing named: the request is what starts a build, so it goes with one.
    assert _request_concern({}) == "provisioning"
    assert _request_concern({"criteria_event_types_eq": []}) == "provisioning"
    assert _request_concern({"criteria_event_types_eq": ["CREATE_DEPLOYMENT"]}) == "provisioning"
    assert _request_concern({"criteria_event_types_eq": ["DESTROY_DEPLOYMENT"]}) == "disposal"
    assert _request_concern({"criteria_event_types_eq": ["UPDATE_DEPLOYMENT"]}) == "day2"
    # Several kinds, or a spelling this tool does not recognise: kept apart
    # rather than placed on a guess.
    assert (
        _request_concern({"criteria_event_types_eq": ["CREATE_DEPLOYMENT", "DESTROY_DEPLOYMENT"]})
        == "request"
    )
    assert _request_concern({"criteria_event_types_eq": ["SOMETHING_ELSE"]}) == "request"


def test_a_criteria_that_excludes_a_build_is_never_filed_under_one():
    """`eventType != 'CREATE_DEPLOYMENT'` says which part of the life it is
    NOT. Defaulting it to Provisioning would file the subscription under the
    one thing its own conditions rule out."""
    from vcf_automation_assessment_tool.flows import _request_concern

    assert _request_concern({"criteria_event_types_ne": ["CREATE_DEPLOYMENT"]}) == "request"
    # An exclusion of some other kind leaves the build open, so the default
    # still applies.
    assert _request_concern({"criteria_event_types_ne": ["DESTROY_DEPLOYMENT"]}) == "provisioning"
    # An equals list always wins: it says what the subscription IS for.
    assert (
        _request_concern(
            {
                "criteria_event_types_eq": ["DESTROY_DEPLOYMENT"],
                "criteria_event_types_ne": ["CREATE_DEPLOYMENT"],
            }
        )
        == "disposal"
    )


def concern_data():
    """One machine item and subscriptions across the whole life of it."""
    data = make_data(
        "com.vmw.blueprint",
        resource_types=["Cloud.vSphere.Machine"],
        topics=(
            "deployment.request.pre",
            "compute.provision.post",
            "deployment.resource.action.pre",
            "compute.removal.post",
        ),
    )
    return data


def test_concerns_are_grouped_and_ordered():
    data = concern_data()
    build_flows(data)
    concerns = data.derived["flows"][0]["concerns"]
    assert [c["key"] for c in concerns] == ["provisioning", "day2", "disposal"]
    assert [c["title"] for c in concerns] == ["Provisioning", "Day 2 Changes", "Disposal"]
    # The request that starts the build leads the provisioning topics, in
    # lifecycle order.
    assert [t["topic"] for t in concerns[0]["topics"]] == [
        "deployment.request.pre",
        "compute.provision.post",
    ]
    assert [t["topic"] for t in concerns[2]["topics"]] == ["compute.removal.post"]


def test_an_event_type_moves_a_request_subscription_to_its_concern():
    """The live built-in delete hook sits on deployment.request.post and
    names DESTROY_DEPLOYMENT, so it belongs under Disposal rather than with
    the build every other request subscription goes to."""
    data = concern_data()
    sub = next(
        s
        for s in data.raw["extensibility"]["subscriptions"]
        if s["eventTopicId"] == "deployment.request.pre"
    )
    sub["criteria"] = "event.data.eventType == 'DESTROY_DEPLOYMENT'"
    sub["criteria_event_types_eq"] = ["DESTROY_DEPLOYMENT"]
    build_flows(data)
    by_key = {c["key"]: c for c in data.derived["flows"][0]["concerns"]}
    assert "request" not in by_key
    assert [t["topic"] for t in by_key["disposal"]["topics"]] == [
        "deployment.request.pre",
        "compute.removal.post",
    ]
    # And it leaves the build, where an unqualified request subscription sits.
    assert [t["topic"] for t in by_key["provisioning"]["topics"]] == ["compute.provision.post"]


def test_flow_topics_flattens_every_concern_once():
    data = concern_data()
    build_flows(data)
    flow = data.derived["flows"][0]
    topics = [t["topic"] for t in flow_topics(flow)]
    assert topics == [
        "deployment.request.pre",
        "compute.provision.post",
        "deployment.resource.action.pre",
        "compute.removal.post",
    ]
    names = [s["name"] for t in flow_topics(flow) for s in t["subscriptions"]]
    assert len(names) == len(set(names))
