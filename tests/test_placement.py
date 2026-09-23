"""Placement diagrams: which templates are drawn, and what they claim.

The diagram and the TAG findings answer the same question about the same
constraint, so the tests that matter most here are the ones binding them
together: a dead end in a diagram that TAG-001 does not report, or the
reverse, would be the report contradicting itself.
"""

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.checks.blueprints import (
    tag_004_unplaceable_in_a_requesting_project,
    tag_005_constraints_that_share_no_place,
)
from vcf_automation_assessment_tool.models import AssessmentData
from vcf_automation_assessment_tool.placement import template_placements


def build(
    constraint_tags, capability_tags, name="web-server", infrastructure=None
) -> AssessmentData:
    data = AssessmentData()
    data.raw["infrastructure"] = infrastructure or {"zones": [], "cloud_accounts": []}
    data.raw["blueprints"] = {
        "blueprints": [
            {
                "id": "bp1",
                "name": name,
                "projectName": "Platform",
                "constraint_tags": constraint_tags,
            }
        ]
    }
    data.derived["capability_tags"] = capability_tags
    return data


def estate(zones_by_project, zones, **rest) -> dict:
    """An infrastructure area with zone assignments, which is what turns the
    project scoping on."""
    return {
        "projects": [
            {"id": pid, "name": pid, "zones": [{"zoneId": z} for z in zids]}
            for pid, zids in zones_by_project.items()
        ],
        "zones": zones,
        "cloud_accounts": [],
        **rest,
    }


def zone(zone_id, account="", region="") -> dict:
    return {
        "id": zone_id,
        "name": zone_id,
        "cloudAccountId": account,
        "externalRegionId": region,
    }


def shared_with(data, project_ids, item_id="ci1") -> AssessmentData:
    """The template reaches those projects through a catalog item, which is how
    a library template is requested from projects that do not own it."""
    data.raw["catalog"] = {
        "items": [{"id": item_id, "name": "Web Server", "projectIds": list(project_ids)}]
    }
    data.raw["deployments"] = {"deployments": [{"catalogItemId": item_id, "blueprintId": "bp1"}]}
    return data


def constraint(
    tag,
    context="resource",
    hard=True,
    negated=False,
    dynamic=False,
    resource="vm1",
    resource_type="Cloud.vSphere.Machine",
):
    return {
        "tag": tag,
        "hard": hard,
        "negated": negated,
        "dynamic": dynamic,
        "resource": resource,
        "resource_type": resource_type,
        "context": context,
    }


def place(kind, name, via="capability tag", constraint_type=None, place_id=None):
    entry = {"kind": kind, "id": place_id or name, "name": name, "via": via}
    if constraint_type:
        entry["constraint_type"] = constraint_type
    return entry


def only(placements):
    """The single template drawn, with its constraints flattened."""
    assert len(placements) == 1, f"expected one template, got {len(placements)}"
    return [c for res in placements[0]["resources"] for c in res["constraints"]]


def test_a_constraint_nothing_carries_is_a_dead_end():
    placements, _ = template_placements(build([constraint("no:such:tag")], {}))
    (found,) = only(placements)
    assert found["state"] == "unsatisfied"
    assert found["gap"] == "matches no capability tag"
    assert found["targets"] == []


def test_a_constraint_one_place_satisfies_is_drawn_as_a_single_point_of_failure():
    """Nothing is broken today, so no finding reports it. The diagram is the
    only place this shows, which is the reason it was worth drawing."""
    placements, _ = template_placements(
        build([constraint("env:prod")], {"env:prod": [place("cloud-zone", "prod-zone")]})
    )
    (found,) = only(placements)
    assert found["state"] == "single"
    assert [t["name"] for t in found["targets"]] == ["prod-zone"]


def test_a_constraint_several_places_satisfy_does_not_get_a_diagram():
    """A template whose every constraint resolves to two or more places has a
    diagram that says "this is fine" at the cost of a page of report."""
    placements, note = template_placements(
        build(
            [constraint("env:prod")],
            {"env:prod": [place("cloud-zone", "z1"), place("cloud-zone", "z2")]},
        )
    )
    assert placements == []
    assert "resolve every constraint to two or more places" in note


def test_the_same_place_reached_twice_is_still_one_place():
    """A fabric network surfaces once per cloud account it was reached
    through. Counting the duplicate would hide a single point of failure."""
    placements, _ = template_placements(
        build(
            [constraint("net:dmz", context="network[0]")],
            {"net:dmz": [place("fabric-network", "dmz"), place("fabric-network", "dmz")]},
        )
    )
    (found,) = only(placements)
    assert found["state"] == "single"
    assert len(found["targets"]) == 1


def test_the_storage_inheritance_exception_reaches_the_diagram():
    """Storage profiles never inherit cloud account tags, so a storage
    constraint carried only by an account is unsatisfiable even though the
    same tag on the same account satisfies a compute constraint."""
    cap = {"site:dc1": [place("cloud-account", "vc-prod", "inherited by its computes")]}
    placements, _ = template_placements(
        build([constraint("site:dc1"), constraint("site:dc1", context="storage")], cap)
    )
    compute, storage = only(placements)
    assert compute["state"] == "single"
    assert storage["state"] == "unsatisfied"
    assert "do not inherit account-level tags" in storage["gap"]


def test_a_request_time_constraint_claims_nothing():
    placements, _ = template_placements(
        build(
            [constraint("env:${input.env}", dynamic=True), constraint("no:such:tag")],
            {},
        )
    )
    dynamic, _static = only(placements)
    assert dynamic["state"] == "unverifiable"
    assert dynamic["gap"] is None


def test_a_negated_constraint_rules_places_out_rather_than_in():
    """Matching nothing is not a fault for an exclusion, which is why
    TAG-001 skips them too."""
    placements, _ = template_placements(
        build(
            [constraint("env:prod", negated=True), constraint("no:such:tag")],
            {"env:prod": [place("cloud-zone", "prod-zone")]},
        )
    )
    excluded, _dead = only(placements)
    assert excluded["state"] == "exclusion"


def test_a_tag_only_a_project_names_is_somewhere_nothing_can_be_built():
    """A project constraint is a requirement on the requests made in the
    project, not a tag on infrastructure. A tag that only a project names is
    a tag nothing offers, and placement fails on it."""
    placements, _ = template_placements(
        build(
            [constraint("env:prod")],
            {"env:prod": [place("project", "Platform", "network constraint", "network")]},
        )
    )
    (found,) = only(placements)
    assert found["state"] == "unsatisfied"
    assert found["targets"] == []
    assert "only a project constraint names it" in found["gap"]


def test_a_project_network_constraint_is_a_requirement_on_a_network_resource():
    """The project's own network list applies to a network resource, and to
    nothing else."""
    cap = {
        "net:dmz": [
            place("network-profile", "dmz-nets"),
            place("project", "Platform", "network constraint", "network"),
        ]
    }
    placements, _ = template_placements(
        build(
            [
                constraint("net:dmz", resource="net1", resource_type="Cloud.NSX.Network"),
                constraint("net:dmz", resource="vm1"),
            ],
            cap,
        )
    )
    network, compute = only(placements)
    assert [r["name"] for r in network["requirements"]] == ["Platform"]
    assert compute["requirements"] == []


def test_an_extensibility_constraint_is_not_a_placement_requirement():
    """It selects the runner that executes extensibility work. A live estate
    drew 57 of them as a requirement on one machine."""
    cap = {
        "ca:sigma": [
            place("cloud-account", "vcf4_sigma", "inherited by its computes"),
            place("project", "DTQ", "extensibility constraint", "extensibility"),
        ]
    }
    placements, _ = template_placements(build([constraint("ca:sigma")], cap))
    (found,) = only(placements)
    assert found["state"] == "single"
    assert found["requirements"] == []


def test_project_constraints_do_not_pad_the_count_of_places():
    """Live regression: four hard constraints resolved to one cloud account
    each and read as open, because 57 projects carried the same tag as a
    project-level constraint. A project constraint is one more thing to
    satisfy, so counting it as somewhere to build hid two of the estate's
    busiest templates from the diagrams entirely."""
    placements, _ = template_placements(
        build(
            [constraint("ca:sigma")],
            {
                "ca:sigma": [
                    place("cloud-account", "vcf4_sigma", "inherited by its computes"),
                    place("project", "DTQ", "extensibility constraint", "extensibility"),
                    place("project", "PPP", "extensibility constraint", "extensibility"),
                ]
            },
        )
    )
    (found,) = only(placements)
    assert found["state"] == "single"
    assert [t["name"] for t in found["targets"]] == ["vcf4_sigma"]
    # Extensibility constraints, so they are not requirements on a machine
    # either: they select the runner, not the zone.
    assert found["requirements"] == []


def test_a_template_whose_constraints_all_wait_on_an_input_says_that():
    """Not the same fact as "every constraint resolves to two or more places",
    which is what the note used to say about all of them - and on a live
    estate that was 16 templates it was wrong about."""
    placements, note = template_placements(
        build([constraint("env:${input.env}", dynamic=True)], {})
    )
    assert placements == []
    assert "build every constraint from a request-time input" in note
    assert "two or more places" not in note


def test_diagrams_are_withheld_when_the_tag_map_has_holes():
    """The same guard the TAG checks apply: a dead end drawn from an unread
    tag would assert something false, and a diagram asserts it loudly."""
    data = build([constraint("no:such:tag")], {})
    data.record_error("infrastructure", "zones", "403 Forbidden")
    placements, note = template_placements(data)
    assert placements == []
    assert "withheld" in note and "gaps" in note


def test_templates_with_no_constraints_are_counted_not_drawn():
    data = build([], {})
    placements, note = template_placements(data)
    assert placements == []
    assert "declare no constraint tags at all" in note


def test_the_diagram_and_tag_001_never_disagree(sample_data):
    """Both read constraint_match_gap. If one is ever reimplemented, a
    template will show a dead end the findings do not report, or the reverse,
    and this is where that shows up."""
    run_checks(sample_data)
    placements, _ = template_placements(sample_data)
    drawn = {
        (p["blueprint_name"], c["tag"], c["context"])
        for p in placements
        for res in p["resources"]
        for c in res["constraints"]
        if c["state"] == "unsatisfied" and c["hard"]
    }
    reported = {
        (obj.name, ct["tag"], ct["context"])
        for finding in sample_data.findings
        if finding.check_id == "TAG-001"
        for obj in finding.affected
        for ct in _constraints_of(sample_data, obj.name)
        if f"'{ct['tag']}'" in (obj.detail or "") and f"({ct['context']})" in (obj.detail or "")
    }
    assert drawn, "the fixture should carry at least one unsatisfiable hard constraint"
    assert drawn == reported


def _constraints_of(data, blueprint_name):
    for bp in data.raw["blueprints"]["blueprints"]:
        if bp["name"] == blueprint_name:
            return bp.get("constraint_tags") or []
    return []


def test_a_request_time_choice_resolves_every_tag_it_can_choose():
    """The expression cannot be evaluated here, but the tags it chooses
    between are written out in the template, and each one matches or does not
    for exactly the reasons TAG-001 would give."""
    tag = (
        '${input.environment == "env:dev" ? "net:dtq"'
        ' : input.environment == "env:qa" ? "net:dtq" : "net:ppp"}'
    )
    placements, _ = template_placements(
        build(
            # The static dead end is what puts the template on the page; the
            # request-time constraint is what this test is about. It sits on a
            # network resource, because a net: tag is matched by a network
            # profile and a machine is not placed on one.
            [
                constraint(tag, dynamic=True, resource="net1", resource_type="Cloud.NSX.Network"),
                constraint("no:such:tag"),
            ],
            {"net:dtq": [place("network-profile", "dtq-vcf4")]},
        )
    )
    found, _dead = only(placements)
    assert found["state"] == "unverifiable"
    assert found["expression"]["references"] == ["input.environment"]
    assert [o["tag"] for o in found["options"]] == ["net:dtq", "net:ppp"]
    dtq, ppp = found["options"]
    assert dtq["state"] == "single" and [t["name"] for t in dtq["targets"]] == ["dtq-vcf4"]
    assert ppp["state"] == "unsatisfied" and ppp["gap"] == "matches no capability tag"


def test_a_computed_tag_claims_no_values_at_all():
    """A tag built by concatenation could come out as anything. Listing the
    literals inside it would read as "one of these" and be a guess."""
    placements, _ = template_placements(
        build(
            [
                constraint('${"net:"+env.projectName+"-"+input.location}', dynamic=True),
                constraint("no:such:tag"),
            ],
            {},
        )
    )
    computed, _dead = only(placements)
    assert computed["options"] == []
    assert computed["expression"]["kind"] == "computed"
    assert computed["expression"]["prefix"] == "net:"
    assert computed["expression"]["references"] == ["env.projectName", "input.location"]


def test_a_value_narrowing_to_one_place_does_not_make_a_template_worth_drawing():
    """A value that lands somewhere is display-only, however narrow it is: it
    is a single point of failure for the requests that choose it and nobody
    else, which is not the same claim as a constraint that always lands there.
    Only a value landing nowhere promotes a template, and neither of these
    does."""
    placements, note = template_placements(
        build(
            [constraint('${input.env == "dev" ? "env:dev" : "env:prod"}', dynamic=True)],
            {
                "env:dev": [place("cloud-zone", "z1")],
                "env:prod": [place("cloud-zone", "z2")],
            },
        )
    )
    assert placements == []
    assert "build every constraint from a request-time input" in note


def test_a_network_resource_is_not_placed_by_a_cloud_zone_tag():
    """A tag on a cloud zone says where a machine can go. It says nothing
    about which network a network resource gets, so it cannot satisfy one."""
    placements, _ = template_placements(
        build(
            [
                constraint("env:prod", resource="net1", resource_type="Cloud.NSX.Network"),
                constraint("no:such:tag"),
            ],
            {"env:prod": [place("cloud-zone", "prod-zone")]},
        )
    )
    network, _dead = only(placements)
    assert network["state"] == "unsatisfied"
    assert network["targets"] == []
    assert "placed on a network profile or a fabric network" in network["gap"]


def test_a_machine_still_takes_the_tags_its_account_passes_down():
    """The inheritance the placement model depends on: an account's tags reach
    the computes in it, so an account tag places a machine."""
    placements, _ = template_placements(
        build(
            [constraint("site:dc1"), constraint("no:such:tag")],
            {"site:dc1": [place("cloud-account", "vc-prod", "inherited by its computes")]},
        )
    )
    compute, _dead = only(placements)
    assert compute["state"] == "single"
    assert [t["name"] for t in compute["targets"]] == ["vc-prod"]


def test_a_zone_no_requesting_project_can_use_is_not_drawn():
    """The tag is on both zones, and only one of them is assigned to a project
    that can request the template. A deployment can never land on the other."""
    data = build(
        [constraint("env:prod")],
        {"env:prod": [place("cloud-zone", "z1"), place("cloud-zone", "z2")]},
        infrastructure=estate({"p1": ["z1"]}, [zone("z1"), zone("z2")]),
    )
    data.raw["blueprints"]["blueprints"][0]["projectId"] = "p1"
    (found,) = only(template_placements(data)[0])
    assert [t["name"] for t in found["targets"]] == ["z1"]
    assert found["state"] == "single"


def test_the_projects_that_can_request_it_decide_the_zones():
    """A library template is authored in a project with no zones and requested
    from others. Its own project answers nothing about where it lands."""
    data = build(
        [constraint("env:prod"), constraint("no:such:tag")],
        {"env:prod": [place("cloud-zone", "z1"), place("cloud-zone", "z2")]},
        infrastructure=estate({"lib": [], "p1": ["z1"], "p2": ["z2"]}, [zone("z1"), zone("z2")]),
    )
    data.raw["blueprints"]["blueprints"][0]["projectId"] = "lib"
    shared_with(data, ["p1", "p2"])
    placements, _ = template_placements(data)
    found, _dead = only(placements)
    assert [t["name"] for t in found["targets"]] == ["z1", "z2"]
    assert found["state"] == "open"
    assert placements[0]["requesting_projects"] == ["p1", "p2"]


def test_a_network_profile_is_reachable_through_the_account_and_region():
    """A network profile serves the account and region its zone sits in. One
    somewhere else is not a place the request can put a network."""
    cap = {
        "net:dmz": [
            place("network-profile", "here"),
            place("network-profile", "elsewhere"),
        ]
    }
    infra = estate(
        {"p1": ["z1"]},
        [zone("z1", account="ca1", region="dc1")],
        network_profiles=[
            {"id": "here", "cloudAccountId": "ca1", "externalRegionId": "dc1"},
            {"id": "elsewhere", "cloudAccountId": "ca2", "externalRegionId": "dc2"},
        ],
    )
    data = build(
        [constraint("net:dmz", resource="net1", resource_type="Cloud.NSX.Network")],
        cap,
        infrastructure=infra,
    )
    data.raw["blueprints"]["blueprints"][0]["projectId"] = "p1"
    (found,) = only(template_placements(data)[0])
    assert [t["name"] for t in found["targets"]] == ["here"]


def test_without_a_zone_assignment_nothing_is_narrowed():
    """An estate that answers nothing about which zones a project has gets the
    behaviour it had before any of this, and the note says so."""
    data = build(
        [constraint("env:prod"), constraint("no:such:tag")],
        {"env:prod": [place("cloud-zone", "z1"), place("cloud-zone", "z2")]},
        infrastructure=estate({"p1": []}, [zone("z1"), zone("z2")]),
    )
    data.raw["blueprints"]["blueprints"][0]["projectId"] = "p1"
    placements, note = template_placements(data)
    found, _dead = only(placements)
    assert len(found["targets"]) == 2
    assert "not narrowed by project" in note


def test_a_template_no_project_claims_is_not_narrowed_at_all():
    """No catalog item shares it and no project owns it, so who requests it is
    unknown. An unknown narrows nothing."""
    data = build(
        [constraint("env:prod"), constraint("no:such:tag")],
        {"env:prod": [place("cloud-zone", "z1"), place("cloud-zone", "z2")]},
        infrastructure=estate({"p1": ["z1"]}, [zone("z1"), zone("z2")]),
    )
    placements, _ = template_placements(data)
    found, _dead = only(placements)
    assert [t["name"] for t in found["targets"]] == ["z1", "z2"]
    assert placements[0]["requesting_projects"] == []


def unplaceable_estate() -> AssessmentData:
    """One template, shared with two projects. p1 is assigned the zone that
    carries the tag; p2 is assigned one that does not."""
    data = build(
        [constraint("env:prod")],
        {"env:prod": [place("cloud-zone", "z1")]},
        infrastructure=estate({"p1": ["z1"], "p2": ["z2"]}, [zone("z1"), zone("z2")]),
    )
    data.derived["project_names"] = {"p1": "Platform", "p2": "Payments"}
    return shared_with(data, ["p1", "p2"])


def test_a_project_with_no_zone_carrying_the_tag_cannot_place_the_template():
    data = unplaceable_estate()
    placements, _ = template_placements(data)
    (found,) = only(placements)
    assert found["misses"] == ["p2"]
    assert found["projects_total"] == 2
    assert placements[0]["cannot_place"] == ["Payments"]


def test_tag_004_and_the_diagram_name_the_same_projects():
    """Both read one resolution. If either is ever reimplemented, the finding
    will name a project the diagram does not, and this is where that shows."""
    data = unplaceable_estate()
    run_checks(data)
    (finding,) = [f for f in data.findings if f.check_id == "TAG-004"]
    (obj,) = finding.affected
    assert "1 of 2 project(s)" in obj.detail and "Payments" in obj.detail
    placements, _ = template_placements(data)
    assert placements[0]["cannot_place"] == ["Payments"]


def test_tag_004_is_silent_where_no_project_carries_a_zone():
    """Without a zone assignment anywhere, "cannot place" would be a claim
    about a map that was never read."""
    data = unplaceable_estate()
    for proj in data.raw["infrastructure"]["projects"]:
        proj["zones"] = []
    run_checks(data)
    assert [f for f in data.findings if f.check_id == "TAG-004"] == []


def test_tag_004_is_silent_where_the_tag_map_has_holes():
    data = unplaceable_estate()
    data.record_error("infrastructure", "zones", "403 Forbidden")
    run_checks(data)
    assert [f for f in data.findings if f.check_id == "TAG-004"] == []


def test_a_project_with_no_zones_at_all_is_not_this_finding():
    """PRJ-006 reports a project with no zone assignment. Repeating it once
    per template it can request would be the same fault 45 times."""
    data = unplaceable_estate()
    for proj in data.raw["infrastructure"]["projects"]:
        if proj["id"] == "p2":
            proj["zones"] = []
    run_checks(data)
    assert [f for f in data.findings if f.check_id == "TAG-004"] == []


def test_two_constraints_that_share_no_zone_make_the_resource_unbuildable():
    """Each tag matches something, so TAG-001 says nothing, and no zone
    carries both, so every build of the machine fails anyway."""
    data = build(
        [constraint("env:prod"), constraint("site:dc2")],
        {
            "env:prod": [place("cloud-zone", "z1")],
            "site:dc2": [place("cloud-zone", "z2")],
        },
        infrastructure=estate({"p1": ["z1", "z2"]}, [zone("z1"), zone("z2")]),
    )
    data.raw["blueprints"]["blueprints"][0]["projectId"] = "p1"
    run_checks(data)
    assert [f.check_id for f in data.findings if f.check_id == "TAG-001"] == []
    (finding,) = [f for f in data.findings if f.check_id == "TAG-005"]
    assert "'env:prod', 'site:dc2'" in finding.affected[0].detail
    assert "no compute place carries all of them" in finding.affected[0].detail
    placements, _ = template_placements(data)
    (group,) = placements[0]["resources"][0]["intersections"]
    assert group["conflict"] and group["places"] == []


def test_an_account_tag_and_a_zone_tag_are_not_a_conflict():
    """The trap this basis exists for: a machine lands in a zone, and a zone
    inside the account satisfies the account's tag and its own. Comparing the
    objects that carry the tags called that a conflict on the live estate."""
    data = build(
        [constraint("ca:sigma"), constraint("env:qa")],
        {
            "ca:sigma": [
                place("cloud-account", "vcf4_sigma", "inherited by its computes", place_id="ca1")
            ],
            "env:qa": [place("cloud-zone", "z1")],
        },
        infrastructure=estate({"p1": ["z1"]}, [zone("z1", account="ca1")]),
    )
    data.raw["blueprints"]["blueprints"][0]["projectId"] = "p1"
    run_checks(data)
    assert [f for f in data.findings if f.check_id == "TAG-005"] == []
    placements, _ = template_placements(data)
    (group,) = placements[0]["resources"][0]["intersections"]
    assert not group["conflict"] and group["places"] == ["z1"]


def test_no_zone_assignment_means_no_intersection_claim():
    """Without zones there is nothing to intersect over, and a conflict would
    be a claim about a map that was never read."""
    data = build(
        [constraint("env:prod"), constraint("site:dc2")],
        {
            "env:prod": [place("cloud-zone", "z1")],
            "site:dc2": [place("cloud-zone", "z2")],
        },
    )
    run_checks(data)
    assert [f for f in data.findings if f.check_id == "TAG-005"] == []


def with_inputs(data, inputs):
    """What the platform says the template's inputs can be, as the collector
    keeps it."""
    data.raw["blueprints"]["blueprints"][0]["inputs"] = inputs
    return data


def declared(name, values, **rest):
    entry = {
        "name": name,
        "type": "string",
        "title": name,
        "values": tuple(values),
        "default": "",
        "source": "",
        "kind": "declared",
    }
    entry.update(rest)
    return entry


def test_a_constraint_that_is_one_input_resolves_to_that_inputs_values():
    """The values are not read out of the expression here: the expression is
    just ${input.environment}. They come from the schema the request form is
    built from, and each one is then matched as an ordinary tag."""
    data = with_inputs(
        build(
            [constraint("${input.environment}", dynamic=True), constraint("no:such:tag")],
            {"env:preprod": [place("cloud-zone", "preprod-zone")]},
        ),
        [declared("environment", ["env:preprod", "env:prod"])],
    )
    placements, _ = template_placements(data)
    found, _dead = only(placements)
    assert found["state"] == "unverifiable"
    assert found["expression"]["input"] == "environment"
    assert [o["tag"] for o in found["options"]] == ["env:preprod", "env:prod"]
    preprod, prod = found["options"]
    assert preprod["state"] == "single"
    assert [t["name"] for t in preprod["targets"]] == ["preprod-zone"]
    assert prod["state"] == "unsatisfied"


def test_an_input_filled_by_an_orchestrator_action_claims_no_values():
    """The list is built when the form opens, by running the action. Naming it
    is the whole of what a read-only assessment can honestly say."""
    data = with_inputs(
        build(
            # The static dead end is what puts the template on the page.
            [constraint("${input.Information_System}", dynamic=True), constraint("no:such:tag")],
            {},
        ),
        [
            declared(
                "Information_System",
                [],
                kind="external",
                source="/data/vro-actions/mod.cmdb/list_app_names",
            )
        ],
    )
    placements, _ = template_placements(data)
    found, _dead = only(placements)
    assert found["options"] == []
    assert found["expression"]["input"] == "Information_System"
    assert found["expression"]["source"] == "Orchestrator action mod.cmdb/list_app_names"


def test_an_input_whose_schema_was_never_read_still_names_the_input():
    """A build that does not answer for inputs schemas leaves the constraint
    exactly where it was, saying what it reads and claiming nothing more."""
    data = build([constraint("${input.environment}", dynamic=True), constraint("no:such:tag")], {})
    placements, _ = template_placements(data)
    found, _dead = only(placements)
    assert found["options"] == []
    assert found["expression"]["input"] == "environment"
    assert found["expression"]["source"] == ""


def test_an_input_declaring_a_shape_the_reader_could_not_read_claims_nothing():
    data = with_inputs(
        build([constraint("${input.environment}", dynamic=True), constraint("no:such:tag")], {}),
        [declared("environment", [], kind="unread")],
    )
    placements, _ = template_placements(data)
    found, _dead = only(placements)
    assert found["options"] == []


def test_a_constraint_reading_two_inputs_resolves_to_neither():
    """One value per input is a combination, and which combinations a request
    can make is not in the schema."""
    data = with_inputs(
        build([constraint("${input.a + input.b}", dynamic=True), constraint("no:such:tag")], {}),
        [declared("a", ["env:prod"]), declared("b", ["env:qa"])],
    )
    placements, _ = template_placements(data)
    found, _dead = only(placements)
    assert found["options"] == []
    assert found["expression"]["input"] == ""


def test_two_network_constraints_are_intersected_over_profiles_not_zones():
    """A network resource is built on a profile, and its constraints have to
    agree on one. The intersection re-derived the kind from a constraint that
    had already been resolved, and a resolved constraint carries no resource
    type, so a standalone network resource read as compute and was intersected
    over cloud zones instead. Nothing carried both tags and TAG-005 said
    nothing."""
    data = build(
        [
            constraint("net:a", resource="net1", resource_type="Cloud.NSX.Network"),
            constraint("net:b", resource="net1", resource_type="Cloud.NSX.Network"),
        ],
        {
            "net:a": [place("network-profile", "profile-a")],
            "net:b": [place("network-profile", "profile-b")],
        },
    )
    placements, _ = template_placements(data)
    (res,) = placements[0]["resources"]
    (group,) = res["intersections"]
    assert group["kind"] == "network"
    assert group["conflict"] and group["places"] == []
    run_checks(data)
    (finding,) = [f for f in data.findings if f.check_id == "TAG-005"]
    assert "no network place carries all of them" in finding.affected[0].detail


def test_a_template_whose_sharing_could_not_be_read_is_not_narrowed_to_its_author():
    """The catalog item is there, and who it is shared with is not. Narrowing
    to the project the template was written in turns a failed read into a red
    dead end and a warning, which is the one thing the placement code must
    never do."""
    data = build(
        [constraint("env:prod")], {"env:prod": [place("cloud-zone", "prod-zone", place_id="z2")]}
    )
    # An item joined to the template, with nothing on this build saying who
    # any item is shared with.
    data.raw["catalog"] = {"items": [{"id": "ci1", "name": "Web Server", "projectIds": []}]}
    data.raw["deployments"] = {"deployments": [{"catalogItemId": "ci1", "blueprintId": "bp1"}]}
    data.raw["blueprints"]["blueprints"][0]["projectId"] = "p1"
    data.raw["infrastructure"] = estate({"p1": ["z1"]}, [zone("z1"), zone("z2")])

    placements, note = template_placements(data)
    (found,) = only(placements)
    assert found["state"] == "single"
    assert [t["name"] for t in found["targets"]] == ["prod-zone"]
    assert "who they are shared with could not be read" in note
    run_checks(data)
    assert [f for f in data.findings if f.check_id == "TAG-004"] == []


def test_a_template_in_no_catalog_item_is_still_placed_in_its_own_project():
    """The fallback that withholding must not take with it: a template nothing
    shares can only be requested where it was written."""
    data = build(
        [constraint("env:prod")], {"env:prod": [place("cloud-zone", "prod-zone", place_id="z2")]}
    )
    data.raw["blueprints"]["blueprints"][0]["projectId"] = "p1"
    data.raw["infrastructure"] = estate({"p1": ["z1"]}, [zone("z1"), zone("z2")])
    placements, _ = template_placements(data)
    (found,) = only(placements)
    assert found["state"] == "unsatisfied"
    assert found["gap"] == "no place a project requesting this template can use carries the tag"


def test_a_zone_whose_computes_could_not_be_listed_rules_nothing_out():
    """The collector leaves an unreadable zone out of the map rather than
    recording it empty, precisely so this cannot happen. Reading absent as
    empty turned one failed listing into a red dead end and a warning."""
    data = build(
        [constraint("env:prod")], {"env:prod": [place("fabric-compute", "esx01", place_id="fc1")]}
    )
    data.raw["blueprints"]["blueprints"][0]["projectId"] = "p1"
    data.raw["infrastructure"] = estate(
        {"p1": ["z1"]},
        [zone("z1"), zone("z2")],
        # z1's listing failed and is absent; z2's succeeded.
        zone_computes={"z2": ["fc9"]},
    )
    placements, _ = template_placements(data)
    (found,) = only(placements)
    assert found["state"] == "single"
    assert [t["name"] for t in found["targets"]] == ["esx01"]
    run_checks(data)
    assert [f for f in data.findings if f.check_id == "TAG-004"] == []


def test_a_zone_that_was_listed_and_holds_nothing_still_rules_out():
    """The other half of the same distinction: read-and-empty is an answer."""
    data = build(
        [constraint("env:prod")], {"env:prod": [place("fabric-compute", "esx01", place_id="fc1")]}
    )
    data.raw["blueprints"]["blueprints"][0]["projectId"] = "p1"
    data.raw["infrastructure"] = estate({"p1": ["z1"]}, [zone("z1")], zone_computes={"z1": []})
    placements, _ = template_placements(data)
    (found,) = only(placements)
    assert found["state"] == "unsatisfied"


def test_a_hard_request_time_value_that_lands_nowhere_is_worth_drawing():
    """Which value a request takes is unknowable, but this one fails whoever
    takes it: the form offers it and nothing carries it. No finding says so -
    TAG-001 skips request-time constraints because it cannot call the template
    broken for every request - so the diagram is the only place it can show."""
    data = with_inputs(
        build(
            [constraint("${input.environment}", dynamic=True)],
            {"env:prod": [place("cloud-zone", "z1"), place("cloud-zone", "z2")]},
        ),
        [declared("environment", ["env:prod", "env:sandbox"])],
    )
    placements, _ = template_placements(data)
    (found,) = only(placements)
    assert found["state"] == "unverifiable"
    assert placements[0]["counts"]["dead_options"] == 1
    sandbox = [o for o in found["options"] if o["state"] == "unsatisfied"]
    assert [o["tag"] for o in sandbox] == ["env:sandbox"]


def test_request_time_values_that_all_land_somewhere_draw_nothing():
    """The anti-noise rule holds: a template whose values all resolve is a
    template with nothing wrong, and a diagram saying so costs a page."""
    data = with_inputs(
        build(
            [constraint("${input.environment}", dynamic=True)],
            {
                "env:prod": [place("cloud-zone", "z1"), place("cloud-zone", "z2")],
                "env:qa": [place("cloud-zone", "z3"), place("cloud-zone", "z4")],
            },
        ),
        [declared("environment", ["env:prod", "env:qa"])],
    )
    placements, _ = template_placements(data)
    assert placements == []


def test_a_soft_request_time_value_that_lands_nowhere_draws_nothing():
    """The platform ignores a soft constraint it cannot satisfy, so a value of
    one matching nothing costs a request nothing."""
    data = with_inputs(
        build(
            [constraint("${input.environment}", dynamic=True, hard=False)],
            {"env:prod": [place("cloud-zone", "z1"), place("cloud-zone", "z2")]},
        ),
        [declared("environment", ["env:prod", "env:sandbox"])],
    )
    placements, _ = template_placements(data)
    assert placements == []


def test_a_project_satisfying_two_constraints_in_two_zones_cannot_place_the_template():
    """A machine lands in one zone. Payments holds a zone carrying each tag
    and no zone carrying both, so every request it makes fails, and each
    constraint on its own looks satisfied from there."""
    data = shared_with(
        build(
            [constraint("env:prod"), constraint("site:dc1")],
            {
                "env:prod": [
                    place("cloud-zone", "prod-a", place_id="z1"),
                    place("cloud-zone", "both", place_id="z3"),
                ],
                "site:dc1": [
                    place("cloud-zone", "dc1-only", place_id="z2"),
                    place("cloud-zone", "both", place_id="z3"),
                ],
            },
        ),
        ["p1", "p2"],
    )
    data.raw["infrastructure"] = estate(
        # Payments has one zone per tag; Billing has the zone carrying both.
        {"p1": ["z1", "z2"], "p2": ["z3"]},
        [zone("z1"), zone("z2"), zone("z3")],
    )
    data.derived["project_names"] = {"p1": "Payments", "p2": "Billing"}

    (finding,) = tag_004_unplaceable_in_a_requesting_project(data)
    assert "1 of 2" in finding.affected[0].detail
    assert "Payments" in finding.affected[0].detail and "Billing" not in finding.affected[0].detail
    # And not TAG-005: one project can build it, so the template is not broken
    # outright, which is the difference between the two findings.
    assert tag_005_constraints_that_share_no_place(data) == []
