"""Mermaid diagram generation: node identity and edge correctness."""

import re

from vcf_automation_assessment_tool.report.diagrams import flow_diagram


def as_concern(flow):
    """Wrap the topic list a fixture declares into one concern.

    The builder groups by concern and the diagram draws one at a time; which
    concern it is makes no difference to node identity, edges or colour, which
    is what these tests are about.
    """
    return {"key": "provisioning", "title": "Provisioning", "topics": flow.get("topics", [])}


def make_sub(sub_id, name, topic, blocking=False, disabled=False):
    return {
        "id": sub_id,
        "name": name,
        "eventTopicId": topic,
        "blocking": blocking,
        "disabled": disabled,
        "runnableType": "extensibility.abx",
        "runnableId": f"abx-{sub_id}",
        "runnableName": f"action-{name}",
    }


def test_topics_with_common_prefix_stay_distinct_nodes():
    """Regression: item uuid + topic truncated to the same node id, merging
    compute.provision.pre and compute.provision.post into one node and
    attaching subscriptions to the wrong topic."""
    flow = {
        "item_id": "b1c1a70e-4514-4393-a027-ef0ea1efb29e",  # full-length uuid
        "item_name": "Web VM",
        "source_name": "",
        "blueprint_id": None,
        "blueprint_name": None,
        "topics": [
            {
                "topic": "compute.provision.pre",
                "subscriptions": [make_sub("s1", "pre-hook", "compute.provision.pre")],
            },
            {
                "topic": "compute.provision.post",
                "subscriptions": [make_sub("s2", "post-hook", "compute.provision.post")],
            },
        ],
    }
    src = flow_diagram(flow, as_concern(flow))

    # Both topic labels must exist as their own node definitions.
    pre_node = re.search(r'(\S+)\(\["compute\.provision\.pre"\]\)', src)
    post_node = re.search(r'(\S+)\(\["compute\.provision\.post"\]\)', src)
    assert pre_node and post_node
    assert pre_node.group(1) != post_node.group(1)

    # Each subscription hangs off its own topic node.
    sub_pre = re.search(r'(\S+)\["pre-hook"\]', src)
    sub_post = re.search(r'(\S+)\["post-hook"\]', src)
    assert f"{pre_node.group(1)} --> {sub_pre.group(1)}" in src
    assert f"{post_node.group(1)} --> {sub_post.group(1)}" in src
    assert f"{pre_node.group(1)} --> {sub_post.group(1)}" not in src
    assert f"{post_node.group(1)} --> {sub_pre.group(1)}" not in src


def test_red_reserved_for_disabled_not_blocking():
    flow = {
        "item_id": "i1",
        "item_name": "Item",
        "source_name": "",
        "blueprint_id": None,
        "blueprint_name": None,
        "topics": [
            {
                "topic": "compute.provision.post",
                "subscriptions": [
                    make_sub("s1", "gate", "compute.provision.post", blocking=True),
                    make_sub("s2", "dead", "compute.provision.post", disabled=True),
                ],
            }
        ],
    }
    src = flow_diagram(flow, as_concern(flow))
    # No blocking class exists; the blocking sub renders as a normal node with
    # only the text marker.
    assert "classDef blocking" not in src
    assert '"gate (blocking)"' in src
    # Disabled gets the red fill.
    assert "classDef disabled fill:#fbe9e9" in src
    disabled_node = re.search(r'(\S+)\["dead \(disabled\)"\]', src).group(1)
    assert re.search(rf"class [^\n]*{re.escape(disabled_node)}[^\n]* disabled", src)


def test_conditional_subscription_dashed_and_marked():
    sub = make_sub("s1", "vro-hook", "compute.provision.pre")
    sub["match"] = "unverified"
    flow = {
        "item_id": "i1",
        "item_name": "Item",
        "source_name": "",
        "blueprint_id": None,
        "blueprint_name": None,
        "topics": [{"topic": "compute.provision.pre", "subscriptions": [sub]}],
    }
    src = flow_diagram(flow, as_concern(flow))
    assert '"vro-hook (conditional)"' in src
    node = re.search(r'(\S+)\["vro-hook \(conditional\)"\]', src).group(1)
    assert re.search(rf"\S+ -\.-> {re.escape(node)}", src)


def test_all_node_ids_unique():
    flow = {
        "item_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "item_name": "Item",
        "source_name": "Source",
        "blueprint_id": "bp-1",
        "blueprint_name": "bp",
        "topics": [
            {
                "topic": f"topic.{i}",
                "subscriptions": [make_sub(f"s{i}", f"sub{i}", f"topic.{i}")],
            }
            for i in range(5)
        ],
    }
    src = flow_diagram(flow, as_concern(flow))
    node_defs = re.findall(r'^(\S+)[\[(]+"', src, flags=re.MULTILINE)
    assert len(node_defs) == len(set(node_defs)), "duplicate mermaid node ids"


def test_blocking_marker_survives_a_long_subscription_name():
    """The marker is appended after truncation: in a diagram the text marker
    is the only signal blocking has (red is reserved for disabled)."""
    from vcf_automation_assessment_tool.report.diagrams import flow_diagram

    flow = {
        "item_id": "i1",
        "item_name": "item",
        "item_type": "com.vmw.blueprint",
        "source_name": "",
        "blueprint_id": None,
        "blueprint_name": None,
        "projects": [],
        "deployment_count": 0,
        "topics": [
            {
                "topic": "compute.provision.pre",
                "subscriptions": [
                    {
                        "id": "s1",
                        "name": "vRA - Machine Provision - Post - Update CMDB Record - Prod",
                        "blocking": True,
                        "disabled": False,
                        "match": "confirmed",
                        "runnableType": "extensibility.abx",
                        "runnableName": "x",
                        "runnableId": "a1",
                    }
                ],
            }
        ],
    }
    src = flow_diagram(flow, as_concern(flow))
    assert "(blocking)" in src


def test_labels_strip_carriage_returns():
    from vcf_automation_assessment_tool.report.diagrams import _label

    assert _label("line one\r\nline two\rtail") == "line one line two tail"


def test_hostile_names_cannot_break_diagram_syntax():
    """Quotes, newlines and oversized names are neutralized in labels: the
    diagram source must contain no unescaped double quote from data and no
    label spanning lines."""
    from vcf_automation_assessment_tool.report.diagrams import flow_diagram

    hostile = 'evil"] x --> y ["\nsecond line ' + "A" * 80
    flow = {
        "item_id": "i1",
        "item_name": hostile,
        "item_type": "com.vmw.blueprint",
        "source_name": hostile,
        "blueprint_id": "b1",
        "blueprint_name": hostile,
        "projects": [],
        "deployment_count": 0,
        "topics": [
            {
                "topic": "compute.provision.pre",
                "subscriptions": [
                    {
                        "id": "s1",
                        "name": hostile,
                        "blocking": False,
                        "disabled": False,
                        "match": "confirmed",
                        "runnableType": "extensibility.abx",
                        "runnableName": hostile,
                        "runnableId": "a1",
                    }
                ],
            }
        ],
    }
    src = flow_diagram(flow, as_concern(flow))
    for line in src.splitlines():
        # Label text sits inside ["..."]: any data-borne double quote was
        # converted to a single quote, so quotes only pair around labels.
        assert 'evil"]' not in line
        assert "AAAA" not in line or len(line) < 200  # 60-char label cap held


def make_placement(constraints, name="web-server", intersections=()):
    return {
        "blueprint_id": "bp1",
        "blueprint_name": name,
        "project": "Platform",
        "resources": [
            {
                "name": "vm1",
                "type": "Cloud.vSphere.Machine",
                "constraints": constraints,
                "intersections": list(intersections),
            }
        ],
        "counts": {},
    }


def make_constraint(tag, state, hard=True, targets=(), gap=None, context="resource", **kw):
    return {
        "tag": tag,
        "hard": hard,
        "negated": kw.get("negated", False),
        "dynamic": kw.get("dynamic", False),
        "context": context,
        "state": state,
        "gap": gap,
        "note": kw.get("note", ""),
        "targets": list(targets),
        "requirements": list(kw.get("requirements", ())),
        "expression": kw.get("expression"),
        "options": list(kw.get("options", ())),
    }


def test_a_place_satisfying_two_constraints_is_drawn_once():
    """Arrows converging on one node is the shape the diagram exists to show;
    a node per constraint would hide the convergence."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    zone = [{"kind": "cloud-zone", "name": "prod-zone", "via": "capability tag"}]
    src = placement_diagram(
        make_placement(
            [
                make_constraint("env:prod", "single", targets=zone),
                make_constraint("site:dc1", "single", targets=zone),
            ]
        )
    )
    nodes = re.findall(r"^(ptgt_\w+)\[", src, re.MULTILINE)
    assert len(nodes) == 1
    assert src.count(f"--> {nodes[0]}") == 2


def test_a_hard_dead_end_is_red_and_a_soft_one_is_muted():
    """A hard constraint nothing satisfies fails every build; a soft one is
    ignored at request time. Rendering both as broken would overstate."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement(
            [
                make_constraint("no:such", "unsatisfied", gap="matches no capability tag"),
                make_constraint("gone", "unsatisfied", hard=False, gap="matches no capability tag"),
            ]
        )
    )
    fail_line = next(
        ln for ln in src.splitlines() if ln.startswith("class ") and ln.endswith(" fail")
    )
    muted_line = next(
        ln for ln in src.splitlines() if ln.startswith("class ") and ln.endswith(" none")
    )
    hard_node = re.search(r"^(pc_\w*no_such\w*)\{", src, re.MULTILINE).group(1)
    soft_node = re.search(r"^(pc_\w*gone\w*)\{", src, re.MULTILINE).group(1)
    assert hard_node in fail_line and hard_node not in muted_line
    assert soft_node in muted_line and soft_node not in fail_line


def test_each_dead_end_keeps_its_own_reason():
    """Two constraints failing for different reasons on one shared node would
    read as a single fault."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement(
            [
                make_constraint("a:1", "unsatisfied", gap="matches no capability tag"),
                make_constraint(
                    "a:1",
                    "unsatisfied",
                    context="storage",
                    gap="matches only a cloud account tag, and storage profiles "
                    "do not inherit account-level tags",
                ),
            ]
        )
    )
    assert len(set(re.findall(r"^(pend_\w+)\(\[", src, re.MULTILINE))) == 2
    # Wrapped rather than truncated: the half naming storage is the half that
    # explains the dead end.
    assert "do not inherit account-" in src


def test_a_brace_in_a_tag_cannot_break_the_rhombus_it_sits_in():
    """A brace inside a node whose own delimiters are braces ends the node,
    and an @ anywhere in a label renders as "Unsupported markdown"."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement([make_constraint("env:{x}@y", "unsatisfied", gap="matches nothing")])
    )
    label = re.search(r"\{\"(.*?)\"\}", src).group(1)
    assert "{" not in label and "}" not in label and "@" not in label
    # Mermaid's own entity form, which has no ampersand: its encodeEntities
    # pass puts one back, so "&#123;" reached a live page as "&{".
    assert "env:#123;x#125;#64;y" in label
    assert "&#" not in label


def test_project_constraints_are_one_node_and_never_a_place():
    """A live template's ca:sigma constraint fanned out to 57 green project
    nodes around the single cloud account that actually carries the tag, all
    of them reading as somewhere it could be built. Only the project lists
    that bear on this kind of resource reach the diagram, and the node says
    which list they came from."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement(
            [
                make_constraint(
                    "ca:sigma",
                    "single",
                    targets=[
                        {"kind": "cloud-account", "name": "sigma", "via": "inherited by computes"}
                    ],
                    requirements=[
                        {
                            "kind": "project",
                            "name": f"P{n}",
                            "via": "network constraint",
                            "constraint_type": "network",
                        }
                        for n in range(57)
                    ],
                )
            ]
        )
    )
    assert len(re.findall(r"^(ptgt_\w+)\[", src, re.MULTILINE)) == 1
    (req,) = re.findall(r"^(preq_\w+)\[", src, re.MULTILINE)
    assert "also required by the network constraint on 57 project(s)" in src
    assert "+54 more" in src
    # Never the green of a place, and never on the arrow that means "can be
    # built here".
    class_line = next(ln for ln in src.splitlines() if ln.startswith("class ") and " req" in ln)
    assert req in class_line
    assert f"-.-> {req}" in src


def test_a_truncated_label_never_ends_inside_an_entity():
    """_safe_text writes a brace as #123; before the 60-character cut, so a
    tag full of them could leave "#12" on the page as text."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    tag = "{x}" * 30
    src = placement_diagram(make_placement([make_constraint(tag, "unsatisfied", gap="gone")]))
    label = re.search(r"\{\"(.*?)\"\}", src).group(1)
    assert not re.search(r"&?#\d*$", label.split("<br/>")[0])
    assert "{" not in label


def test_a_constraint_a_whole_estate_satisfies_is_capped():
    """A tag every zone carries needs no map, and a hundred nodes of it would
    bury the constraint that narrows to one place next to it."""
    from vcf_automation_assessment_tool.report.diagrams import MAX_PLACES, placement_diagram

    places = [
        {"kind": "cloud-zone", "name": f"z{n}", "via": "capability tag"}
        for n in range(MAX_PLACES + 5)
    ]
    src = placement_diagram(make_placement([make_constraint("env:prod", "open", targets=places)]))
    assert len(re.findall(r"^(ptgt_\w+)\[", src, re.MULTILINE)) == MAX_PLACES
    assert "+5 more place(s)" in src


def test_an_exclusion_is_drawn_as_one():
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement(
            [
                make_constraint(
                    "env:prod",
                    "exclusion",
                    negated=True,
                    targets=[{"kind": "cloud-zone", "name": "prod-zone", "via": "capability tag"}],
                )
            ]
        )
    )
    assert "-.->|excludes|" in src


LIVE_EXPRESSION = (
    '${input.environment == "env:dev" ? "net:ALL-sigma-dtq"'
    ' : input.environment == "env:qa" ? "net:ALL-sigma-dtq" : "net:ALL-sigma-ppp"}'
)


def request_time(options, kind="choice", references=("input.environment",), prefix=""):
    return make_constraint(
        LIVE_EXPRESSION,
        "unverifiable",
        dynamic=True,
        expression={"kind": kind, "references": list(references), "prefix": prefix},
        options=options,
    )


def test_a_request_time_expression_is_said_in_words_and_never_drawn():
    """The live report drew a five-branch conditional inside a rhombus. It
    told the reader nothing except that it was long."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement(
            [
                request_time(
                    [
                        make_constraint(
                            "net:ALL-sigma-dtq",
                            "single",
                            targets=[
                                {
                                    "kind": "network-profile",
                                    "name": "dtq-vcf4",
                                    "via": "capability tag",
                                }
                            ],
                        ),
                        make_constraint(
                            "net:ALL-sigma-ppp",
                            "unsatisfied",
                            gap="matches no capability tag",
                        ),
                    ]
                )
            ]
        )
    )
    assert "input.environment ==" not in src
    assert "decided at request time" in src and "by input.environment" in src
    # Each tag it can decide on resolves like the same tag written directly.
    assert "net:ALL-sigma-dtq" in src and "only one place matches" in src
    assert "dtq-vcf4" in src
    assert "matches no capability tag" in src


def test_a_tag_only_some_requests_ask_for_is_never_drawn_as_a_broken_build():
    """Red means every build of the resource fails and TAG-001 reports it as
    well. A value only the requests that choose it depend on is neither."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement(
            [
                request_time(
                    [make_constraint("net:gone", "unsatisfied", gap="matches no capability tag")]
                )
            ]
        )
    )
    assert not [ln for ln in src.splitlines() if ln.startswith("class ") and ln.endswith(" fail")]
    (option,) = re.findall(r"^(popt_\w+)\[", src, re.MULTILINE)
    warn = next(ln for ln in src.splitlines() if ln.startswith("class ") and ln.endswith(" warn"))
    assert option in warn
    # Dotted, because exactly one of them applies to any one request.
    assert f"-.-> {option}" in src


def test_a_computed_tag_says_what_it_is_built_from():
    """Nothing to enumerate, so the node carries the one thing a reader can
    act on: the prefix it must come out as, and what feeds it."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement(
            [request_time([], kind="computed", references=["env.projectName"], prefix="net:")]
        )
    )
    assert "built at request time" in src and "from env.projectName" in src
    assert "'net:...' tag" in src
    assert "where it lands depends on the answer" in src


def test_the_tags_one_constraint_can_choose_are_capped():
    from vcf_automation_assessment_tool.report.diagrams import MAX_OPTIONS, placement_diagram

    options = [
        make_constraint(f"net:{n}", "unsatisfied", gap="matches no capability tag")
        for n in range(MAX_OPTIONS + 3)
    ]
    src = placement_diagram(make_placement([request_time(options)]))
    assert len(re.findall(r"^(popt_\w+)\[", src, re.MULTILINE)) == MAX_OPTIONS
    assert "+3 more tag(s)" in src


def together(tags, places=(), conflict=False, kind="compute"):
    return {"kind": kind, "tags": list(tags), "places": list(places), "conflict": conflict}


def test_what_satisfies_every_constraint_at_once_is_drawn_once():
    """A resource is built in one place, so its constraints have to agree on
    one. The constraints keep their own places, and one shape says what they
    leave between them."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    zones = [{"kind": "cloud-zone", "name": n, "via": "capability tag"} for n in ("z1", "z2")]
    src = placement_diagram(
        make_placement(
            [
                make_constraint("env:prod", "open", targets=zones),
                make_constraint("site:dc1", "open", targets=zones[:1] + [zones[1]]),
            ],
            intersections=[together(["env:prod", "site:dc1"], places=["z1"])],
        )
    )
    (node,) = re.findall(r"^(pall_\w+)\[", src, re.MULTILINE)
    assert "one compute place carries all 2 tags" in src
    # Both constraints feed it, and each still shows its own places.
    assert src.count(f"-.->|together| {node}") == 2
    assert len(re.findall(r"^(ptgt_\w+)\[", src, re.MULTILINE)) == 2


def test_constraints_that_agree_on_nothing_are_drawn_as_broken():
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement(
            [
                make_constraint(
                    "env:prod",
                    "single",
                    targets=[{"kind": "cloud-zone", "name": "z1", "via": "capability tag"}],
                ),
                make_constraint(
                    "site:dc2",
                    "single",
                    targets=[{"kind": "cloud-zone", "name": "z2", "via": "capability tag"}],
                ),
            ],
            intersections=[together(["env:prod", "site:dc2"], conflict=True)],
        )
    )
    (node,) = re.findall(r"^(pall_\w+)\[", src, re.MULTILINE)
    assert "no compute place carries all 2 tags" in src
    fail_line = next(
        ln for ln in src.splitlines() if ln.startswith("class ") and ln.endswith(" fail")
    )
    assert node in fail_line


def test_an_agreement_that_says_nothing_new_is_not_drawn():
    """Two constraints resolving to the same two places need no third shape to
    say so - the anti-noise rule the whole diagram is built on."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    zones = [{"kind": "cloud-zone", "name": n, "via": "capability tag"} for n in ("z1", "z2")]
    src = placement_diagram(
        make_placement(
            [
                make_constraint("env:prod", "open", targets=zones),
                make_constraint("site:dc1", "open", targets=zones),
            ],
            intersections=[together(["env:prod", "site:dc1"], places=["z1", "z2"])],
        )
    )
    assert "pall_" not in src


def test_a_request_time_node_says_where_its_values_come_from():
    """An input filled by an Orchestrator action has no values in the schema,
    and "decided at request time" alone leaves the reader nowhere to look."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement(
            [
                make_constraint(
                    "${input.Information_System}",
                    "unverifiable",
                    dynamic=True,
                    expression={
                        "kind": "reference",
                        "references": ["input.Information_System"],
                        "prefix": "",
                        "input": "Information_System",
                        "source": "Orchestrator action mod.cmdb/list_app_names",
                    },
                )
            ]
        )
    )
    assert "decided at request time" in src
    assert "by input.Information_System" in src
    assert "values come from Orchestrator action mod.cmdb/list_app_names" in src


def test_a_project_that_rules_a_tag_out_does_not_read_as_asking_for_it():
    """A project writes !net:x to say never place here, and it reached the
    diagram as "also required by", which says the opposite. Hardness went the
    same way: a soft entry is a preference the platform drops when nothing
    matches, not a condition every request meets."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement(
            [
                make_constraint(
                    "net:x",
                    "single",
                    targets=[{"kind": "network-profile", "name": "dmz", "via": "capability tag"}],
                    requirements=[
                        {
                            "kind": "project",
                            "name": "Payments",
                            "via": "",
                            "constraint_type": "network",
                            "hard": True,
                            "negated": True,
                        },
                        {
                            "kind": "project",
                            "name": "Billing",
                            "via": "",
                            "constraint_type": "network",
                            "hard": True,
                            "negated": False,
                        },
                        {
                            "kind": "project",
                            "name": "Reporting",
                            "via": "",
                            "constraint_type": "network",
                            "hard": False,
                            "negated": False,
                        },
                    ],
                )
            ]
        )
    )
    assert "also required by the network constraint on 1 project(s)" in src
    assert "ruled out by the network constraint on 1 project(s)" in src
    assert "preferred by the network constraint on 1 project(s)" in src
    assert "soft, so it is dropped where nothing matches" in src
    # Three claims, three nodes, each naming only the projects making it.
    assert len(re.findall(r"^(preq_\w+)\[", src, re.MULTILINE)) == 3


def test_a_soft_exclusion_is_not_worded_as_a_soft_preference():
    """A project can rule a tag out softly, and the caveat written for the
    preference case reads wrong beside "ruled out by": what is set aside there
    is the exclusion, not a preference nothing matched."""
    from vcf_automation_assessment_tool.report.diagrams import placement_diagram

    src = placement_diagram(
        make_placement(
            [
                make_constraint(
                    "net:x",
                    "single",
                    targets=[{"kind": "network-profile", "name": "dmz", "via": "capability tag"}],
                    requirements=[
                        {
                            "kind": "project",
                            "name": "Payments",
                            "via": "",
                            "constraint_type": "network",
                            "hard": False,
                            "negated": True,
                        }
                    ],
                )
            ]
        )
    )
    assert "ruled out by the network constraint on 1 project(s)" in src
    assert "soft, so it is set aside where nothing else matches" in src
    assert "soft, so it is dropped where nothing matches" not in src
