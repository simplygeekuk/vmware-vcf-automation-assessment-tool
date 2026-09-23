"""Tag normalization and blueprint constraint extraction."""

import pytest

from vcf_automation_assessment_tool.tagutil import (
    BlueprintParseError,
    describe_dynamic_tag,
    extract_constraint_tags,
    extract_project_constraints,
    normalize_tag,
)


def test_normalize_dict_tag():
    assert normalize_tag({"key": "env", "value": "prod"}) == "env:prod"


def test_normalize_key_only():
    assert normalize_tag({"key": "pci", "value": ""}) == "pci"
    assert normalize_tag({"key": "pci"}) == "pci"


def test_normalize_string_passthrough():
    assert normalize_tag(" env:prod ") == "env:prod"


BLUEPRINT = """
formatVersion: 1
inputs:
  size:
    type: string
resources:
  vm1:
    type: Cloud.vSphere.Machine
    properties:
      image: ubuntu
      constraints:
        - tag: 'env:prod:hard'
        - tag: 'region:emea:soft'
        - tag: '!legacy'
        - tag: 'env:${input.env}'
      networks:
        - network: '${resource.net.id}'
          constraints:
            - tag: 'net:dmz'
      attachedDisks:
        - source: '${resource.disk.id}'
          constraints:
            - tag: 'tier:gold:hard'
      storage:
        constraints:
          - tag: 'storage:fast'
  net:
    type: Cloud.Network
    properties:
      networkType: existing
"""


def test_extract_all_constraint_locations():
    tags = extract_constraint_tags(BLUEPRINT)
    by_tag = {t.tag: t for t in tags}

    assert by_tag["env:prod"].hard is True
    assert by_tag["region:emea"].hard is False
    assert by_tag["legacy"].negated is True
    assert by_tag["env:${input.env}"].dynamic is True
    assert by_tag["net:dmz"].context == "network[0]"
    assert by_tag["tier:gold"].context == "disk[0]"
    assert by_tag["storage:fast"].context == "storage"
    # No hardness suffix means hard by default.
    assert by_tag["net:dmz"].hard is True
    assert by_tag["env:prod"].resource == "vm1"
    assert by_tag["env:prod"].resource_type == "Cloud.vSphere.Machine"


def test_extract_handles_invalid_yaml():
    with pytest.raises(BlueprintParseError):
        extract_constraint_tags("resources:\n  vm1:\n    - {broken")


def test_extract_non_mapping_document():
    assert extract_constraint_tags("just a string") == []
    assert extract_constraint_tags("") == []


# Every shape a live estate's 75 request-time constraints came in. The parser
# reads what the template writes out and refuses to guess at the rest.


def test_a_bare_input_is_a_reference_and_nothing_more():
    read = describe_dynamic_tag("${input.environment}")
    assert read.kind == "reference"
    assert read.values == ()
    assert read.references == ("input.environment",)


def test_a_chained_conditional_yields_every_tag_it_can_choose():
    """Five branches, three of them the same tag: a reader needs the two
    outcomes, not the five comparisons that lead to them."""
    read = describe_dynamic_tag(
        '${input.environment == "env:dev" ? "net:ALL-sigma-dtq"'
        ' : input.environment == "env:test" ? "net:ALL-sigma-dtq"'
        ' : input.environment == "env:qa" ? "net:ALL-sigma-dtq"'
        ' : input.environment == "env:preprod" ? "net:ALL-sigma-ppp"'
        ' : "net:ALL-sigma-ppp"}'
    )
    assert read.kind == "choice"
    assert read.values == ("net:ALL-sigma-dtq", "net:ALL-sigma-ppp")
    assert read.references == ("input.environment",)


def test_the_compared_values_are_never_read_as_tags():
    """input.environment is itself tag-shaped on this estate. The values it is
    compared against are what the requester answers, not where anything is
    placed, and listing them as candidate tags would be a fabrication."""
    read = describe_dynamic_tag('${input.network == "vlan:900" ? "vlan:902" : "vlan:906"}')
    assert read.values == ("vlan:902", "vlan:906")


def test_parenthesised_branches_read_the_same():
    read = describe_dynamic_tag('${input.cyberark?("net:wis-oob-cyberark"):("net:wis-oob-prod")}')
    assert read.values == ("net:wis-oob-cyberark", "net:wis-oob-prod")
    assert read.references == ("input.cyberark",)


def test_a_concatenation_claims_no_values_but_names_its_prefix():
    """A tag built from a project name and two split() calls could come out as
    anything. The prefix is the one thing that is known about the result."""
    read = describe_dynamic_tag(
        '${"net:"+env.projectName+"-"+split(input.location,":")[1]'
        '+"-"+split(input.environment,":")[1]}'
    )
    assert read.kind == "computed"
    assert read.values == ()
    assert read.prefix == "net:"
    assert read.references == ("env.projectName", "input.location", "input.environment")


def test_a_property_group_lookup_names_what_it_reads():
    read = describe_dynamic_tag(
        '${propgroup.windows_propgroup.deploymentproperties[env.projectName][input.os]["nsxtag"]}'
    )
    assert read.kind == "computed"
    assert read.references == ("propgroup.windows_propgroup", "env.projectName", "input.os")


def test_one_unreadable_branch_makes_the_whole_list_a_guess():
    """The request could always be the one that takes that branch, so "one of
    these two" would be wrong rather than incomplete."""
    read = describe_dynamic_tag('${input.env == "dev" ? "env:dev" : "env:"+input.env}')
    assert read.kind == "computed"
    assert read.values == ()


def test_static_text_around_the_expression_withholds_the_values():
    """net:dtq and net:ppp would both be true, and neither string exists in
    the template's own text. The redacted copy of the report rewrites the
    estate's text, so a value assembled here would be printed unredacted next
    to a tag map that no longer uses that spelling."""
    read = describe_dynamic_tag('net:${input.env == "dev" ? "dtq" : "ppp"}-vcf4')
    assert read.values == ()
    assert read.kind == "computed"
    assert read.prefix == "net:"


def test_a_brace_inside_a_literal_does_not_end_the_expression():
    read = describe_dynamic_tag('${input.x ? "a}b" : "c"}')
    assert read.values == ("a}b", "c")


def test_a_tag_with_no_expression_at_all_reads_as_computed():
    """describe_dynamic_tag is only called for tags the extractor marked
    dynamic, but a caller that gets it wrong must not get a claim back."""
    read = describe_dynamic_tag("env:prod")
    assert read.kind == "computed"
    assert read.values == () and read.references == ()


def test_an_entry_that_is_only_a_hardness_suffix_yields_no_tag():
    """Stripping ":hard" off a tag that was nothing else leaves an empty
    string, and an empty tag joins the capability map as a key that matches
    everything."""
    yaml_text = """
resources:
  vm:
    type: Cloud.vSphere.Machine
    properties:
      constraints:
        - tag: ':hard'
        - tag: '!'
        - tag: 'env:prod:hard'
"""
    tags = extract_constraint_tags(yaml_text)
    assert [t.tag for t in tags] == ["env:prod"]


# A project constrains the requests made in it through three lists, which the
# user interface labels Network, Storage and Extensibility. The build and its
# own documentation disagree about the shape, so both are read.


def test_the_live_shape_is_read():
    """What the 8.x build answers: a list per type, the expression written out,
    and mandatory standing in for hard."""
    read = extract_project_constraints(
        {
            "extensibility": [{"mandatory": True, "expression": "ca:sigma"}],
            "network": [{"mandatory": False, "expression": "net:windowsapps-prod"}],
        }
    )
    assert [(c.tag, c.constraint_type, c.hard, c.negated) for c in read] == [
        ("ca:sigma", "extensibility", True, False),
        ("net:windowsapps-prod", "network", False, False),
    ]


def test_the_documented_shape_is_read():
    """What projects.json types: conditions with enforcement and occurrence,
    and the tag split into a key and a value."""
    read = extract_project_constraints(
        {
            "network": {
                "conditions": [
                    {
                        "type": "TAG",
                        "enforcement": "SOFT",
                        "occurrence": "MUST_NOT_OCCUR",
                        "expression": {"key": "env", "value": "prod"},
                    }
                ]
            }
        }
    )
    assert [(c.tag, c.constraint_type, c.hard, c.negated) for c in read] == [
        ("env:prod", "network", False, True)
    ]


def test_the_text_wins_over_the_field():
    """The user interface offers key:value:soft and !key:value in the same box,
    so the expression can carry what the documented model puts in a field."""
    read = extract_project_constraints(
        {"storage": [{"mandatory": True, "expression": "!disk:gold:soft"}]}
    )
    assert [(c.tag, c.hard, c.negated) for c in read] == [("disk:gold", False, True)]


def test_a_condition_that_is_not_a_tag_is_left_alone():
    read = extract_project_constraints(
        {"network": {"conditions": [{"type": "EXPRESSION", "expression": "something else"}]}}
    )
    assert read == []


def test_a_shape_that_is_neither_claims_nothing():
    """Iterating the keys of a Constraint object adds a capability tag called
    "conditions", which is what reading one shape only would do to the other."""
    assert extract_project_constraints({"network": {"conditions": "not a list"}}) == []
    assert extract_project_constraints({"network": 42}) == []
    assert extract_project_constraints(None) == []
    assert extract_project_constraints({"network": [{"mandatory": True}]}) == []
