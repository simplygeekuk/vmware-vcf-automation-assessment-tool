"""What a template input can be: reading the schema, and collecting it.

The values behind a request-time constraint come from the platform's own
resolved schema, so a reader on any estate gets that estate's answer rather
than one written from the estate this tool was built against.
"""

from pathlib import Path

from vcf_automation_assessment_tool.client import ApiError
from vcf_automation_assessment_tool.collectors.blueprints import _collect_inputs
from vcf_automation_assessment_tool.models import AssessmentData
from vcf_automation_assessment_tool.tagutil import (
    input_references,
    input_source_label,
    read_input_schema,
)

SCHEMA = {
    "type": "object",
    "encrypted": False,
    "properties": {
        "environment": {
            "type": "string",
            "title": "Environment",
            "default": "env:preprod",
            "oneOf": [
                {"title": "Preprod", "const": "env:preprod"},
                {"title": "Prod", "const": "env:prod"},
            ],
        },
        "os": {"type": "string", "title": "OS", "enum": ["RHEL8", "RHEL9"]},
        "Information_System": {
            "type": "string",
            "title": "Information System",
            "$data": "/data/vro-actions/ie.aib.cmdb/list_cmdb_app_names",
        },
        "app_name": {"type": "string", "title": "App Name", "maxLength": 7},
    },
}


def _by_name(schema=SCHEMA, wanted=None):
    return {i.name: i for i in read_input_schema(schema, wanted)}


def test_a_labelled_choice_is_read_as_its_values():
    """oneOf carries the label the form shows and the value the tag matches.
    The value is what placement compares, so the value is what is kept."""
    environment = _by_name()["environment"]
    assert environment.kind == "declared"
    assert environment.values == ("env:preprod", "env:prod")
    assert environment.default == "env:preprod"
    assert environment.title == "Environment"


def test_a_plain_enum_is_read_as_its_values():
    assert _by_name()["os"].values == ("RHEL8", "RHEL9")


def test_an_externally_fed_input_names_its_source_and_claims_no_values():
    information_system = _by_name()["Information_System"]
    assert information_system.kind == "external"
    assert information_system.values == ()
    assert information_system.source == "/data/vro-actions/ie.aib.cmdb/list_cmdb_app_names"
    assert input_source_label(information_system.source) == (
        "Orchestrator action ie.aib.cmdb/list_cmdb_app_names"
    )


def test_the_other_documented_source_key_is_read_the_same_way():
    """$data is what this build writes; the API documents $dynamicDefault too."""
    schema = {"properties": {"x": {"$dynamicDefault": "/data/vro-actions/mod/act"}}}
    assert _by_name(schema)["x"].kind == "external"


def test_an_input_declaring_nothing_is_not_an_input_that_could_not_be_read():
    assert _by_name()["app_name"].kind == "none"


def test_a_shape_the_reader_does_not_recognise_claims_nothing():
    """Every one of these has a declaration. None of them is a list of tags
    this tool can read in full, and inventing one puts a guess in the report."""
    for definition in (
        {"anyOf": [{"const": "a"}, {"const": "b"}]},
        {"$ref": "#/components/schemas/Thing"},
        {"oneOf": [{"const": "env:prod"}, {"title": "Other"}]},
        {"enum": [1, 2, 3]},
        {"enum": ["a"], "oneOf": [{"const": "b"}]},
    ):
        entry = _by_name({"properties": {"x": definition}})["x"]
        assert entry.kind == "unread", definition
        assert entry.values == ()


def test_a_schema_without_properties_yields_nothing():
    assert read_input_schema({}) == []
    assert read_input_schema({"properties": []}) == []


def test_only_the_inputs_a_constraint_reads_are_kept():
    assert set(_by_name(wanted={"environment"})) == {"environment"}


def test_the_inputs_a_constraint_reads_are_named_from_its_expression():
    tags = [
        {"tag": "${input.environment}"},
        {"tag": '${input.site == "a" ? "net:a" : "net:b"}'},
        {"tag": "${env.projectName}"},
        {"tag": "env:prod"},
    ]
    assert input_references(tags) == {"environment", "site"}


class StubClient:
    def __init__(self, answers):
        self.answers = answers
        self.paths = []

    def get(self, path, params=None):
        self.paths.append(path)
        answer = self.answers.get(path)
        if isinstance(answer, ApiError):
            raise answer
        return answer


def _entry(bp_id="bp1", name="Template", tags=("${input.environment}",)):
    return {
        "id": bp_id,
        "name": name,
        "constraint_tags": [{"tag": t} for t in tags],
        "inputs": None,
    }


def test_a_template_no_constraint_reads_an_input_from_is_never_asked():
    client = StubClient({})
    data = AssessmentData()
    entry = _entry(tags=("env:prod",))
    _collect_inputs(client, data, entry, {"available": True, "asked": False})
    assert client.paths == []
    assert entry["inputs"] is None
    assert data.errors == []


def test_the_referenced_input_is_collected_and_the_rest_left_alone():
    client = StubClient({"/blueprint/api/blueprints/bp1/inputs-schema": SCHEMA})
    data = AssessmentData()
    entry = _entry()
    _collect_inputs(client, data, entry, {"available": True, "asked": False})
    assert [i["name"] for i in entry["inputs"]] == ["environment"]
    assert entry["inputs"][0]["values"] == ("env:preprod", "env:prod")


def test_a_build_without_the_route_is_asked_once():
    state = {"available": True, "asked": False}
    client = StubClient(
        {
            "/blueprint/api/blueprints/bp1/inputs-schema": ApiError("GET -> 404", status_code=404),
            "/blueprint/api/blueprints/bp2/inputs-schema": SCHEMA,
        }
    )
    data = AssessmentData()
    first, second = _entry(), _entry("bp2", "Other")
    _collect_inputs(client, data, first, state)
    _collect_inputs(client, data, second, state)
    assert client.paths == ["/blueprint/api/blueprints/bp1/inputs-schema"]
    assert [e["item"] for e in data.errors] == ["blueprint-inputs"]
    assert first["inputs"] is None and second["inputs"] is None


def test_one_unreadable_template_does_not_cost_the_others():
    state = {"available": True, "asked": False}
    client = StubClient(
        {
            "/blueprint/api/blueprints/bp1/inputs-schema": SCHEMA,
            "/blueprint/api/blueprints/bp2/inputs-schema": ApiError("GET -> 500", status_code=500),
            "/blueprint/api/blueprints/bp3/inputs-schema": SCHEMA,
        }
    )
    data = AssessmentData()
    third = _entry("bp3", "Third")
    _collect_inputs(client, data, _entry(), state)
    _collect_inputs(client, data, _entry("bp2", "Second"), state)
    _collect_inputs(client, data, third, state)
    assert [e["item"] for e in data.errors] == ["blueprint-inputs:Second"]
    assert third["inputs"] is not None


def test_nothing_asks_the_form_service_to_resolve_an_external_list():
    """That route runs the Orchestrator action behind the field. This is a
    read-only assessment, and it names the action instead."""
    source = Path("src/vcf_automation_assessment_tool")
    hits = [p for p in source.rglob("*.py") if "external-values" in p.read_text(encoding="utf-8")]
    assert hits == []
