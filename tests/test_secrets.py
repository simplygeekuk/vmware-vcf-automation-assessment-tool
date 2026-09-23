"""Platform secrets: names and scope only, template use resolved, INF-007."""

from vcf_automation_assessment_tool.checks.infrastructure import inf_007_secrets_no_template_reads
from vcf_automation_assessment_tool.collectors.blueprints import secret_refs
from vcf_automation_assessment_tool.collectors.infrastructure import _slim_secret
from vcf_automation_assessment_tool.models import AssessmentData, secret_rows


def test_the_collector_never_keeps_the_value():
    slimmed = _slim_secret(
        {
            "id": "s1",
            "name": "db-password",
            "value": "hunter2",
            "orgScoped": False,
            "projectIds": ["p1", None, "p2"],
            "createdBy": "alice",
        }
    )
    assert "value" not in slimmed
    assert slimmed["projectIds"] == ["p1", "p2"]
    assert slimmed["orgScoped"] is False


def test_secret_references_are_read_from_template_content():
    content = (
        "inputs: {}\nresources:\n  vm:\n    properties:\n"
        "      password: ${secret.db-password}\n"
        "      token: ${secret.api.token}\n      again: ${secret.db-password}\n"
    )
    assert secret_refs(content) == ["api.token", "db-password"]
    assert secret_refs("") == []


def _data(gap=None):
    data = AssessmentData()
    data.derived["project_names"] = {"p1": "Platform", "p2": "Edge"}
    data.raw["infrastructure"] = {
        "secrets": [
            {
                "id": "s1",
                "name": "used",
                "orgScoped": True,
                "createdBy": "alice",
                "updatedAt": "2025-01-02T00:00:00Z",
            },
            {
                "id": "s2",
                "name": "shared",
                "orgScoped": False,
                "projectIds": ["p1", "p2"],
                "createdBy": "bob",
            },
            {
                "id": "s3",
                "name": "wide",
                "orgScoped": False,
                "projectIds": [f"p{i}" for i in range(10)],
            },
            {
                "id": "s4",
                "name": "pg-only",
                "orgScoped": False,
                "projectId": "p1",
                "projectName": "Platform",
            },
        ]
    }
    data.raw["blueprints"] = {
        "blueprints": [
            {"id": "b1", "name": "Web Server", "secret_refs": ["used"]},
            {"id": "b2", "name": "Unread", "secret_refs": None},
        ],
        "property_groups": [
            {"id": "pg1", "name": "common", "properties": {"key": "${secret.pg-only}"}}
        ],
    }
    if gap:
        data.record_error(*gap)
    return data


def test_rows_resolve_scope_and_readers():
    rows = {r["name"]: r for r in secret_rows(_data())}
    assert rows["used"]["scope"] == "organization"
    assert rows["used"]["used_by"] == ["Web Server"]
    assert rows["used"]["updated"] == "2025-01-02"
    assert rows["shared"]["scope"] == "Edge, Platform" and rows["shared"]["used_by"] == []
    # The API caps projectIds at ten, so ten is a floor, not a count.
    assert rows["wide"]["scope"] == "10 or more projects"
    assert rows["pg-only"]["scope"] == "Platform"
    assert rows["pg-only"]["used_by"] == ["property group common"]


def test_inf007_lists_only_what_nothing_reads():
    (finding,) = inf_007_secrets_no_template_reads(_data())
    assert [o.name for o in finding.affected] == ["shared", "wide"]
    assert finding.severity.name == "INFO"
    assert "scope: Edge, Platform" in finding.affected[0].detail


def test_inf007_is_withheld_when_a_template_or_the_secrets_could_not_be_read():
    assert (
        inf_007_secrets_no_template_reads(_data(gap=("blueprints", "blueprint:Unread", "403")))
        == []
    )
    assert inf_007_secrets_no_template_reads(_data(gap=("infrastructure", "secrets", "403"))) == []


def test_secrets_table_shows_readers_and_withholds_them_on_a_gap(sample_data, tmp_path):
    from vcf_automation_assessment_tool.report.renderer import render_report

    out = tmp_path / "report.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    table = html[html.index("<summary>Secrets ") :]
    table = table[: table.index("</details>")]
    assert "1 read by nothing" in table
    assert "<td>ad-join-password</td>" in table and "web-server" in table
    assert "<td>legacy-api-key</td>" in table and "nothing" in table
    assert "hunter2" not in html

    sample_data.record_error("blueprints", "blueprint:web-server", "403")
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    table = html[html.index("<summary>Secrets ") :]
    table = table[: table.index("</details>")]
    assert "<th>Used by</th>" not in table and "withheld here" in table
