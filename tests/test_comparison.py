"""Run-over-run comparison: what moved since an earlier --json dump."""

import json

import pytest

import vcf_automation_assessment_tool.cli as cli
from vcf_automation_assessment_tool.comparison import (
    compare_runs,
    inventory_counts,
    load_previous,
    previous_path_problem,
)
from vcf_automation_assessment_tool.models import AffectedObject, AssessmentData, Finding, Severity


def _finding(check_id, *objects, severity=Severity.WARNING):
    return Finding(
        check_id=check_id,
        title=f"title {check_id}",
        severity=severity,
        recommendation="do",
        affected=[
            AffectedObject(kind="thing", id=oid, name=name, detail="") for oid, name in objects
        ],
    )


def _dump(data: AssessmentData) -> dict:
    return json.loads(json.dumps(data.to_json_dict(), default=str))


def _now():
    data = AssessmentData()
    data.meta = {
        "url": "https://vra.example.test",
        "generated_at": "2026-09-22",
        "assessment_ruleset": "same-definitions",
    }
    data.findings = [
        _finding("DEP-001", ("d1", "web-prod"), ("d3", "new-one")),  # d2 resolved, d3 new
        _finding("CAT-001", ("", "unused-item")),  # matched by name: no id
        _finding("EXT-008", ("a1", "old-py")),  # new finding
    ]
    data.raw = {
        "deployments": {
            "deployments": [
                {
                    "id": "d1",
                    "resources": [{"type": "Cloud.vSphere.Machine"}, {"type": "Cloud.Network"}],
                },
                {"id": "d3", "resources": [{"type": "Cloud.Machine"}]},
            ]
        },
        "catalog": {"items": [{"id": "i1"}, {"id": "i2"}]},
        "governance": {"policies": []},
        "infrastructure": {"projects": []},
        "extensibility": {"abx_actions": []},
    }
    return data


def _before():
    data = AssessmentData()
    data.meta = {
        "url": "https://vra.example.test",
        "generated_at": "2026-08-01",
        "assessment_ruleset": "same-definitions",
    }
    data.findings = [
        _finding("DEP-001", ("d1", "web-prod"), ("d2", "gone-dep")),
        _finding("CAT-001", ("", "unused-item")),
        _finding("POL-002", ("p9", "stale-policy")),  # resolved finding
    ]
    data.raw = {
        "deployments": {
            "deployments": [{"id": "d1", "resources": [{"type": "Cloud.vSphere.Machine"}]}]
        },
        "catalog": {"items": [{"id": "i1"}]},
        "blueprints": {"blueprints": [{"id": "b1"}]},  # absent from the current run
        "governance": {"policies": []},
        "infrastructure": {"projects": []},
        "extensibility": {"abx_actions": []},
    }
    return data


def test_findings_are_classified_and_objects_matched_by_id_then_name():
    result = compare_runs(_now(), _dump(_before()))
    rows = {r["check_id"]: r for r in result["findings"]}
    assert rows["DEP-001"]["status"] == "changed"
    assert rows["DEP-001"]["new_names"] == ["new-one"]
    assert rows["DEP-001"]["resolved_names"] == ["gone-dep"]
    assert (rows["DEP-001"]["before"], rows["DEP-001"]["now"]) == (2, 2)
    assert rows["CAT-001"]["status"] == "unchanged"
    assert rows["EXT-008"]["status"] == "new" and rows["EXT-008"]["before"] == 0
    assert rows["POL-002"]["status"] == "resolved" and rows["POL-002"]["now"] == 0
    # New, resolved and changed first; the id sorts within a status.
    assert [r["check_id"] for r in result["findings"]] == [
        "EXT-008",
        "POL-002",
        "DEP-001",
        "CAT-001",
    ]
    assert result["summary"] == {
        "unable_to_reassess": 0,
        "new": 1,
        "resolved": 1,
        "changed": 1,
        "unchanged": 1,
        "objects_added": 2,
        "objects_resolved": 2,
    }


def test_inventory_rows_only_where_both_runs_hold_the_list():
    result = compare_runs(_now(), _dump(_before()))
    rows = {r["label"]: r for r in result["inventory"]}
    assert rows["Deployments"]["delta"] == 1
    assert rows["Machines"] == {"label": "Machines", "before": 1, "now": 2, "delta": 1}
    assert rows["Catalog items"]["delta"] == 1
    # Templates were collected before and not now: no row, never "-1".
    assert "Cloud templates" not in rows
    assert result["previous"] == {
        "generated_at": "2026-08-01",
        "tool_version": "",
        "same_target": True,
    }


def test_a_different_target_is_said_without_naming_it():
    before = _dump(_before())
    before["meta"]["url"] = "https://other.example.test"
    result = compare_runs(_now(), before)
    assert result["previous"]["same_target"] is False
    assert "other.example.test" not in json.dumps(result)


def test_inventory_counts_treat_a_missing_list_as_unknown():
    counts = inventory_counts({"deployments": {"deployments": "not a list"}})
    assert counts["Deployments"] is None and counts["Machines"] is None
    assert inventory_counts({})["Projects"] is None


def test_previous_dump_is_validated_before_login(tmp_path):
    assert previous_path_problem(None) is None
    assert "not found" in previous_path_problem(str(tmp_path / "missing.json"))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert "not a JSON dump" in previous_path_problem(str(bad))
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"meta": {}}), encoding="utf-8")
    assert "no findings list" in previous_path_problem(str(other))
    good = tmp_path / "good.json"
    good.write_text(json.dumps(_dump(_before())), encoding="utf-8")
    assert previous_path_problem(str(good)) is None
    assert load_previous(str(good))["meta"]["generated_at"] == "2026-08-01"


def test_a_bad_compare_file_fails_the_run_before_it_logs_in(monkeypatch, tmp_path, capsys):
    class NeverLogin:
        def __init__(self, cfg):
            raise AssertionError("login must not be attempted")

    monkeypatch.setattr(cli, "ApiClient", NeverLogin)
    rc = cli.main(
        [
            "--url",
            "https://vra.example.test",
            "--refresh-token",
            "tok",
            "--output",
            str(tmp_path / "report.html"),
            "--compare",
            str(tmp_path / "missing.json"),
        ]
    )
    assert rc == 1
    assert "compare file not found" in capsys.readouterr().err


def test_the_summary_block_renders_and_hides_old_names_when_redacted(sample_data, tmp_path):
    from vcf_automation_assessment_tool.checks import run_checks
    from vcf_automation_assessment_tool.report.renderer import render_report

    run_checks(sample_data)
    before = _dump(sample_data)
    before["meta"]["generated_at"] = "2026-08-01"
    # The earlier run flagged one deployment this run no longer does.
    for f in before["findings"]:
        if f["check_id"] == "DEP-001":
            f["affected"].append(
                {"kind": "deployment", "id": "dz", "name": "was-failing", "detail": ""}
            )
    sample_data.derived["comparison"] = compare_runs(sample_data, before)
    sample_data.meta["compared_with"] = "2026-08-01"
    out = tmp_path / "report.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    assert "Since the run of 2026-08-01" in html
    assert "<div>Compared with<b>run of 2026-08-01</b></div>" in html
    block = html[html.index("Since the run of") : html.index("<tr><th>ID</th><th>Severity</th>")]
    assert "<td>changed</td>" in block and "was-failing" in block
    assert "Objects no longer flagged" in block

    sample_data.meta["redaction"] = {"classes": ["identity"], "replaced": 0, "described": "nothing"}
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    block = html[html.index("Since the run of") : html.index("<tr><th>ID</th><th>Severity</th>")]
    assert "was-failing" not in block and "1 object" in block


def test_ignored_findings_leave_the_comparison_too(sample_data, tmp_path):
    from vcf_automation_assessment_tool.checks import run_checks
    from vcf_automation_assessment_tool.report.renderer import render_report

    run_checks(sample_data)
    before = _dump(sample_data)
    before["findings"] = [f for f in before["findings"] if f["check_id"] != "DEP-001"]
    sample_data.derived["comparison"] = compare_runs(sample_data, before)
    sample_data.meta["ignore_findings"] = ["DEP-001"]
    out = tmp_path / "report.html"
    render_report(sample_data, str(out))
    block = out.read_text(encoding="utf-8")
    block = block[block.index("Since the run of") : block.index("<tr><th>ID</th><th>Severity</th>")]
    assert "DEP-001" not in block


@pytest.mark.parametrize("payload", ["[]", '{"findings": []}'])
def test_load_previous_rejects_a_dump_without_meta_or_findings(tmp_path, payload):
    path = tmp_path / "x.json"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError):
        load_previous(str(path))
