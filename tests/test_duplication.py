"""EXT-007: actions duplicated across the estate.

Fixtures live here rather than in conftest's sample_data on purpose: adding an
action to the shared fixture ripples every ABX count assertion in test_report
and test_checks, the same reason the POL-003 day-2 fixtures are kept separate.
"""

from __future__ import annotations

from vcf_automation_assessment_tool import codequality
from vcf_automation_assessment_tool.checks.governance import ext_007_duplicated_action_source
from vcf_automation_assessment_tool.models import AssessmentData

# Long enough to clear MIN_DUPLICATE_CODE_LINES; short glue scripts are
# excluded by design and would prove nothing here.
BASE = "\n".join(
    [
        "import json",
        "def handler(context, inputs):",
        "    payload = json.loads(inputs['body'])",
        "    host = payload['host']",
        "    record = {'name': host, 'owner': payload['owner']}",
        "    record['env'] = payload.get('env', 'dev')",
        "    record['tier'] = payload.get('tier', 'web')",
        "    for key in ('cpu', 'memory', 'disk'):",
        "        record[key] = payload.get(key)",
        "    if not record['owner']:",
        "        raise ValueError('owner is required')",
        "    result = context.request('/cmdb/api/ci', 'POST', record)",
        "    if result.get('status') != 201:",
        "        raise RuntimeError('cmdb rejected the record')",
        "    context.log('registered ' + host)",
        "    return {'id': result['id'], 'host': host}",
    ]
)
# One line changed: the copy-paste-then-tweak case the check exists to find.
TWEAKED = BASE.replace("'tier', 'web'", "'tier', 'app'")
# Same logic, reformatted and re-commented only.
REFORMATTED = "# Registers a CI in the CMDB.\n" + BASE.replace("    ", "        ")
UNRELATED = "\n".join(
    [
        "def handler(context, inputs):",
        "    total = 0",
        "    for machine in inputs['machines']:",
        "        total += machine['cpuCount']",
        "        context.log('counted ' + machine['name'])",
        "    quota = context.getSecret('quota_limit')",
        "    if total > int(quota):",
        "        return {'allowed': False, 'total': total}",
        "    for tag in inputs['tags']:",
        "        context.log('tag ' + tag)",
        "    summary = {'allowed': True, 'total': total}",
        "    summary['checked'] = len(inputs['machines'])",
        "    summary['quota'] = quota",
        "    context.log('quota check complete')",
        "    return summary",
    ]
)


def _abx(action_id: str, name: str, source: str) -> dict:
    sketch = codequality.source_sketch(source, "python")
    return {
        "id": action_id,
        "name": name,
        "runtime": "python",
        "has_inline_source": True,
        "analysis": {"code_lines": sketch["code_lines"]},
        "source_fingerprint": sketch["fingerprint"],
        "source_sketch": sketch["sketch"],
    }


def _vro(action_id: str, fqn: str, source: str) -> dict:
    sketch = codequality.source_sketch(source, "python")
    return {
        "id": action_id,
        "fqn": fqn,
        "name": fqn.rsplit("/", 1)[-1],
        "runtime": "python",
        "analysis": {"code_lines": sketch["code_lines"]},
        "source_fingerprint": sketch["fingerprint"],
        "source_sketch": sketch["sketch"],
    }


def _data(abx: list[dict], vro: list[dict] | None = None) -> AssessmentData:
    data = AssessmentData()
    data.raw["extensibility"] = {"abx_actions": abx}
    data.raw["vro"] = {"actions": vro or []}
    return data


def test_exact_copies_are_one_group():
    data = _data([_abx("a1", "register-cmdb", BASE), _abx("a2", "register-cmdb-copy", BASE)])
    findings = ext_007_duplicated_action_source(data)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "EXT-007"
    assert len(finding.affected) == 1
    detail = finding.affected[0].detail
    assert "identical source" in detail
    assert "register-cmdb (ABX)" in detail
    assert "register-cmdb-copy (ABX)" in detail


def test_reformatting_and_comments_do_not_hide_a_copy():
    data = _data([_abx("a1", "original", BASE), _abx("a2", "reindented", REFORMATTED)])
    detail = ext_007_duplicated_action_source(data)[0].affected[0].detail
    assert "identical source" in detail


def test_one_edited_line_still_groups_and_is_reported_as_partial():
    data = _data([_abx("a1", "original", BASE), _abx("a2", "tweaked", TWEAKED)])
    detail = ext_007_duplicated_action_source(data)[0].affected[0].detail
    assert "identical source" not in detail
    assert "% or more of the source in common" in detail


def test_copies_across_abx_and_orchestrator_group_together():
    # Copy-paste crosses the boundary; one finding, both platforms named.
    data = _data(
        [_abx("a1", "register-cmdb", BASE)],
        [_vro("v1", "com.simplygeek.cmdb/registerCi", BASE)],
    )
    detail = ext_007_duplicated_action_source(data)[0].affected[0].detail
    assert "register-cmdb (ABX)" in detail
    assert "com.simplygeek.cmdb/registerCi (Orchestrator)" in detail


def test_unrelated_actions_are_not_grouped():
    data = _data([_abx("a1", "register-cmdb", BASE), _abx("a2", "quota-check", UNRELATED)])
    assert ext_007_duplicated_action_source(data) == []


def test_short_actions_are_never_compared():
    # Glue scripts that read an input and call one API resemble each other by
    # nature; reporting them would swamp the finding.
    tiny = "def handler(context, inputs):\n    return inputs['x']\n"
    data = _data([_abx("a1", "one", tiny), _abx("a2", "two", tiny)])
    assert ext_007_duplicated_action_source(data) == []


def test_unanalyzable_actions_are_skipped():
    # Flows and bundles carry no sketch: they must not cluster with each other
    # on the strength of both being empty.
    bundled = {"id": "a1", "name": "bundle-one", "source_sketch": [], "source_fingerprint": ""}
    flow = {"id": "a2", "name": "flow-one", "source_sketch": [], "source_fingerprint": ""}
    assert ext_007_duplicated_action_source(_data([bundled, flow])) == []


def test_three_copies_report_as_one_group_of_three():
    data = _data(
        [
            _abx("a1", "first", BASE),
            _abx("a2", "second", BASE),
            _abx("a3", "third", TWEAKED),
        ]
    )
    finding = ext_007_duplicated_action_source(data)[0]
    assert len(finding.affected) == 1
    assert "3 actions" in finding.affected[0].detail
