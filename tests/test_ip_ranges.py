"""IP ranges: one reading shared by the Infrastructure table and INF-005/006."""

from vcf_automation_assessment_tool.checks.infrastructure import (
    inf_005_ip_ranges_exhausted,
    inf_006_ip_ranges_near_exhaustion,
)
from vcf_automation_assessment_tool.models import AssessmentData, ip_range_usage
from vcf_automation_assessment_tool.report.renderer import render_report


def _range(name, total, allocated, available, **extra):
    return {
        "id": name,
        "name": name,
        "ipVersion": "IPv4",
        "startIPAddress": "10.0.0.1",
        "endIPAddress": "10.0.0.254",
        "totalNumberOfIPs": total,
        "numberOfAllocatedIPs": allocated,
        "numberOfAvailableIPs": available,
        **extra,
    }


def _data(ranges, gap=False):
    data = AssessmentData()
    data.raw["infrastructure"] = {"network_ip_ranges": ranges}
    if gap:
        data.record_error("infrastructure", "network_ip_ranges", "403")
    return data


def test_usage_never_invents_a_ratio_from_a_missing_counter():
    rows = ip_range_usage(
        [
            _range("full", 50, 50, 0),
            _range("near", 100, 85, 15),
            _range("unknown", None, 5, None),
            _range("zero-total", 0, 0, 0),
        ]
    )
    by = {r["name"]: r for r in rows}
    assert by["full"]["ratio"] == 1
    assert by["near"]["ratio"] == 0.85
    assert by["unknown"]["ratio"] is None and by["unknown"]["total"] is None
    assert by["zero-total"]["ratio"] is None


def test_checks_split_full_from_near_and_skip_the_unknown():
    data = _data(
        [_range("full", 50, 50, 0), _range("near", 100, 85, 15), _range("unknown", None, 5, None)]
    )
    (full,) = inf_005_ip_ranges_exhausted(data)
    (near,) = inf_006_ip_ranges_near_exhaustion(data)
    assert [o.name for o in full.affected] == ["full"]
    assert [o.name for o in near.affected] == ["near"]
    assert "50 of 50 addresses allocated, 0 available" in full.affected[0].detail


def test_checks_are_silent_when_the_ranges_could_not_be_read():
    data = _data([_range("full", 50, 50, 0)], gap=True)
    assert inf_005_ip_ranges_exhausted(data) == []
    assert inf_006_ip_ranges_near_exhaustion(data) == []


def test_table_and_findings_agree_on_the_sample(sample_data, tmp_path):
    from vcf_automation_assessment_tool.checks import run_checks

    run_checks(sample_data)
    out = tmp_path / "report.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    table = html[html.index("<summary>IP Ranges ") :]
    table = table[: table.index("</details>")]
    assert "2 at or near full" in table
    assert "<td>dev-range</td>" in table and "100%" in table
    assert "<td>prod-range</td>" in table and "83%" in table
    flagged = {
        f.check_id: [o.name for o in f.affected]
        for f in sample_data.findings
        if f.check_id in ("INF-005", "INF-006")
    }
    assert flagged == {"INF-005": ["dev-range"], "INF-006": ["prod-range"]}
