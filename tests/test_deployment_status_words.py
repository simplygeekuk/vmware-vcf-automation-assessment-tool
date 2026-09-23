"""The deployments-by-status table says what each status means.

The report goes to stakeholders, and CREATE_FAILED against a count is a raw
enum name, not an answer. Two things matter beyond the wording: the map covers
the deployment service's whole documented enum, and a status it does not know
renders bare rather than explained.
"""

from vcf_automation_assessment_tool.report.renderer import (
    DEPLOYMENT_STATUS_WORDS,
    build_html,
)

# The nine values the deployment service's swagger documents for
# Deployment.status. No day-2 action appears among them, which is the point the
# standfirst makes: a failed power off leaves the deployment reading successful.
DOCUMENTED = {
    "CREATE_SUCCESSFUL",
    "CREATE_INPROGRESS",
    "CREATE_FAILED",
    "UPDATE_SUCCESSFUL",
    "UPDATE_INPROGRESS",
    "UPDATE_FAILED",
    "DELETE_SUCCESSFUL",
    "DELETE_INPROGRESS",
    "DELETE_FAILED",
}


def test_every_documented_status_is_explained():
    assert set(DEPLOYMENT_STATUS_WORDS) == DOCUMENTED


def test_the_table_carries_the_meaning_of_each_status(sample_data):
    html = build_html(sample_data)
    assert "<th>What it means</th>" in html
    assert DEPLOYMENT_STATUS_WORDS["CREATE_FAILED"] in html
    # The standfirst answers the question the table raises: why a failed day-2
    # action is not among these counts.
    assert "day-2 action that failed" in html


def test_a_status_this_build_invented_is_printed_without_a_meaning(sample_data):
    deployments = sample_data.raw["deployments"]["deployments"]
    deployments[0]["status"] = "QUARANTINE_FAILED"
    html = build_html(sample_data)
    assert "QUARANTINE_FAILED" in html
    # Still a real column - other rows fill it - but nothing is invented for
    # the status the map does not know.
    assert "<th>What it means</th>" in html
    row = html[html.index("QUARANTINE_FAILED") :]
    assert row[: row.index("</tr>")].endswith("<td></td>")


def test_the_column_is_dropped_when_nothing_fills_it(sample_data):
    for dep in sample_data.raw["deployments"]["deployments"]:
        dep["status"] = "UNRECOGNISED"
    html = build_html(sample_data)
    assert "<th>What it means</th>" not in html
