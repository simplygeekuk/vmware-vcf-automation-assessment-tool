"""The two headline strips: catalog usage and ownership concentration.

Every number is a claim about the estate, so each has to be withheld rather
than guessed when the data cannot support it.
"""

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.flows import build_flows
from vcf_automation_assessment_tool.report.renderer import (
    catalog_usage_summary,
    deployment_usage_summary,
    owner_usage_summary,
    render_report,
)


def _items(*counts):
    """One item per deployment count; failures are a quarter of each, rounded."""
    return [
        {
            "id": f"i{n}",
            "name": f"Item {n}",
            "deployment_count": c,
            "deployment_failed_count": c // 4,
        }
        for n, c in enumerate(counts)
    ]


def test_no_items_means_no_summary():
    """A percentage of nothing reads as a fact about the estate."""
    assert catalog_usage_summary([]) is None


def test_counts_and_percentages():
    summary = catalog_usage_summary(_items(40, 30, 20, 8, 2, 0, 0))
    assert summary["item_count"] == 7
    assert summary["never_ordered"] == 2
    assert summary["total_deployments"] == 100
    # 10 + 7 + 5 + 2 + 0
    assert summary["failed_deployments"] == 24
    assert summary["failed_pct"] == 24
    # The three most-ordered items carry 90 of the 100 deployments.
    assert summary["concentration_items"] == 3
    assert summary["concentration_pct"] == 90


def test_concentration_is_withheld_on_a_catalog_too_small_to_concentrate():
    """ "The top 3 items account for 100%" says nothing about a catalog of
    three items - it is arithmetic, not a finding."""
    summary = catalog_usage_summary(_items(5, 3, 1))
    assert "concentration_pct" not in summary
    assert summary["item_count"] == 3


def test_a_catalog_nobody_has_ordered_gets_counts_but_no_rates():
    summary = catalog_usage_summary(_items(0, 0, 0, 0))
    assert summary["item_count"] == 4
    assert summary["never_ordered"] == 4
    assert summary["total_deployments"] == 0
    assert "failed_pct" not in summary
    assert "concentration_pct" not in summary


def test_the_table_renders_open_and_under_its_headline(sample_data, tmp_path):
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "catalog.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    assert '<div class="glance headline">' in html
    assert "<span>Orderable items</span>" in html
    assert "<span>No current deployments</span>" in html
    # Open, and marked out from the collapsibles around it: this is the one
    # inventory block read before the findings.
    assert '<details class="inv featured" open>' in html
    assert html.index('class="glance headline"') < html.index('class="inv featured"')
    assert html.index('class="inv featured"') < html.index("Catalog Items and Deployment Usage")


def _owners(*pairs):
    return [{"owner": name, "deployments": n, "machines": 0} for name, n in pairs]


def test_no_owners_means_no_summary():
    assert owner_usage_summary([]) is None


def test_ownership_concentration():
    summary = owner_usage_summary(
        _owners(("bob", 50), ("alice", 25), ("carol", 15), ("dave", 7), ("erin", 3))
    )
    assert summary["owner_count"] == 5
    assert summary["total_deployments"] == 100
    assert summary["top_owner"] == "bob"
    assert summary["top_owner_pct"] == 50
    assert summary["concentration_names"] == 3
    assert summary["concentration_pct"] == 90


def test_concentration_is_withheld_on_an_estate_too_small_to_concentrate():
    """The top owner's own share still means something with three owners; the
    top-three figure does not, because it is everybody."""
    summary = owner_usage_summary(_owners(("bob", 5), ("alice", 3), ("carol", 2)))
    assert summary["top_owner_pct"] == 50
    assert "concentration_pct" not in summary


def test_deployments_with_no_recorded_owner_are_called_out_separately():
    """ "(unknown)" is a gap in the data, not a person, so it is reported on its
    own rather than presented as somebody holding a share of the estate."""
    summary = owner_usage_summary(_owners(("bob", 6), ("(unknown)", 4)))
    assert summary["unknown_owner_deployments"] == 4
    assert summary["top_owner"] == "bob"


def test_the_owner_headline_reads_without_opening_the_table(sample_data, tmp_path):
    """The numbers are the point; the per-owner rows stay collapsed behind
    them. It keeps the accent border, so the blocks a stakeholder is meant to
    read are marked out from the inventory around them."""
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "owners.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    assert "<span>Owners</span>" in html
    assert "<span>Held by the top 3</span>" in html
    owners = html[html.index("<span>Owners</span>") :]
    # Featured, but not open: the headline answers the question and the rows
    # are the follow-up.
    assert owners.index('<details class="inv featured">') < owners.index("Deployments by Owner")
    # Reserved for the three stakeholder-facing blocks in Consumption, and no
    # more: once every block is featured, none of them is.
    assert html.count('class="inv featured') == 3


def test_the_deployment_headline_carries_size_and_health(sample_data, tmp_path):
    """Two questions get asked of this section before any other: how much is
    running, and how much of it is broken. The status table answers neither
    without the reader adding rows up."""
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "deployments.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    strip = html[html.index("<span>Deployments</span>") - 400 : html.index("Deployments by Status")]
    for label in ("Deployments", "Machines", "In a failed state", "Projects in use"):
        assert f"<span>{label}</span>" in strip
    # The headline reads before the table it summarises.
    assert strip.index("glance headline") < len(strip)


def test_deployment_totals_count_machines_not_every_resource(sample_data):
    """Disks and networks are not what anybody means by the size of an estate."""
    deployments = sample_data.raw["deployments"]["deployments"]
    summary = deployment_usage_summary(deployments)
    assert summary["deployment_count"] == len(deployments)
    resources = sum(len(d.get("resources") or []) for d in deployments)
    assert 0 < summary["machines"] < resources


def test_failed_states_are_counted_by_suffix_as_well_as_by_name():
    """The named set does not cover every build's vocabulary, so the _FAILED
    suffix is honoured too - and neither may catch an in-flight deployment."""
    summary = deployment_usage_summary(
        [
            {"status": "CREATE_SUCCESSFUL", "projectId": "p1"},
            {"status": "CREATE_FAILED", "projectId": "p1"},
            {"status": "ROLLBACK_FAILED", "projectId": "p2"},
            {"status": "UPDATE_INPROGRESS", "projectId": "p2"},
        ]
    )
    assert summary["failed"] == 2
    assert summary["projects"] == 2


def test_no_deployments_means_no_headline():
    """Zeroes across the strip would read as a healthy empty estate rather
    than as a section with nothing to say."""
    assert deployment_usage_summary([]) is None
