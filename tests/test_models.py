"""Tests for shared data model helpers."""

import pytest

from vcf_automation_assessment_tool.models import endpoint_status


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({}, None),
        ({"healthy": True}, "OK"),
        ({"healthy": False}, "UNHEALTHY"),
        ({"healthy": True, "inMaintenanceMode": True}, "MAINTENANCE"),
        ({"healthy": False, "inMaintenanceMode": True}, "UNHEALTHY"),
        ({"inMaintenanceMode": True}, "MAINTENANCE"),
        ({"inMaintenanceMode": False}, None),
    ],
)
def test_endpoint_status_boolean_truth_table(document, expected):
    assert endpoint_status(document) == expected


@pytest.mark.parametrize("healthy", [None, 0, 1, "true", [], {}])
def test_endpoint_status_ignores_non_bool_healthy(healthy):
    assert endpoint_status({"healthy": healthy}) is None


def test_endpoint_status_string_wins_over_booleans():
    document = {
        "status": " FAILED ",
        "healthy": True,
        "inMaintenanceMode": True,
    }

    assert endpoint_status(document) == "FAILED"


@pytest.mark.parametrize(
    "bag_name",
    ["customProperties", "cloudAccountProperties", "integrationProperties"],
)
def test_endpoint_status_ignores_booleans_in_property_bags(bag_name):
    document = {bag_name: {"healthy": False, "inMaintenanceMode": True}}

    assert endpoint_status(document) is None


def test_endpoint_status_does_not_read_maintenance_boolean_from_property_bag():
    document = {
        "healthy": True,
        "cloudAccountProperties": {"inMaintenanceMode": True},
    }

    assert endpoint_status(document) == "OK"


def test_endpoint_status_ignores_strings_in_property_bags():
    """The bags hold provider settings, not the endpoint's own health: a
    provider key like state: ENABLED must not beat the documented booleans
    (nor fire INF-003 over configuration)."""
    document = {
        "healthy": False,
        "cloudAccountProperties": {"status": "AVAILABLE"},
    }

    assert endpoint_status(document) == "UNHEALTHY"
    assert endpoint_status({"customProperties": {"state": "ENABLED"}}) is None
