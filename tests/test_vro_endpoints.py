"""One Orchestrator server reached two ways is one endpoint.

A live run listed the embedded Orchestrator as both "https://host/vco" and
"https://host:443/vco" - the same server, one with the default port written
out. Every customer action was then fetched, analysed and parsed twice, which
doubled the API calls and the inventory.
"""

import pytest

from vcf_automation_assessment_tool.collectors.vro import _endpoint_key, _endpoints
from vcf_automation_assessment_tool.models import AssessmentData


class FakeClient:
    base_url = "https://host"


def _data(*urls):
    data = AssessmentData()
    data.raw["infrastructure"] = {
        "integrations": [
            {
                "name": f"vro-{index}",
                "integrationType": "vro",
                "integrationProperties": {"apiEndpoint": url},
            }
            for index, url in enumerate(urls)
        ]
    }
    return data


@pytest.mark.parametrize(
    "url",
    [
        "https://host:443/vco",
        "https://HOST/vco",
        "https://host/vco/",
    ],
)
def test_the_embedded_server_is_recognised_however_it_is_written(url):
    endpoints = _endpoints(FakeClient(), _data(url))
    assert [u for _, u in endpoints] == ["https://host/vco"]


def test_a_genuinely_different_server_is_kept():
    endpoints = _endpoints(FakeClient(), _data("https://other/vco"))
    assert [u for _, u in endpoints] == ["https://host/vco", "https://other/vco"]


def test_a_non_default_port_is_a_different_endpoint():
    """:8281 is the standalone Orchestrator's own port, not a spelling of 443."""
    endpoints = _endpoints(FakeClient(), _data("https://host:8281/vco"))
    assert [u for _, u in endpoints] == ["https://host/vco", "https://host:8281/vco"]


def test_the_key_ignores_only_the_default_port_for_the_scheme():
    assert _endpoint_key("https://host:443/vco") == _endpoint_key("https://host/vco")
    assert _endpoint_key("http://host:80/vco") == _endpoint_key("http://host/vco")
    # http on 443 is not the default for http, so it stays distinct.
    assert _endpoint_key("http://host:443/vco") != _endpoint_key("http://host/vco")
