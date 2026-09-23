"""Pagination helpers against a stubbed ApiClient.get."""

from vcf_automation_assessment_tool.client import ApiClient
from vcf_automation_assessment_tool.config import RunConfig


def make_client(pages):
    """pages: list of response bodies returned by successive get() calls."""
    cfg = RunConfig(url="https://example.test")
    client = ApiClient(cfg)
    calls = []

    def fake_get(path, params=None):
        calls.append(dict(params or {}))
        return pages[len(calls) - 1]

    client.get = fake_get
    client.calls = calls
    return client


def test_iter_odata_walks_all_pages():
    client = make_client(
        [
            {"content": [{"id": 1}, {"id": 2}], "totalElements": 3},
            {"content": [{"id": 3}], "totalElements": 3},
        ]
    )
    items = list(client.iter_odata("/iaas/api/things", page_size=2))
    assert [i["id"] for i in items] == [1, 2, 3]
    assert client.calls[0]["$skip"] == 0
    assert client.calls[1]["$skip"] == 2


def test_iter_odata_empty():
    client = make_client([{"content": [], "totalElements": 0}])
    assert list(client.iter_odata("/iaas/api/things")) == []


def test_iter_odata_exact_multiple_stops():
    client = make_client(
        [
            {"content": [{"id": 1}, {"id": 2}], "totalElements": 2},
        ]
    )
    assert len(list(client.iter_odata("/x", page_size=2))) == 2
    assert len(client.calls) == 1  # no wasted extra page


def test_iter_odata_pins_api_version():
    client = make_client([{"content": [], "totalElements": 0}])
    client.iaas_api_version = "2021-07-15"
    list(client.iter_odata("/x"))
    assert client.calls[0]["apiVersion"] == "2021-07-15"


def test_iter_paged_uses_last_flag():
    client = make_client(
        [
            {"content": [{"id": 1}], "last": False, "totalPages": 2},
            {"content": [{"id": 2}], "last": True, "totalPages": 2},
        ]
    )
    items = list(client.iter_paged("/deployment/api/deployments", page_size=1))
    assert [i["id"] for i in items] == [1, 2]
    assert client.calls[0]["page"] == 0
    assert client.calls[1]["page"] == 1


def test_iter_paged_stops_on_total_pages_without_last():
    client = make_client(
        [
            {"content": [{"id": 1}], "totalPages": 1},
        ]
    )
    assert len(list(client.iter_paged("/x"))) == 1
    assert len(client.calls) == 1


def test_iter_paged_stops_on_empty_content():
    client = make_client([{"content": []}])
    assert list(client.iter_paged("/x")) == []


def test_iter_paged_stops_on_a_repeated_page():
    """A server ignoring the page param with neither last nor totalPages in
    the envelope used to loop forever re-yielding page 0."""
    same = {"content": [{"id": "a"}, {"id": "b"}]}
    client = make_client([same, same, same])
    items = list(client.iter_paged("/svc/things", page_size=2))
    assert [i["id"] for i in items] == ["a", "b"]  # yielded once, then stopped
    assert len(client.calls) == 2


def test_iter_odata_missing_total_walks_to_a_short_page():
    """No totalElements used to read as 0 and truncate to the first page."""
    client = make_client(
        [
            {"content": [{"id": 1}, {"id": 2}]},
            {"content": [{"id": 3}]},
        ]
    )
    items = list(client.iter_odata("/iaas/api/things", page_size=2))
    assert [i["id"] for i in items] == [1, 2, 3]


def test_iter_odata_stops_on_a_repeated_page():
    same = {"content": [{"id": "a"}, {"id": "b"}]}
    client = make_client([same, same, same])
    items = list(client.iter_odata("/iaas/api/things", page_size=2))
    assert [i["id"] for i in items] == ["a", "b"]
    assert len(client.calls) == 2
