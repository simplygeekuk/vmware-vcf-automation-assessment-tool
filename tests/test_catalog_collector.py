"""Entitlement resolution: projectIds unioned from item- and source-level
shares; unreadable entitlements must leave the field alone rather than
fabricating 'shared with nobody'."""

from vcf_automation_assessment_tool.client import ApiError
from vcf_automation_assessment_tool.collectors.catalog import _apply_entitlements
from vcf_automation_assessment_tool.models import AssessmentData


class StubClient:
    def __init__(self, by_project, error=None):
        self.by_project = by_project  # projectId -> entitlements list
        self.error = error

    def get(self, path, params=None):
        if self.error:
            raise self.error
        return self.by_project.get((params or {}).get("projectId"), [])


def _setup(items):
    data = AssessmentData()
    data.raw["infrastructure"] = {
        "projects": [{"id": "p1", "name": "Platform"}, {"id": "p2", "name": "Dev"}]
    }
    return data, {"items": items}


def test_item_and_source_level_entitlements_union():
    items = [
        {"id": "i1", "sourceId": "s1", "projectIds": []},
        {"id": "i2", "sourceId": "s1", "projectIds": []},
        {"id": "i3", "sourceId": "s2", "projectIds": ["p9"]},  # pre-populated survives
    ]
    client = StubClient(
        {
            # Whole-source share: everything imported from s1 goes to p1.
            "p1": [{"definition": {"type": "CatalogSourceIdentifier", "id": "s1"}}],
            # Item-level share: only i2 also goes to p2.
            "p2": [{"definition": {"type": "CatalogItemIdentifier", "id": "i2"}}],
        }
    )
    data, raw = _setup(items)
    _apply_entitlements(client, data, raw)
    assert raw["entitlements_collected"] is True
    assert items[0]["projectIds"] == ["p1"]
    assert items[1]["projectIds"] == ["p1", "p2"]
    assert items[2]["projectIds"] == ["p9"]


def test_forbidden_entitlements_leave_items_untouched():
    items = [{"id": "i1", "sourceId": "s1", "projectIds": []}]
    client = StubClient({}, error=ApiError("HTTP 403", status_code=403))
    data, raw = _setup(items)
    _apply_entitlements(client, data, raw)
    assert raw["entitlements_collected"] is False
    assert items[0]["projectIds"] == []
    assert any(e["item"] == "entitlements" for e in data.errors)
    # One recorded gap, not one per project.
    assert len(data.errors) == 1


def test_deployment_counters_split_by_outcome():
    from vcf_automation_assessment_tool.collectors.catalog import _deployment_counters

    total, success, failed, adhoc = _deployment_counters(
        [
            {"catalogItemId": "i1", "status": "CREATE_SUCCESSFUL"},
            {"catalogItemId": "i1", "status": "UPDATE_FAILED"},
            {"catalogItemId": "i1", "status": "CREATE_INPROGRESS"},
            {"catalogItemId": "i2", "status": "UPDATE_SUCCESSFUL"},
            {"catalogItemId": None, "status": "CREATE_SUCCESSFUL"},
        ]
    )
    assert total["i1"] == 3 and success["i1"] == 1 and failed["i1"] == 1
    assert total["i2"] == 1 and success["i2"] == 1 and failed["i2"] == 0
    assert adhoc == 1


class FormListStub:
    """Serves the /form-service/api/forms list route."""

    def __init__(self, forms):
        self.forms = forms

    def iter_paged(self, path, params=None, page_size=None):
        return iter(self.forms)


class FormLookupStub:
    """No list route (404) - forces the per-item fallback, keyed by sourceId."""

    def __init__(self, forms, error=None, list_error=None):
        self.forms = forms
        self.error = error
        self.list_error = list_error or ApiError("HTTP 404", status_code=404)
        self.calls = []

    def iter_paged(self, path, params=None, page_size=None):
        raise self.list_error

    def get(self, path, params=None):
        if self.error:
            raise self.error
        self.calls.append(params or {})
        form = self.forms.get((params or {}).get("sourceId"))
        if form is None:
            raise ApiError("HTTP 404", status_code=404)
        return form


def test_custom_form_from_forms_list():
    # Primary path: one list call mapped by sourceId - the live build 404s
    # per-item lookups even for items whose forms exist.
    from vcf_automation_assessment_tool.collectors.catalog import _fetch_custom_forms

    items = [{"id": "i1"}, {"id": "i2"}, {"id": "i3"}, {"id": "i4"}]
    client = FormListStub(
        [
            {"sourceId": "i1", "type": "requestForm", "status": "ON"},
            {"sourceId": "i3/2", "status": "OFF"},  # versioned source id
            {"sourceId": "i4", "type": "actionForm", "status": "ON"},  # not a request form
        ]
    )
    _fetch_custom_forms(client, AssessmentData(), {"items": items})
    assert items[0]["custom_form"] == "enabled"
    assert items[1]["custom_form"] == ""
    assert items[2]["custom_form"] == "disabled"
    assert items[3]["custom_form"] == ""


def test_custom_form_falls_back_to_per_item_with_source_type():
    from vcf_automation_assessment_tool.collectors.catalog import _fetch_custom_forms

    items = [
        {"id": "i1", "type": "com.vmw.blueprint"},
        {"id": "i2", "type": "com.vmw.vro.workflow"},
    ]
    client = FormLookupStub({"i1": {"status": "ON"}})
    _fetch_custom_forms(client, AssessmentData(), {"items": items})
    assert items[0]["custom_form"] == "enabled"
    assert items[1]["custom_form"] == ""
    # The per-item lookup passes the item type as sourceType.
    assert client.calls[0]["sourceType"] == "com.vmw.blueprint"


def test_custom_form_sweep_aborts_on_403():
    from vcf_automation_assessment_tool.collectors.catalog import _fetch_custom_forms

    items = [{"id": "i1"}, {"id": "i2"}]
    data = AssessmentData()
    _fetch_custom_forms(
        FormLookupStub({}, list_error=ApiError("HTTP 403", status_code=403)),
        data,
        {"items": items},
    )
    assert all(i["custom_form"] == "" for i in items)
    assert len(data.errors) == 1  # one gap, not one per item


def test_empty_entitlements_are_still_evidence():
    # Successful calls returning nothing = genuinely shared with nobody.
    items = [{"id": "i1", "sourceId": "s1", "projectIds": []}]
    data, raw = _setup(items)
    _apply_entitlements(StubClient({}), data, raw)
    assert raw["entitlements_collected"] is True
    assert items[0]["projectIds"] == []
