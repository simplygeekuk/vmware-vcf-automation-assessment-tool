"""Blueprints (cloud templates) collector: list + per-blueprint YAML content
with constraint-tag extraction, plus the other design-time content that
renders alongside templates: property groups, custom resource types and
custom resource actions."""

from __future__ import annotations

import logging

from .. import codequality
from ..client import ApiClient, ApiError
from ..models import SECRET_REF_RE, AssessmentData
from ..tagutil import (
    BlueprintParseError,
    extract_constraint_tags,
    input_references,
    read_input_schema,
)

log = logging.getLogger(__name__)

AREA = "blueprints"


def collect(client: ApiClient, data: AssessmentData) -> None:
    raw: dict = {"blueprints": _collect_blueprints(client, data)}
    # Design-time content that renders with the templates; a failed template
    # listing must not cost these independent fetches.
    for key, path in (
        ("property_groups", "/properties/api/property-groups"),
        ("custom_resource_types", "/form-service/api/custom/resource-types"),
        ("custom_resource_actions", "/form-service/api/custom/resource-actions"),
    ):
        try:
            raw[key] = list(client.iter_paged(path))
            log.info("%s: %d %s", AREA, len(raw[key]), key)
        except ApiError as exc:
            log.warning("%s: %s unavailable: %s", AREA, key, exc)
            data.record_error(AREA, key, str(exc))
            raw[key] = []
    data.raw[AREA] = raw


def _collect_blueprints(client: ApiClient, data: AssessmentData) -> list[dict]:
    blueprints: list[dict] = []
    try:
        listing = list(client.iter_paged("/blueprint/api/blueprints"))
    except ApiError as exc:
        log.error("%s: collection failed: %s", AREA, exc)
        data.record_error(AREA, "blueprints", str(exc))
        return []

    log.info("%s: %d blueprints, fetching YAML content...", AREA, len(listing))
    # Whether this build answers for inputs schemas at all, decided by the
    # first template that needs one.
    schema = {"available": True, "asked": False}
    for i, bp in enumerate(listing, 1):
        entry = {
            "id": bp.get("id", ""),
            "name": bp.get("name", ""),
            "projectId": bp.get("projectId", ""),
            "projectName": bp.get("projectName", ""),
            "status": bp.get("status", ""),
            "valid": bp.get("valid", True),
            "validationMessages": bp.get("validationMessages") or [],
            "totalVersions": bp.get("totalVersions", 0),
            "totalReleasedVersions": bp.get("totalReleasedVersions", 0),
            "contentSourceId": bp.get("contentSourceId"),
            "constraint_tags": [],
            "parse_error": None,
            # None = unknown (detail unfetched or YAML unreadable), a list =
            # what the parsed template defines. Flows treats None as "may
            # fire" (conditional edge) and [] as proof a resource topic
            # cannot; conflating them turned one failed GET into a confident
            # exclusion.
            "resource_types": None,
            "quality": None,
            # Names read through ${secret.<name>}; None until the content
            # was fetched, [] once it was and names nothing.
            "secret_refs": None,
            # None = not asked, or asked and unreadable. A list = what the
            # platform says the inputs a constraint reads can be. Only those
            # inputs are kept: one no constraint mentions cannot move a
            # resource, and free-text business fields have no business here.
            "inputs": None,
        }
        try:
            detail = client.get(f"/blueprint/api/blueprints/{entry['id']}")
            content = detail.get("content", "")
            entry["valid"] = detail.get("valid", entry["valid"])
            entry["validationMessages"] = (
                detail.get("validationMessages") or entry["validationMessages"]
            )
            entry["quality"] = _quality_scan(content)
            entry["secret_refs"] = secret_refs(content)
            try:
                tags = extract_constraint_tags(content)
                entry["constraint_tags"] = [vars(t) for t in tags]
                entry["resource_types"] = _resource_types(content)
            except BlueprintParseError as exc:
                entry["parse_error"] = str(exc)[:300]
        except ApiError as exc:
            log.warning("%s: detail fetch for %s failed: %s", AREA, entry["name"], exc)
            data.record_error(AREA, f"blueprint:{entry['name']}", str(exc))
        _collect_inputs(client, data, entry, schema)
        blueprints.append(entry)
        if i % 25 == 0:
            log.info("%s: %d/%d blueprints processed", AREA, i, len(listing))

    return blueprints


def _collect_inputs(client: ApiClient, data: AssessmentData, entry: dict, state: dict) -> None:
    """Read the resolved schema for the inputs this template's constraints use.

    A constraint written as ${input.environment} decides where a resource
    goes, and the values that input offers are in the schema the request form
    is built from. Nothing else in the schema is kept.

    A build that does not answer for the route at all is asked once. Anything
    else is recorded per template and the sweep carries on, so one bad
    template does not cost the rest.
    """
    wanted = input_references(entry["constraint_tags"])
    if not wanted or not state["available"]:
        return
    try:
        schema = client.get(f"/blueprint/api/blueprints/{entry['id']}/inputs-schema")
    except ApiError as exc:
        first = not state["asked"]
        state["asked"] = True
        if exc.status_code in (401, 403) or (first and exc.status_code == 404):
            # Absent or refused for every template, so asking 39 more times
            # buys 39 more copies of the same gap.
            state["available"] = False
            data.record_error(
                AREA,
                "blueprint-inputs",
                f"{exc} - what a request-time constraint can resolve to is unknown",
            )
            return
        log.warning("%s: inputs schema for %s failed: %s", AREA, entry["name"], exc)
        data.record_error(AREA, f"blueprint-inputs:{entry['name']}", str(exc))
        return
    state["asked"] = True
    if not isinstance(schema, dict):
        return
    entry["inputs"] = [vars(i) for i in read_input_schema(schema, wanted)]


def _resource_types(content: str) -> list[str] | None:
    """Resource types the template defines, or None when that is unknowable.

    Only a document with a real resources mapping yields a list (possibly
    empty - a template genuinely defining nothing). Unparseable YAML, a
    non-mapping document, or a missing/odd resources key all return None:
    "could not read" must stay distinguishable from "defines none".
    """
    import yaml

    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("resources"), dict):
        return None
    return sorted(
        {
            str(r.get("type", ""))
            for r in doc["resources"].values()
            if isinstance(r, dict) and r.get("type")
        }
    )


def secret_refs(content: str) -> list[str]:
    """Names a template reads as ${secret.<name>}; the value never appears in YAML."""
    return sorted(set(SECRET_REF_RE.findall(content or "")))


def _quality_scan(content: str) -> dict:
    """Replatforming-relevant signals from the template YAML: hardcoded
    values, inline cloud-init payloads, and input surface."""
    import yaml

    literals = codequality.scan_literals(content)
    # URLs in YAML comments are documentation pointers, not environment
    # coupling - rescan for URLs with comment lines stripped. Credentials
    # and IPs keep the full-text scan: a secret in a comment still leaks.
    stripped = "\n".join(line for line in content.splitlines() if not line.lstrip().startswith("#"))
    literals["urls"] = codequality.scan_literals(stripped)["urls"]
    quality = {
        **literals,
        "inputs": 0,
        "cloud_config_blocks": 0,
        "cloud_config_lines": 0,
    }
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return quality
    if not isinstance(doc, dict):
        return quality
    inputs = doc.get("inputs")
    if isinstance(inputs, dict):
        quality["inputs"] = len(inputs)

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("cloudConfig", "cloud_config") and isinstance(value, str):
                    quality["cloud_config_blocks"] += 1
                    quality["cloud_config_lines"] += len(value.splitlines())
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(doc.get("resources"))
    return quality
