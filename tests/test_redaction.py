"""The redacted copy: what it must replace, what it must leave alone, and the
audit that refuses to let a report call itself redacted when it is not."""

import pytest

from vcf_automation_assessment_tool.models import (
    AffectedObject,
    AssessmentData,
    Finding,
    Severity,
)
from vcf_automation_assessment_tool.redaction import Redactor


def build(raw=None, derived=None, meta=None, findings=(), errors=()) -> AssessmentData:
    data = AssessmentData()
    data.meta = meta or {}
    data.raw = raw or {}
    data.derived = derived or {}
    data.findings = list(findings)
    data.errors = list(errors)
    return data


def redacted(data: AssessmentData, classes=None, extra=()) -> tuple[AssessmentData, Redactor]:
    redactor = Redactor(classes, extra) if classes else Redactor(extra=extra)
    redactor.learn(data)
    return redactor.redact(data), redactor


def test_one_person_gets_one_alias_in_every_place_they_appear():
    """A name is a table cell in one place and a sentence in another. Two
    aliases for one person makes the report unreadable and the mapping back
    impossible."""
    data = build(
        raw={"deployments": {"deployments": [{"name": "db01", "ownedBy": "a.smith@corp.local"}]}},
        meta={"identity": "a.smith@corp.local"},
        findings=[
            Finding(
                check_id="DEP-001",
                title="Failed deployments",
                severity=Severity.CRITICAL,
                recommendation="Ask a.smith@corp.local why db01 failed.",
                affected=[AffectedObject(kind="deployment", id="d1", name="db01")],
            )
        ],
    )
    out, _ = redacted(data)
    owner = out.raw["deployments"]["deployments"][0]["ownedBy"]
    assert owner != "a.smith@corp.local"
    assert owner == out.meta["identity"]
    assert owner in out.findings[0].recommendation
    assert "a.smith" not in out.findings[0].recommendation


def test_principal_shapes_survive_so_the_identity_source_still_reads():
    """A UPN, a DOMAIN\\user and the project service doubled form each say
    something about where the identity comes from."""
    data = build(
        raw={
            "identity": {
                "groups": [{"principal": "platform-team@corp.local@corp.local", "members": ["bob"]}]
            },
            "governance": {"policies": [{"definition": {"authorities": ["USER:CORP\\a.smith"]}}]},
        }
    )
    out, _ = redacted(data)
    principal = out.raw["identity"]["groups"][0]["principal"]
    local, _, domain = principal.partition("@")
    assert principal == f"{local}@{domain.split('@')[0]}@{domain.split('@')[0]}"
    assert "corp.local" not in principal
    authority = out.raw["governance"]["policies"][0]["definition"]["authorities"][0]
    assert authority.startswith("USER:")
    assert "\\" in authority and "a.smith" not in authority


def test_hosts_keep_their_domain_so_two_systems_still_look_related():
    data = build(
        raw={
            "vro": {
                "endpoints": [
                    {"url": "https://vro01.corp.local:8281/vco"},
                    {"url": "https://vro02.corp.local/vco"},
                    {"url": "https://other.example.net/vco"},
                ]
            }
        }
    )
    out, _ = redacted(data)
    first, second, third = (e["url"] for e in out.raw["vro"]["endpoints"])
    assert "corp.local" not in first + second + third
    assert first.split("/")[2].split(":")[1] == "8281"  # the port is not identifying
    assert first.split(".", 1)[1].split(":")[0] == second.split(".", 1)[1].split("/")[0]
    assert third.split(".", 1)[1] != second.split(".", 1)[1].split("/")[0]


def test_a_host_is_replaced_wherever_it_is_written_not_only_in_urls():
    """Collection gaps and hardcoded-value findings quote bare host names."""
    data = build(
        raw={"infrastructure": {"integrations": [{"url": "https://vro01.corp.local/vco"}]}},
        errors=[{"area": "vro", "item": "workflows", "error": "vro01.corp.local timed out"}],
    )
    out, _ = redacted(data)
    assert "corp.local" not in out.errors[0]["error"]
    assert out.errors[0]["error"].endswith("timed out")


def test_addresses_become_documentation_addresses():
    data = build(
        raw={
            "blueprints": {
                "blueprints": [{"quality": {"ips": ["192.168.10.5", "10.0.0.53", "127.0.0.1"]}}]
            }
        }
    )
    out, _ = redacted(data)
    first, second, loopback = out.raw["blueprints"]["blueprints"][0]["quality"]["ips"]
    assert first.startswith("192.0.2.") and second.startswith("192.0.2.")
    assert first != second
    assert loopback == "127.0.0.1"  # says nothing about anybody


def test_credentials_in_a_url_do_not_survive_in_any_form():
    data = build(raw={"extensibility": {"abx_actions": [{"issues": ["https://svc:hunter2@x.io"]}]}})
    out, _ = redacted(data)
    issue = out.raw["extensibility"]["abx_actions"][0]["issues"][0]
    assert "hunter2" not in issue and "svc" not in issue
    assert issue.startswith("https://redacted@")


def test_an_ordinary_word_used_as_a_tag_does_not_rewrite_the_prose():
    """A tag spelled "no" or "high" is still replaced in its own cell, but the
    report's sentences are not rewritten around it."""
    data = build(
        raw={"infrastructure": {"tags": [{"key": "no", "value": "high"}]}},
        findings=[
            Finding(
                check_id="TAG-003",
                title="Unused tags",
                severity=Severity.INFO,
                recommendation="No template references these, and the risk is high.",
            )
        ],
    )
    out, _ = redacted(data)
    tag = out.raw["infrastructure"]["tags"][0]
    assert tag["key"].startswith("tag") and tag["value"].startswith("tag")
    assert out.findings[0].recommendation == "No template references these, and the risk is high."


def test_a_tag_and_its_halves_are_replaced_together():
    data = build(
        raw={"infrastructure": {"tags": [{"key": "site", "value": "dc1"}]}},
        derived={"capability_tags": {"site:dc1": [{"kind": "cloud-zone", "name": "z"}]}},
        findings=[
            Finding(
                check_id="TAG-001",
                title="t",
                severity=Severity.INFO,
                recommendation="Nothing matches site:dc1 anywhere.",
            )
        ],
    )
    out, _ = redacted(data)
    composite = next(iter(out.derived["capability_tags"]))
    assert composite != "site:dc1"
    assert composite in out.findings[0].recommendation
    assert "dc1" not in out.findings[0].recommendation
    tag = out.raw["infrastructure"]["tags"][0]
    assert (tag["key"], tag["value"]) != ("site", "dc1")


def test_a_document_field_name_is_never_rewritten():
    """A live estate can name a tag anything, including the name of a field
    the code reads. Rewriting keys wholesale renamed "tag" out from under the
    template and broke the render."""
    data = build(
        raw={
            "blueprints": {
                "blueprints": [{"constraint_tags": [{"tag": "no:such:tag", "hard": True}]}]
            }
        }
    )
    out, _ = redacted(data)
    entry = out.raw["blueprints"]["blueprints"][0]["constraint_tags"][0]
    assert set(entry) == {"tag", "hard"}
    assert entry["tag"] != "no:such:tag"


def test_object_names_stay_readable_unless_the_names_class_is_asked_for():
    data = build(raw={"infrastructure": {"projects": [{"id": "p1", "name": "Payments-Prod"}]}})
    kept, _ = redacted(data)
    assert kept.raw["infrastructure"]["projects"][0]["name"] == "Payments-Prod"

    data = build(raw={"infrastructure": {"projects": [{"id": "p1", "name": "Payments-Prod"}]}})
    gone, _ = redacted(data, classes=["names"])
    assert gone.raw["infrastructure"]["projects"][0]["name"].startswith("Project ")


def test_a_name_reference_is_replaced_with_the_same_alias_as_the_object():
    data = build(
        raw={
            "infrastructure": {"projects": [{"id": "p1", "name": "Payments-Prod"}]},
            "deployments": {"deployments": [{"name": "db01", "projectName": "Payments-Prod"}]},
        }
    )
    out, _ = redacted(data, classes=["names"])
    assert (
        out.raw["deployments"]["deployments"][0]["projectName"]
        == out.raw["infrastructure"]["projects"][0]["name"]
    )


def test_ids_are_left_alone_by_default_and_stay_joinable_when_asked_for():
    uuid = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
    data = build(
        raw={"infrastructure": {"projects": [{"id": uuid, "name": "p"}]}},
        derived={"project_names": {uuid: "p"}},
    )
    kept, _ = redacted(data)
    assert kept.derived["project_names"] == {uuid: "p"}

    data = build(
        raw={"infrastructure": {"projects": [{"id": uuid, "name": "p"}]}},
        derived={"project_names": {uuid: "p"}},
    )
    out, _ = redacted(data, classes=["ids"])
    alias = out.raw["infrastructure"]["projects"][0]["id"]
    assert alias != uuid
    # The map is keyed by the id: rewriting one side only would break the
    # lookups the whole report is built on.
    assert list(out.derived["project_names"]) == [alias]


def test_the_findings_themselves_are_untouched():
    """Redaction changes the words, never the assessment. Anything else and a
    redacted report stops being evidence of the same estate."""
    finding = Finding(
        check_id="INF-003",
        title="Unreachable endpoints",
        severity=Severity.CRITICAL,
        recommendation="Fix vc01.corp.local.",
        affected=[
            AffectedObject(kind="cloud-account", id="ca1", name="vc01", project="Payments"),
            AffectedObject(kind="cloud-account", id="ca2", name="vc02"),
        ],
    )
    out, _ = redacted(build(findings=[finding]))
    assert len(out.findings) == 1
    assert out.findings[0].check_id == "INF-003"
    assert out.findings[0].severity is Severity.CRITICAL
    assert out.findings[0].count == 2
    assert [a.kind for a in out.findings[0].affected] == ["cloud-account"] * 2


def test_configured_strings_are_replaced_inside_longer_words():
    """The classes cannot know a company name buried in an identifier, which
    is exactly what this option exists for."""
    data = build(raw={"catalog": {"items": [{"name": "acmecorp-build-vm"}]}})
    out, redactor = redacted(data, extra=["acmecorp"])
    assert "acmecorp" not in out.raw["catalog"]["items"][0]["name"]
    assert out.raw["catalog"]["items"][0]["name"].endswith("-build-vm")
    assert any(row[0] == "extra" for row in redactor.key_rows())


def test_the_audit_reports_a_value_that_survived():
    data = build(raw={"deployments": {"deployments": [{"ownedBy": "a.smith@corp.local"}]}})
    _, redactor = redacted(data)
    assert redactor.audit("<p>clean</p>") == []
    # One row per leaked stretch of text, named by the longest value that
    # covers it: reporting a.smith and corp.local underneath it would be three
    # lines about one mistake.
    assert [h["value"] for h in redactor.audit("<p>owner: a.smith@corp.local</p>")] == [
        "a.smith@corp.local"
    ]
    # A half leaking on its own is still a leak, and still reported.
    assert [h["value"] for h in redactor.audit("<p>host: corp.local</p>")] == ["corp.local"]


def test_the_audit_ignores_the_vendored_script_and_the_template_prose():
    data = build(raw={"infrastructure": {"tags": [{"key": "site", "value": "primary"}]}})
    _, redactor = redacted(data)
    # A word inside the inlined mermaid build is not this estate's tag.
    assert redactor.audit("<script>var primary = 1;</script>") == []
    # Nor is a word the report prints whatever the estate holds.
    assert redactor.audit("<p>primary</p>", allowed="the primary owner") == []
    assert redactor.audit("<p>primary</p>") != []


def test_an_alias_is_never_minted_over_a_real_value():
    """Estates contain surprises. If an alias collided with something real,
    two different objects would read as one."""
    data = build(
        raw={
            "infrastructure": {
                "tags": [{"key": "tag01", "value": "one"}, {"key": "alpha", "value": "two"}]
            }
        }
    )
    out, _ = redacted(data)
    aliases = [t["key"] for t in out.raw["infrastructure"]["tags"]]
    assert len(set(aliases)) == 2
    assert "tag01" not in aliases[1:]


@pytest.mark.parametrize("classes", [None, ["identity", "hosts", "tags", "names", "ids"]])
def test_the_whole_sample_report_renders_clean(sample_data, classes):
    from vcf_automation_assessment_tool.access import build_catalog_access
    from vcf_automation_assessment_tool.capability_map import build_capability_map
    from vcf_automation_assessment_tool.checks import run_checks
    from vcf_automation_assessment_tool.flows import build_flows
    from vcf_automation_assessment_tool.redaction import _visible_text
    from vcf_automation_assessment_tool.report.renderer import build_html, template_source

    build_flows(sample_data)
    build_capability_map(sample_data)
    build_catalog_access(sample_data)
    run_checks(sample_data)

    redactor = Redactor(classes) if classes else Redactor()
    redactor.learn(sample_data)
    copy = redactor.redact(sample_data)
    copy.meta["redaction"] = redactor.summary()
    html = build_html(copy)

    assert redactor.audit(html, allowed=template_source()) == []
    # Spot-check the classes that are on in both runs, in the rendered page
    # rather than the data: the report is what leaves the organisation. The
    # fixture's env:prod is not in this list because the template prints it as
    # its own worked example, where it stands for nobody's estate.
    # Against the readable text, not the file: the vendored mermaid build has
    # an "aliceblue" in its colour table and no bearing on this estate.
    readable = _visible_text(html)
    for gone in ("sample-admin", "vra.example.test", "192.168.10.5", "site:dc1", "alice"):
        assert gone not in readable, gone
    assert "env:prod" not in str(copy.derived["capability_tags"])
    assert "Redacted copy." in html
    # The assessment underneath is the same one.
    assert len(copy.findings) == len(sample_data.findings)
    assert [f.check_id for f in copy.findings] == [f.check_id for f in sample_data.findings]


def test_the_cli_writes_both_files_and_the_key_when_asked(sample_data, tmp_path, capsys):
    from vcf_automation_assessment_tool.checks import run_checks
    from vcf_automation_assessment_tool.cli import _write_redacted
    from vcf_automation_assessment_tool.config import RunConfig

    run_checks(sample_data)
    cfg = RunConfig()
    cfg.redact = True
    cfg.redact_key = str(tmp_path / "key.csv")
    out = tmp_path / "redacted.html"

    assert _write_redacted(sample_data, cfg, str(out)) is True
    assert "sample-admin" not in out.read_text(encoding="utf-8")
    key = (tmp_path / "key.csv").read_text(encoding="utf-8")
    assert key.startswith("class,alias,real value")
    assert "sample-admin" in key  # the mapping is the one place it survives
    printed = capsys.readouterr().out
    assert "redacted report written" in printed
    assert "as sensitive as the estate" in printed


def test_the_cli_refuses_to_write_a_report_that_leaked(sample_data, tmp_path, capsys):
    """The audit is the whole safety net. If it fires, nothing is written -
    an operator must not be able to send a file the tool knew was dirty."""
    import vcf_automation_assessment_tool.cli as cli
    from vcf_automation_assessment_tool.checks import run_checks
    from vcf_automation_assessment_tool.config import RunConfig

    run_checks(sample_data)
    cfg = RunConfig()
    cfg.redact = True
    out = tmp_path / "redacted.html"
    # A renderer that forgets to use the redacted copy is exactly the bug the
    # audit exists to catch.
    monkey = cli.build_html
    try:
        cli.build_html = lambda data: "<p>owner: sample-admin</p>"
        assert cli._write_redacted(sample_data, cfg, str(out)) is False
    finally:
        cli.build_html = monkey
    assert not out.exists()
    err = capsys.readouterr().err
    assert "was NOT written" in err and "sample-admin" in err


def test_a_value_spelled_like_an_alias_is_replaced_and_still_audited():
    """host01 is this scheme's own alias format and an entirely ordinary host
    name. Refusing to alias the estate's own host01 left it in the report and
    hid it from the audit at the same time - two owners read as one person and
    nothing complained."""
    data = build(
        raw={
            "deployments": {
                "deployments": [
                    {"ownedBy": "alice"},  # takes person01
                    {"ownedBy": "person01"},  # the estate's own person01
                ]
            }
        }
    )
    out, redactor = redacted(data)
    first, second = (d["ownedBy"] for d in out.raw["deployments"]["deployments"])
    assert first != second, "two people must not share an alias"
    assert second != "person01", "the colliding value must still be replaced"
    # And it is in the audit's sights, which is what makes a miss loud.
    assert "person01" in [row[2] for row in redactor.key_rows()]
    assert [h["value"] for h in redactor.audit("<p>person01</p>")] == ["person01"]


def test_an_alias_is_never_minted_over_the_value_being_registered():
    """The value being aliased is not in the map yet, so the counter can walk
    straight onto it and map person02 to itself."""
    data = build(
        raw={"deployments": {"deployments": [{"ownedBy": "person02"}, {"ownedBy": "alice"}]}}
    )
    out, _ = redacted(data)
    aliases = [d["ownedBy"] for d in out.raw["deployments"]["deployments"]]
    assert "person02" not in aliases
    assert len(set(aliases)) == 2


def test_a_placeholder_identity_is_not_given_a_persons_name():
    """ "(refresh token)" is the tool saying nobody was named. An alias there
    puts a person in the header where the report means to say there is none."""
    data = build(
        meta={"identity": "(refresh token)"},
        raw={"deployments": {"deployments": [{"ownedBy": "(unknown)"}]}},
    )
    out, _ = redacted(data)
    assert out.meta["identity"] == "(refresh token)"
    assert out.raw["deployments"]["deployments"][0]["ownedBy"] == "(unknown)"


def test_the_audit_scans_a_map_larger_than_one_chunk():
    """The residue scan compiles one pattern per chunk of values. A map that
    fits in a single chunk would never exercise the boundary."""
    from vcf_automation_assessment_tool.redaction import _CHUNK

    owners = [{"ownedBy": f"user{i:05d}@corp.local"} for i in range(_CHUNK + 50)]
    data = build(raw={"deployments": {"deployments": owners}})
    out, redactor = redacted(data)
    assert all("corp.local" not in d["ownedBy"] for d in out.raw["deployments"]["deployments"])
    # One value from each side of the chunk boundary, plus one that is clean.
    hits = redactor.audit("<p>user00003@corp.local and user00540@corp.local</p>")
    assert {"user00003@corp.local", "user00540@corp.local"} <= {h["value"] for h in hits}
    assert redactor.audit("<p>nothing to see</p>") == []


def test_the_default_redacted_path_carries_no_host_name():
    """The report is named after the appliance; its shareable twin must not
    be, or the file name gives away what the contents were cleaned of."""
    from vcf_automation_assessment_tool.cli import _redacted_path
    from vcf_automation_assessment_tool.config import RunConfig

    cfg = RunConfig()
    cfg.redact = True
    path = _redacted_path(
        "reports/report-vra01.corp.local-20260821-1530.html", "20260821-1530", cfg
    )
    assert "corp.local" not in path
    assert path.replace("\\", "/") == (
        "reports/vcf-automation-assessment-report-redacted-20260821-1530.html"
    )

    cfg.redact_output = "somewhere/else.html"
    assert _redacted_path("reports/r.html", "20260821-1530", cfg) == "somewhere/else.html"


def test_a_word_the_report_writes_itself_is_replaced_only_where_it_stands_alone():
    """A live run failed here. The assessment account was called
    "administrator", so every project role label on the page - which the
    renderer works out from its own vocabulary, after redaction has run -
    read as a leaked identity and the audit refused to write the file."""
    out, redactor = redacted(build(meta={"identity": "administrator"}))
    assert out.meta["identity"] == "person01"
    sentence = "The project administrator approves the request."
    assert redactor.text(sentence) == sentence
    assert redactor.audit("<td>administrator</td><td>member</td>") == []


def test_every_project_role_the_report_can_print_is_its_own_vocabulary():
    """The renderer names an owner's role from identity_map. A role word
    added there and not here is the same failure again, silently."""
    from vcf_automation_assessment_tool.identity_map import PROJECT_ROLES
    from vcf_automation_assessment_tool.redaction import REPORT_WORDS

    assert {word for _field, word in PROJECT_ROLES} <= REPORT_WORDS


def test_a_policy_audience_named_by_role_is_not_a_person():
    """USER: and GROUP: name somebody. ROLE: names a kind of access every
    estate has alike, so aliasing it renames a concept rather than hiding
    anyone - and gives the report's own role labels a person's alias."""
    data = build(
        raw={
            "governance": {
                "policies": [
                    {
                        "definition": {
                            "allowedActions": [
                                {
                                    "actions": ["Deployment.Delete"],
                                    "authorities": ["ROLE:administrator", "USER:jane@corp.local"],
                                }
                            ]
                        }
                    }
                ]
            }
        }
    )
    out, _ = redacted(data)
    granted = out.raw["governance"]["policies"][0]["definition"]["allowedActions"][0]
    role, user = granted["authorities"]
    assert role == "ROLE:administrator"
    assert user.startswith("USER:person") and "jane" not in user


def test_addresses_continue_past_the_documentation_blocks(caplog):
    """A fabric inventory passes 762 addresses on its own. Every address after
    that used to collapse onto one alias, so two machines read as one host,
    and each one logged a warning of its own over the run's output.

    Running out of documentation addresses is not a fault and there is nothing
    to do about it, so it is said once and it is not a warning: an operator
    who reads WARNING as "look into this" would find nothing to look at.
    """
    import logging

    redactor = Redactor()
    with caplog.at_level(logging.INFO, logger="vcf_automation_assessment_tool.redaction"):
        aliases = [
            redactor.ip_alias(f"10.{a}.{b}.{c}")
            for a in range(4)
            for b in range(16)
            for c in range(1, 20)
        ]
    assert len(set(aliases)) == len(aliases)
    assert aliases[761] == "203.0.113.254"
    assert aliases[762].startswith("198.18.")
    said = [r for r in caplog.records if "198.18.0.0/15" in r.getMessage()]
    assert len(said) == 1
    assert said[0].levelno == logging.INFO


def test_a_request_time_value_survives_redaction_as_the_same_claim():
    """The placement diagram reads the tags a request-time constraint chooses
    between out of the expression itself. Redaction rewrites that expression,
    so the values have to come back rewritten the same way the tag map is, or
    the shareable copy prints a real tag beside a dead end it does not have.
    """
    from vcf_automation_assessment_tool.placement import template_placements

    def placement(data):
        (drawn,) = template_placements(data)[0]
        return [
            (o["tag"], o["state"])
            for res in drawn["resources"]
            for c in res["constraints"]
            for o in c["options"]
        ]

    def estate():
        return build(
            raw={
                "infrastructure": {"zones": [], "cloud_accounts": []},
                "blueprints": {
                    "blueprints": [
                        {
                            "id": "bp1",
                            "name": "web-server",
                            "constraint_tags": [
                                {
                                    "tag": '${input.env == "qa" ? "env:qa" : "env:nowhere"}',
                                    "hard": True,
                                    "negated": False,
                                    "dynamic": True,
                                    "resource": "vm1",
                                    "resource_type": "Cloud.vSphere.Machine",
                                    "context": "resource",
                                },
                                # The same two values reached the other way:
                                # the constraint names one input, and the
                                # platform declares what that input can be.
                                {
                                    "tag": "${input.environment}",
                                    "hard": True,
                                    "negated": False,
                                    "dynamic": True,
                                    "resource": "vm1",
                                    "resource_type": "Cloud.vSphere.Machine",
                                    "context": "resource",
                                },
                                # Drawn for this one; the request-time
                                # constraints are what the assertions are about.
                                {
                                    "tag": "no:such:tag",
                                    "hard": True,
                                    "negated": False,
                                    "dynamic": False,
                                    "resource": "vm1",
                                    "resource_type": "Cloud.vSphere.Machine",
                                    "context": "resource",
                                },
                            ],
                            "inputs": [
                                {
                                    "name": "environment",
                                    "type": "string",
                                    "title": "Environment",
                                    "values": ["env:qa", "env:nowhere"],
                                    "default": "env:qa",
                                    "source": "",
                                    "kind": "declared",
                                }
                            ],
                        }
                    ]
                },
            },
            derived={
                "capability_tags": {
                    "env:qa": [
                        {
                            "kind": "cloud-zone",
                            "id": "z1",
                            "name": "qa-zone",
                            "via": "capability tag",
                        }
                    ]
                }
            },
        )

    real = placement(estate())
    assert real == [
        ("env:qa", "single"),
        ("env:nowhere", "unsatisfied"),
        ("env:qa", "single"),
        ("env:nowhere", "unsatisfied"),
    ]

    out, _ = redacted(estate())
    aliased = placement(out)
    assert [state for _, state in aliased] == [state for _, state in real]
    # Every value, from the expression and from the input alike. One left
    # alone names a real tag beside a renamed estate.
    assert all(alias != tag for (alias, _), (tag, _) in zip(aliased, real, strict=True))
    # The alias the map uses, not one assembled from pieces of it.
    assert aliased[0][0] in out.derived["capability_tags"]
    # The two routes to the same tag agree, or the diagram shows one estate
    # tag under two names.
    assert aliased[0][0] == aliased[2][0] and aliased[1][0] == aliased[3][0]


def test_an_input_value_that_is_a_capability_tag_is_rewritten_with_it():
    """What a template input can be is kept as plain strings, and those
    strings are tags: the placement diagram prints them beside the constraint
    that reads the input. A value left alone would name a real tag beside a
    map that no longer spells it that way."""
    data = build(
        raw={
            "blueprints": {
                "blueprints": [
                    {
                        "id": "bp1",
                        "name": "web-server",
                        "constraint_tags": [],
                        "inputs": [
                            {
                                "name": "environment",
                                "type": "string",
                                "title": "Environment",
                                "values": ["env:qa", "env:prod"],
                                "default": "env:qa",
                                "source": "",
                                "kind": "declared",
                            }
                        ],
                    }
                ]
            }
        },
        derived={
            "capability_tags": {
                "env:qa": [{"kind": "cloud-zone", "id": "z1", "name": "qa-zone"}],
                "env:prod": [{"kind": "cloud-zone", "id": "z2", "name": "prod-zone"}],
            }
        },
    )
    out, _ = redacted(data)
    values = out.raw["blueprints"]["blueprints"][0]["inputs"][0]["values"]
    assert "env:qa" not in values and "env:prod" not in values
    # The aliases the map itself uses, so the two still line up.
    assert set(values) <= set(out.derived["capability_tags"])
    assert out.raw["blueprints"]["blueprints"][0]["inputs"][0]["default"] == values[0]
