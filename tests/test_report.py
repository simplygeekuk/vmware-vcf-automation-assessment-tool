"""Render the full sample report; assert structure and write it for inspection."""

import re

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.flows import build_flows
from vcf_automation_assessment_tool.report.renderer import render_report


def test_render_full_report(sample_data, tmp_path):
    from vcf_automation_assessment_tool.access import build_catalog_access
    from vcf_automation_assessment_tool.capability_map import build_capability_map

    build_flows(sample_data)
    build_capability_map(sample_data)
    build_catalog_access(sample_data)
    run_checks(sample_data)
    out = tmp_path / "report.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    assert "<!doctype html>" in html.lower()
    # Executive summary and anchors
    assert "Summary" in html
    assert 'id="DEP-001"' in html and 'href="#DEP-001"' in html
    # Inventory sections
    assert "prod-zone" in html and "Web Server" in html and "web-server" in html
    # Integrations table lives in the Infrastructure section
    assert "vro-embedded" in html
    assert html.index("Integrations") < html.index("<h4>Capability Tags</h4>")
    # Cloud accounts table: status (only rendered because the fixture accounts
    # expose one) and capability tags per endpoint. The integrations table has
    # no status column - no fixture integration reports one.
    assert "<td>FAILED</td>" in html
    assert "<td>env:prod, site:dc1</td>" in html
    accounts_table = html[html.index("<summary>Cloud Accounts ") :]
    accounts_table = accounts_table[: accounts_table.index("</details>")]
    assert "<th>Status</th>" in accounts_table
    assert "<th>Capability tags</th>" in accounts_table
    integrations_table = html[html.index("<summary>Integrations ") :]
    integrations_table = integrations_table[: integrations_table.index("</details>")]
    assert "<th>Status</th>" not in integrations_table
    assert "<th>Capability tags</th>" in integrations_table
    # Profiles and mappings each have their own collapsible section
    for summary in ("Network Profiles", "Storage Profiles", "Flavor Mappings", "Image Mappings"):
        assert f"<summary>{summary} " in html, summary
    # The tag table's consumers column is the tag usage matrix, with the
    # honesty wording for unconsumed tags.
    assert "<summary>Tag Assignments and Consumers " in html
    assert "<th>Consumed by</th>" in html
    assert "no visible constraint" in html
    # Flavor/image rows carry their region (profile names are optional in the
    # API - account/region is what tells identically-named rows apart), with
    # the profile's own externalRegionId as fallback when the region is not
    # in the collected list
    assert "vc-prod / Datacenter:dc-1" in html
    assert "(unnamed profile)" in html and "northeurope" in html
    # Every major heading carries a plain-language explanation (the report is
    # read by non-engineers) - spot-check one per section
    for lead in (
        "Severity describes the concern",
        "The parts everything else is built on",
        "labels that decide where a machine is built",
        "The building blocks people order from",
        "specific to this organisation",
        "A subscription is a rule",
        "What people actually use",
        "Every item people can order",
        # Not "grouped\nby state": coupling to template line wrapping means a
        # prose reflow breaks the suite with no behavior change.
        "grouped",
        "Policies are the platform's rules",
    ):
        assert lead in html, lead

    # Platform version in the meta grid (from the embedded vRO /about)
    assert "Platform version<b>8.14.1.33234</b>" in html

    # Estate-at-a-glance strip: plain size numbers ahead of the findings, in a
    # panel of their own so they read as one instrument rather than loose chips
    assert "This environment at a glance" in html
    assert html.index('<section class="estate">') < html.index("Projects</span>")
    assert '<div class="g"><b>2</b><span>Projects</span></div>' in html
    assert '<div class="g"><b>8</b><span>Deployments</span></div>' in html
    assert '<div class="g"><b>8</b><span>Policies</span></div>' in html

    # Every major section is a collapsible chapter, expanded on load, with
    # the h2 kept inside the summary so the outline and #anchors survive
    for key, title in [
        ("summary", "Summary"),
        ("infrastructure", "Infrastructure"),
        ("design", "Design and Templates"),
        ("extensibility", "Extensibility"),
        ("consumption", "Consumption"),
        ("governance", "Policies and Governance"),
        ("replatforming", "Replatforming"),
    ]:
        assert f'<details class="sec" id="{key}" open>' in html, key
        assert f"<summary><h2>{title}</h2></summary>" in html, key
    # An anchor into a collapsed chapter opens it before scrolling
    assert "function revealTarget(hash)" in html

    # Each chapter splits into an Inventory rail then a Findings rail, and
    # the Findings rail carries that chapter's own severity tally
    section_ids = [
        "infrastructure",
        "consumption",
        "governance",
        "design",
        "extensibility",
        "replatforming",
    ]
    # The fixture has no collection gaps, so the footer closes the last chapter
    bounds = [html.index(f'id="{key}"') for key in section_ids] + [html.index("<footer>")]
    for key, start, end in zip(section_ids, bounds[:-1], bounds[1:], strict=True):
        chapter = html[start:end]
        assert '<h3 class="subhead">Inventory</h3>' in chapter, key
        assert '<h3 class="subhead">Findings <span class="count">' in chapter, key
        assert chapter.index("Inventory</h3>") < chapter.index("Findings <span"), key
    # Content headings sit under the rails, one level down
    assert "<h4>Subscriptions</h4>" in html
    # Capability tags live inside Infrastructure, so the INF/PRJ and TAG
    # findings share one rail and one tally
    infra = html[html.index('id="infrastructure"') : html.index('id="consumption"')]
    assert "<h4>Capability Tags</h4>" in infra
    assert 'id="TAG-001"' in infra
    assert (
        '<h3 class="subhead">Findings <span class="count">15 total &middot; '
        "2 critical &middot; 8 warning &middot; 5 info</span></h3>" in infra
    )
    # Project quotas render beside the projects that hold them, and the cell
    # says how full each one is rather than printing two bare numbers
    assert "Project Zone Allocation" in infra
    assert "<td>Platform</td><td>prod-zone</td>" in infra
    assert "4 / 4 (full)" in infra and "12,288 / 16,384 MB (75%)" in infra
    assert 'id="PRJ-004"' in infra

    # Section navigation pills at the top, one per major section
    assert '<nav class="toc">' in html
    assert '<a href="#consumption">Consumption</a>' in html
    assert '<a href="#replatforming">Replatforming</a>' in html

    # Top-level section order per the agreed layout
    order = section_ids
    at = {key: html.index(f'id="{key}"') for key in order}
    positions = [at[key] for key in order]
    assert positions == sorted(positions)
    ends = dict(zip(order, order[1:] + ["system-or-footer"], strict=True))
    end_at = {k: at.get(v, html.index("<footer>")) for k, v in ends.items()}
    # Design and Templates holds templates, property groups and REP-002;
    # Extensibility holds subscriptions, ABX inventory and EXT-003
    assert at["design"] < html.index('id="REP-002"') < end_at["design"]
    assert at["extensibility"] < html.index('id="EXT-003"') < end_at["extensibility"]
    assert at["design"] < html.index("common-props") < end_at["design"]
    assert at["extensibility"] < html.index("ABX Actions Inventory") < end_at["extensibility"]
    # ABX run evidence: Last run column from the retained history, honest
    # "none recorded" for the never-run actions, EXT-006 listing them
    assert "<th>Last run</th>" in html
    # NBSP joins date and state so the cell never wraps mid-label
    assert "2026-07-16 (COMPLETED)" in html
    assert "none recorded" in html
    # The oldest retained record dates the floor of the window, in both the
    # inventory note and the EXT-006 recommendation - bolded so it stands out
    assert html.count("oldest record still held is from") == 2
    assert html.count("<strong>2025-07-01</strong>") == 2
    assert at["extensibility"] < html.index('id="EXT-006"') < end_at["extensibility"]
    # vRO workflows table in Extensibility: resolved names plus a visible
    # marker for references that could not be resolved
    assert (
        at["extensibility"]
        < html.index("Referenced Orchestrator Workflows")
        < end_at["extensibility"]
    )
    assert "1 resolved of 2" in html
    assert "Active Directory - Add Computer" in html
    assert "not found on any Orchestrator this report could reach" in html
    # Workflow complexity columns and the HIGH flag with interaction marker
    assert "<th>Complexity</th>" in html
    assert "HIGH (user interaction)" in html
    # vRO actions table with builtin-exclusion note and runtime breakdown
    # (the plain string also appears as VRO-001's title in the exec summary,
    # so anchor on the collapsible's summary element)
    assert (
        at["extensibility"] < html.index("<summary>Orchestrator Actions ") < end_at["extensibility"]
    )
    # Error handling surfaces as a metric column, not a finding
    assert "<th>Error handling</th>" in html
    assert "no error handling" not in html
    assert "com.simplygeek.dns/legacySetRecord" in html
    assert "(240 skipped)" in html and "1 javascript, 1 python" in html
    # Policies grouped by type with their own sub-sections
    assert "<summary>Lease Policies " in html
    assert "<summary>Approval Policies " in html
    # Content sharing policies get their own table with the shared content
    # resolved to names (the UI calls them Content Sharing, not Entitlement)
    assert "<summary>Content Sharing Policies " in html
    assert "share-platform-catalog" in html
    assert "item: Web Server" in html
    assert "Entitlement policies" not in html
    # Scope column: org-scoped policies say so, project-scoped resolve the name
    assert "<td>organization</td>" in html
    assert "platform-lease" in html
    # POL-001 (per-project policy copies) renders in Policies and Governance
    assert at["governance"] < html.index('id="POL-001"') < end_at["governance"]
    # Subscriptions and flow diagrams
    assert "add-to-cmdb" in html
    assert "flowchart LR" in html
    # The subscriptions table bounds its name/runnable columns so the
    # criteria column stays inside the viewport instead of scrolling away
    assert '<table class="subs">' in html
    # Criteria render in full (the 80-char truncation is gone) with the
    # pinned blueprint id resolved on a line beneath; EXT-005 details the
    # portability risk in the Extensibility section
    assert "event.data.blueprintId == &#39;bp-gone&#39;" in html
    assert "(unknown blueprint bp-gone)" in html
    assert at["extensibility"] < html.index('id="EXT-005"') < end_at["extensibility"]
    # The flow diagrams read under Consumption > Catalog, next to the items
    # they are about, not in Extensibility with the subscriptions that drive
    # them. The list is one collapsible with the count visible; every fixture
    # item has a reacting subscription, so the silent-items table stays
    # absent, and diagram summaries sort by item name.
    # The placement diagrams read under Design, beneath the templates table
    # they are about. Only web-server qualifies: the other fixture templates
    # declare no constraints at all, and the note says so rather than leaving
    # a reader wondering where they went.
    assert at["design"] < html.index("<h4>Template Placement</h4>") < end_at["design"]
    assert html.index("Cloud Templates (Blueprints)") < html.index("<h4>Template Placement</h4>")
    assert 'Placement Diagrams <span class="count">(1 template)' in html
    assert "declare no constraint tags at all" in html
    assert "only one place matches" in html  # site:dc1 lives on one cloud account
    assert at["consumption"] < html.index("<h4>Catalog Flow Diagrams</h4>") < end_at["consumption"]
    assert html.index("<h4>Catalog</h4>") < html.index("<h4>Catalog Flow Diagrams</h4>")
    # One section per part of a deployment's life, in life order, each
    # counting the items that have something attached in that part.
    assert 'Provisioning Flows <span class="count">(3 items)' in html
    assert 'Day 2 Change Flows <span class="count">(3 items)' in html
    assert 'Disposal Flows <span class="count">(2 items)' in html
    assert (
        html.index("<summary>Provisioning Flows")
        < html.index("<summary>Day 2 Change Flows")
        < html.index("<summary>Disposal Flows")
    )
    # A request event goes with the build unless its conditions name another
    # kind of request, so no section is left holding every item twice.
    assert "Unplaced Request Flows" not in html
    assert "also fire when somebody changes a deployment or takes it away" in html
    assert "Items No Subscription Reacts To" not in html
    # Items sort by name inside a section. Day 2 is the one every item has.
    day2 = html[html.index("<summary>Day 2 Change Flows") :]
    day2 = day2[: day2.index("<summary>Disposal Flows")]
    assert (
        day2.index("<summary>Reset VM Password")
        < day2.index("<summary>Unused Item")
        < day2.index("<summary>Web Server")
    )
    # A criteria-less subscription renders an empty cell, not an empty pill
    assert "<code></code>" not in html
    # CSV export ships with every report: the script that grows an
    # "Export CSV" button on each data table at load, plus the print rule
    # hiding the buttons on paper. The download itself is a client-side Blob
    # URL, so presence of the machinery is what a static render can prove.
    assert "function csvFromTable" in html
    assert "Export CSV" in html
    assert "@media print { .csvbtn { display: none; } }" in html
    # No external requests: no script/style tags pointing at remote hosts
    # (mermaid's minified body legitimately contains strings like '@import',
    # so only tag attributes are asserted on).
    assert '<script src="http' not in html
    assert '<link rel="stylesheet" href="http' not in html
    assert "https://cdn." not in html
    # Findings badges rendered with label text, not color alone
    assert "CRITICAL" in html and "WARNING" in html
    # Multi-line recommendations render as lead + bullets, not a wall of text
    assert "<li>Complexity describes content conversion" in html
    # Built-in subscriptions are hidden by default and say nothing about it:
    # the count note was removed, so the name must not appear at all.
    assert "(built-in)" not in html
    assert "Quota enforcement" not in html
    # Catalog items table: friendly type labels and the custom form column
    assert "<th>Custom form</th>" in html
    assert "VCF Automation template" in html
    assert "<td>enabled</td>" in html
    # Deployment usage split by outcome
    assert '<th class="num">Successful</th>' in html
    assert '<th class="num">Failed</th>' in html

    # Inventory tables sort by display name regardless of API order - the
    # ABX inventory arrives as register-cmdb, legacy-dns-update,
    # vm-lifecycle-orchestrator and renders alphabetically. (The catalog
    # items table deliberately keeps most-deployed-first instead.)
    abx_table = html[html.index("<summary>ABX Actions Inventory") :]
    abx_table = abx_table[: abx_table.index("</details>")]
    assert (
        abx_table.index("legacy-dns-update")
        < abx_table.index("register-cmdb")
        < abx_table.index("vm-lifecycle-orchestrator")
    )

    # The ad-hoc deployments note is a deployment statistic: it renders under
    # the Deployments heading, not stranded in the Catalog block.
    assert html.index("did not come from the catalog") > html.index("<h4>Deployments</h4>")

    # Ownership rollup: heaviest owner first (bob: 2 deployments), machine
    # counts from actual compute resources only
    assert "<summary>Deployments by Owner " in html
    bob = html.index("<td>bob</td>")
    alice = html.index("<td>alice</td>")
    assert bob < alice  # 2 deployments sorts above 1
    assert "people who have left still appear" in html

    # Catalog access map: sharing-pattern table plus mermaid diagram. Web
    # Server is shared with both fixture projects ("all projects"), Unused
    # Item with none.
    assert "<summary>Catalog Access by Project " in html
    assert "all projects (2)" in html
    assert "(no project - not requestable)" in html
    assert 'id="CAT-004"' in html

    # Approvals: policy table and request table with pending count
    assert "Approval Policies" in html and "prod-approval" in html
    assert "2 total,\n1 pending" in html or "1 pending" in html
    assert "big-vm" in html
    # Approval gate diagram: the fixture's single project-scoped policy draws
    # one chain whose gate shows level, enforcement/mode, approver and the
    # auto-expiry outcome (labels reach mermaid via the escaped <br/> form)
    assert "<summary>Approval Flow Diagrams</summary>" in html
    # The header above a diagram names the contexts only: the actions live in
    # the request node, and printing both put every action on the page twice.
    assert "project Platform</strong>" in html
    assert "project Platform</strong> - Deployment.Create" not in html
    # "level 1:" and never "1." - a leading "N. " is markdown-list syntax to
    # mermaid and rendered as "Unsupported markdown: list"
    assert "level 1: prod-approval" in html
    assert "1. prod-approval" not in html
    assert "HARD, ANY_OF" in html
    assert "1 approver(s), see table" in html
    assert "auto-expiry after 7d: REJECT" in html
    assert "approved: request proceeds" in html
    # Capability replacement map rendered with evidence
    assert "Capability Replacement Map" in html
    assert "VM &amp; network provisioning" in html
    assert "3 template(s), 8 active deployment(s)" in html


def test_tag_assignments_grouped_and_deduped():
    # Live regression: the same fabric network appeared twice per tag (once
    # per collection path) and every tag rendered as one run-on cell.
    from vcf_automation_assessment_tool.report.renderer import _tag_assignments

    rows = _tag_assignments(
        {
            "net:k8s": [
                {"kind": "fabric-network", "id": "n1", "name": "seg-241", "via": "capability tag"},
                {"kind": "fabric-network", "id": "n1", "name": "seg-241", "via": "capability tag"},
                {"kind": "fabric-network", "id": "n2", "name": "seg-240", "via": "capability tag"},
                {"kind": "project", "id": "p1", "name": "PROJ-X", "via": "storage constraint"},
                {"kind": "project", "id": "p1", "name": "PROJ-X", "via": "network constraint"},
            ]
        }
    )
    assert rows[0]["tag"] == "net:k8s"
    assert rows[0]["lines"] == [
        "fabric-network (2): seg-240, seg-241",
        "project (1): PROJ-X (network constraint, storage constraint)",
    ]


def test_tag_assignments_cap_long_kinds():
    # A tag on fifty segments stays one line: 12 names then "+N more".
    from vcf_automation_assessment_tool.report.renderer import _tag_assignments

    uses = [
        {"kind": "fabric-network", "id": f"n{i}", "name": f"seg-{i:03d}", "via": "capability tag"}
        for i in range(50)
    ]
    rows = _tag_assignments({"net:big": uses})
    (line,) = rows[0]["lines"]
    assert line.startswith("fabric-network (50): seg-000, seg-001")
    assert line.endswith("(+38 more)")


def test_tag_assignments_hoist_shared_note():
    # A note every group member shares is stated once in the group head: a
    # live estate suffixed all 12 accounts on one tag with the same
    # inheritance note, drowning the names in repetition.
    from vcf_automation_assessment_tool.report.renderer import _tag_assignments

    uses = [
        {
            "kind": "cloud-account",
            "id": f"a{i}",
            "name": f"acct-{i}",
            "via": "inherited by its computes",
        }
        for i in range(3)
    ]
    rows = _tag_assignments({"ca:azure": uses})
    (line,) = rows[0]["lines"]
    assert line == "cloud-account (3; inherited by its computes): acct-0, acct-1, acct-2"
    # A single-member group keeps the note next to the name.
    rows = _tag_assignments(
        {
            "ca:one": [
                {
                    "kind": "cloud-account",
                    "id": "a1",
                    "name": "solo",
                    "via": "inherited by its computes",
                }
            ]
        }
    )
    assert rows[0]["lines"] == ["cloud-account (1): solo (inherited by its computes)"]


def test_display_sorted_is_case_insensitive_with_fallback_and_ties():
    from vcf_automation_assessment_tool.report.renderer import _display_sorted

    rows = [
        {"id": "b", "name": "beta"},
        {"id": "a", "name": "Alpha"},
        {"id": "z", "name": ""},  # unnamed rows sort first, stable by id
        {"id": "y", "name": ""},
    ]
    assert [r["id"] for r in _display_sorted(rows, "name")] == ["y", "z", "a", "b"]

    # Identically named profiles (real estates hold five RHEL9 image
    # profiles) tie-break on the region the table shows next to them.
    profiles = [
        {"id": "2", "name": "RHEL9", "region_label": "vc-b / dc"},
        {"id": "1", "name": "RHEL9", "region_label": "vc-a / dc"},
    ]
    ordered = _display_sorted(profiles, "name", secondary="region_label")
    assert [p["id"] for p in ordered] == ["1", "2"]

    # The label falls back through the keys like the table's own cell does.
    crts = [
        {"id": "1", "resourceType": "vcAD"},
        {"id": "2", "displayName": "AD Computer", "resourceType": "zz"},
    ]
    assert [c["id"] for c in _display_sorted(crts, "displayName", "resourceType")] == ["2", "1"]


def test_mark_dates_bolds_dates_and_keeps_escaping():
    # The filter escapes first, so the emphasis markup is the only HTML that
    # survives - markup smuggled into finding text stays inert.
    from vcf_automation_assessment_tool.report.renderer import _mark_dates

    marked = str(_mark_dates("floor dates from 2025-07-01, honest"))
    assert marked == "floor dates from <strong>2025-07-01</strong>, honest"
    hostile = str(_mark_dates('<script>alert("2025-07-01")</script>'))
    assert "<script>" not in hostile
    assert "<strong>2025-07-01</strong>" in hostile


def test_abx_run_column_withheld_on_id_dialect_mismatch():
    # Live shape: run records carried name-like actionIds ("Infoblox_Get...")
    # that may not match UUID inventory ids. Zero overlap means matching
    # cannot be trusted: no labels, and the evidence view hides the column -
    # never a false "none recorded" on every action.
    from vcf_automation_assessment_tool.report.renderer import _abx_run_view

    gov = {
        "abx_actions": [{"id": "8a7480f0-uuid-1", "name": "Infoblox_GetIPRanges"}],
        "abx_run_evidence": {
            "collected": True,
            "complete": True,
            "by_action": {"Infoblox_GetIPRanges": {"count": 9, "last_millis": 1, "last_state": ""}},
        },
    }
    view, evidence = _abx_run_view(gov)
    assert evidence == {}  # column hidden
    assert "last_run_label" not in view["abx_actions"][0]


def test_approval_gates_chains_group_and_order():
    # A request passes org policies everywhere and project policies only in
    # their project, in level order; identical chains merge across contexts.
    from vcf_automation_assessment_tool.report.renderer import _approval_gates

    org_1 = {
        "id": "o1",
        "name": "org-mgr",
        "projectId": "",
        "level": 1,
        "actions": ["Deployment.Create", "Deployment.Delete"],
    }
    org_2 = {
        "id": "o2",
        "name": "org-cfo",
        "projectId": "",
        "level": 2,
        "actions": ["Deployment.Create"],
    }
    proj = {
        "id": "pp",
        "name": "proj-extra",
        "projectId": "p1",
        "level": 3,
        "actions": ["Deployment.Create"],
    }
    unread = {"id": "ux", "name": "no-actions", "projectId": "", "actions": []}
    chains, note = _approval_gates([org_2, org_1, proj, unread], {"p1": "Platform"})

    gates = {
        (c["context"], tuple(c["actions"])): [g["policy"]["id"] for g in c["gates"]] for c in chains
    }
    # Create in Platform stacks all three gates by level; Delete has the same
    # single-gate chain everywhere, so both contexts fold into one diagram.
    assert gates[("project Platform", ("Deployment.Create",))] == ["o1", "o2", "pp"]
    assert gates[("project Platform; every other project", ("Deployment.Delete",))] == ["o1"]
    assert gates[("every other project", ("Deployment.Create",))] == ["o1", "o2"]
    # The action-less policy is named in the note, never guessed into a chain.
    assert "no-actions" in note and "not drawn" in note


def test_approval_gates_merge_structurally_identical_project_policies():
    # Live estate shape: one approval policy per project, every one level 1 /
    # HARD / ANY_OF / REJECT after 7d on the same actions, only the approvers
    # differing. That draws ONE diagram standing for all of them, not one per
    # project; the odd one out (an extra gated action) keeps its own diagram.
    from vcf_automation_assessment_tool.report.renderer import _approval_gates

    def pol(pid, name, actions):
        return {
            "id": f"id-{name}",
            "name": name,
            "projectId": pid,
            "scopeCriteria": {},
            "level": 1,
            "enforcementType": "HARD",
            "approvalMode": "ANY_OF",
            "approvers": [f"USER:{name}@x"],
            "autoApprovalDecision": "REJECT",
            "autoApprovalExpiry": 7,
            "actions": actions,
        }

    same = ["Deployment.Create", "Deployment.Delete"]
    chains, note = _approval_gates(
        [
            pol("p1", "a-approval", same),
            pol("p2", "b-approval", same),
            pol("p3", "c-approval", [*same, "Deployment.ChangeLease"]),
        ],
        {"p1": "A", "p2": "B", "p3": "C"},
    )
    assert note == ""
    assert len(chains) == 2
    merged = next(c for c in chains if c["gates"][0]["count"] == 2)
    # Counted, not one "project X" per name: the live header repeated the word
    # 20 times before it ran out of room.
    assert merged["context"] == "2 projects: A, B"
    assert merged["gates"][0]["policy"] is None  # approvers differ per policy
    assert merged["gates"][0]["approvalMode"] == "ANY_OF"
    single = next(c for c in chains if c["gates"][0]["count"] == 1)
    assert single["context"] == "project C"
    assert single["gates"][0]["policy"]["name"] == "c-approval"


def test_approval_gate_diagram_keeps_identities_out_of_labels():
    # Live regression: approvers like "USER:12345@example.com" in a gate label
    # hit mermaid's markdown autolinker and rendered as "Unsupported
    # markdown: link". Identities never enter the diagram source; the gate
    # carries the count and points at the table above.
    from vcf_automation_assessment_tool.report.diagrams import approval_gates_diagram

    chain = {
        "context": "project A",
        "actions": ["Deployment.Create"],
        "gates": [
            {
                "count": 1,
                "policy": {
                    "id": "x",
                    "name": "A - Approval Policy",
                    "approvers": ["USER:12345@example.com", "USER:6789@example.com"],
                },
                "level": 1,
                "enforcementType": "HARD",
                "approvalMode": "ANY_OF",
                "autoApprovalDecision": "REJECT",
                "autoApprovalExpiry": 7,
                "scope_criteria": False,
            }
        ],
    }
    src = approval_gates_diagram(chain)
    assert "@" not in src
    assert "2 approver(s), see table" in src
    assert "level 1: A - Approval Policy" in src


def _render(sample_data, tmp_path, name="report.html"):
    out = tmp_path / name
    build_flows(sample_data)
    run_checks(sample_data)
    render_report(sample_data, str(out))
    return out.read_text(encoding="utf-8")


def _finding_block(html, check_id):
    start = html.index(f'id="{check_id}"')
    return html[start : html.index("</details>", start)]


def test_the_project_column_is_dropped_where_no_row_fills_it(sample_data, tmp_path):
    """Zones, endpoints, policies and whole projects belong to no project, and
    a column left empty down every row of a table reads as something the
    collection failed to fetch. Same rule as the endpoint Status column."""
    html = _render(sample_data, tmp_path, "report-project-column.html")
    # INF-003 is about cloud accounts, which no project owns.
    assert "<th>Project</th>" not in _finding_block(html, "INF-003")
    # TAG-001 is about template constraints, which a project does own.
    assert "<th>Project</th>" in _finding_block(html, "TAG-001")


def test_zones_hide_the_compute_filter_column_when_no_zone_uses_one(sample_data, tmp_path):
    """A live estate picked the computes for all 41 of its zones by hand, so
    the column was 41 blank cells."""
    for zone in sample_data.raw["infrastructure"]["zones"]:
        zone["tagsToMatch"] = []
    html = _render(sample_data, tmp_path, "report-no-zone-filters.html")
    zones = html[html.index("<summary>Cloud Zones ") :]
    zones = zones[: zones.index("</details>")]
    assert "tagsToMatch" not in zones
    assert "No cloud zone selects its compute resources by tag" in zones


def test_no_storage_profiles_is_stated_rather_than_left_blank(sample_data, tmp_path):
    """The section promises storage choices. Dropping the table in silence
    makes an estate that defines none look like a report that forgot to ask."""
    sample_data.raw["infrastructure"]["storage_profiles"] = []
    html = _render(sample_data, tmp_path, "report-no-storage.html")
    assert "No storage profiles are defined" in html


def test_storage_profiles_that_could_not_be_read_are_not_called_absent(sample_data, tmp_path):
    """The collector records an empty list for a failed fetch as well as for an
    empty estate. Only one of those is something to tell the reader."""
    sample_data.raw["infrastructure"]["storage_profiles"] = []
    sample_data.record_error("infrastructure", "storage_profiles", "HTTP 403")
    html = _render(sample_data, tmp_path, "report-storage-unread.html")
    assert "No storage profiles are defined" not in html


def test_the_orchestrators_are_named_in_a_sentence(sample_data, tmp_path):
    """The source of an external endpoint is the integration's own name, so
    the raw values joined by commas read as a broken list."""
    sample_data.raw["vro"]["endpoints"] = [
        {"source": "embedded", "reachable": True},
        {"source": "external-vRO", "reachable": False},
    ]
    html = _render(sample_data, tmp_path, "report-vro-endpoints.html")
    assert (
        "looked up on the embedded Orchestrator and the external-vRO integration (unreachable)"
        in html
    )


def test_glance_omits_areas_that_returned_nothing(sample_data, tmp_path):
    # Every area is collected now, but one can still fail outright, and a
    # tile reading 0 would present that as a fact about the estate.
    sample_data.raw.pop("vro")
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "report-missing-area.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    assert "<span>Orchestrator actions</span>" not in html
    assert "<span>Projects</span>" in html


def test_report_shows_builtin_subs_when_asked(sample_data, tmp_path):
    sample_data.meta["include_system_subscriptions"] = True
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "report-with-system.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    assert "Quota enforcement" in html and "(built-in)" in html


def test_report_notes_missing_sharing_data_instead_of_fake_unshared(sample_data, tmp_path):
    # Live regression: a build whose items API never populates projectIds
    # rendered ALL items as "(no project - not requestable)". Without
    # evidence the report must say the data is unavailable instead.
    from vcf_automation_assessment_tool.access import build_catalog_access

    for i in sample_data.raw["catalog"]["items"]:
        i["projectIds"] = []
    sample_data.raw["governance"]["policies"] = [
        p
        for p in sample_data.raw["governance"]["policies"]
        if not p["typeId"].endswith("catalog.entitlement")
    ]
    build_flows(sample_data)
    build_catalog_access(sample_data)
    run_checks(sample_data)
    out = tmp_path / "report-nosharing.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    assert "not requestable" not in html
    assert "could not work out which projects" in html


def test_hiding_the_replatforming_section_takes_every_rep_finding(sample_data, tmp_path):
    """The REP family is always computed now; listing the section in
    ignore_sections is what keeps it out, and that has to take REP-002 with
    it - the one finding rendered outside its own section."""
    sample_data.meta["ignore_sections"] = ["replatforming"]
    build_flows(sample_data)
    run_checks(sample_data)
    assert any(f.check_id == "REP-002" for f in sample_data.findings)
    out = tmp_path / "report-noreplat.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    assert 'id="replatforming"' not in html
    assert 'href="#replatforming"' not in html  # nav pill hidden too
    assert "Replatforming" not in html
    assert "Capability Replacement Map" not in html
    # REP-002 renders in Design and Templates, so a section filter keyed on
    # the display section would have left it behind.
    # This also covers cross-references from other sections: nothing outside
    # Replatforming may name a REP check while the section is hidden.
    assert "REP-" not in html
    # The header says what it withheld.
    assert "Hidden sections<b>replatforming</b>" in html


def test_a_wide_sharing_pattern_reads_as_a_count(sample_data, tmp_path):
    """Naming forty projects in a cell fills four lines and buries the item
    the row is about. Past a handful the count stands in for the list, and the
    names stay in the document so the CSV export still carries them."""
    from vcf_automation_assessment_tool.access import build_catalog_access

    wide = {f"wide-{i:02d}": f"WIDE-{i:02d}" for i in range(12)}
    sample_data.derived.setdefault("project_names", {}).update(wide)
    sample_data.raw["catalog"]["items"][0]["projectIds"] = list(wide)
    build_catalog_access(sample_data)
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "report-wide-sharing.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    # The fixture's own sharing policy widens the pattern past the twelve
    # projects set here, so the count is read back rather than hard-coded.
    summary = re.search(r"<summary>(\d+) projects: </summary>", html)
    assert summary and int(summary.group(1)) >= 12
    assert "WIDE-00" in html and "WIDE-11" in html


def test_adhoc_deployment_note_suppressed_at_zero(sample_data, tmp_path):
    # "0 deployments were did not come from the catalog" is noise - the note
    # only renders when there is something to say.
    from vcf_automation_assessment_tool.access import build_catalog_access

    sample_data.raw["catalog"]["adhoc_deployment_count"] = 0
    build_catalog_access(sample_data)
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "report-noadhoc.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    assert "did not come from the catalog" not in html


def test_render_escapes_object_names(sample_data, tmp_path):
    # Autoescape was silently off once (select_autoescape doesn't match .j2);
    # this pins that object-supplied strings can never inject markup.
    # deployments[1] is failed-dep, which renders in the DEP-001 affected table.
    sample_data.raw["deployments"]["deployments"][1]["name"] = "x<script>alert(1)</script>&y"
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "report-escape.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    assert "x<script>alert(1)</script>&y" not in html
    assert "x&lt;script&gt;" in html


def test_render_without_mermaid(sample_data, tmp_path, monkeypatch):
    import vcf_automation_assessment_tool.report.renderer as renderer

    monkeypatch.setattr(renderer, "_load_mermaid", lambda: None)
    build_flows(sample_data)
    run_checks(sample_data)
    out = tmp_path / "report-nomermaid.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    # Diagrams degrade to visible source blocks.
    assert 'class="mmd-src"' in html
    assert "mermaid.initialize" not in html
    # The CSV export script does not ride on mermaid's presence.
    assert "function csvFromTable" in html


def test_flows_nothing_reacts_to_are_listed_not_drawn(sample_data, tmp_path):
    build_flows(sample_data)
    # The renderer, not the matcher, owns the split, so force the empty-topics
    # shape directly instead of engineering an unmatchable fixture item.
    flow = next(f for f in sample_data.derived["flows"] if f["item_name"] == "Reset VM Password")
    flow["concerns"] = []
    out = tmp_path / "report-silent-flow.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    # It leaves the diagram list (count drops) for the compact table, which
    # shows the friendly type label; no diagram row remains for it.
    assert 'Day 2 Change Flows <span class="count">(2 items)' in html
    assert '<summary>Items No Subscription Reacts To <span class="count">(1)</span>' in html
    silent = html[html.index("Items No Subscription Reacts To") :]
    silent = silent[: silent.index("</details>")]
    assert "<td>Reset VM Password</td>" in silent
    assert "<td>Automation Orchestrator workflow</td>" in silent
    assert "<summary>Reset VM Password" not in html


def test_finding_row_cap_comes_from_meta(sample_data, tmp_path):
    """max_rows_per_finding in meta (set from config/CLI) caps each finding's
    affected table, with the truncation note carrying the remainder."""
    import re

    build_flows(sample_data)
    run_checks(sample_data)
    sample_data.meta["max_rows_per_finding"] = 1
    out = tmp_path / "report-capped.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    # Every finding now shows at most one row; at least one fixture finding
    # has more than one affected object, so the cap must visibly bite there.
    counts = [int(n) for n in re.findall(r"Show 1 of (\d+) affected", html)]
    assert counts and max(counts) > 1
    assert re.search(r"Show 1 of \d+ affected", html) and "Show 2 of" not in html
    assert "more not shown. Use --json for the full list." in html


def test_csv_export_logic_runs(sample_data, tmp_path):
    """Exercise the report's own CSV functions in node, extracted from the
    rendered HTML, so escaping and truncation honesty are proven against the
    exact code a browser will run. Self-skips when node is not on PATH."""
    import shutil
    import subprocess

    import pytest

    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available to exercise the CSV export script")

    build_flows(sample_data)
    out = tmp_path / "report-csv.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    script = html[
        html.index("function csvField") : html.index("</script>", html.index("function csvField"))
    ]
    # Keep the pure functions, drop the DOM wiring that needs a browser.
    script = script[: script.index("document.querySelectorAll")]

    harness = script + (
        'const assert = require("assert");\n'
        "assert.strictEqual(csvField('a \"quoted\" value, with comma'),"
        ' \'"a ""quoted"" value, with comma"\');\n'
        "assert.strictEqual(csvField('  spaced   out  '), 'spaced out');\n"
        "assert.strictEqual(csvField('line one\\n   line two\\n\\n'), '\"line one\\nline two\"');\n"
        "const table = { rows: [\n"
        "  { cells: [{ textContent: 'Name' }, { textContent: 'Detail' }] },\n"
        "  { cells: [{ textContent: 'web-01' }, { textContent: 'status=FAILED, since 2024' }] },\n"
        "] };\n"
        "assert.strictEqual(csvFromTable(table, '88 more not shown.'),\n"
        "  'Name,Detail\\r\\nweb-01,\"status=FAILED, since 2024\"\\r\\n'\n"
        "  + '# 88 more not shown.\\r\\n');\n"
        "assert.strictEqual(csvSlug('Cloud accounts (3)'), 'cloud-accounts');\n"
        "// Formula injection: a leading =, +, -, @ or tab is neutralized with\n"
        "// an apostrophe so Excel renders text, never a live formula.\n"
        "assert.strictEqual(csvField('=HYPERLINK(\"http://evil\")'),\n"
        '  \'"\\\'=HYPERLINK(""http://evil"")"\');\n'
        "assert.strictEqual(csvField('+441234567890'), \"'+441234567890\");\n"
        "assert.strictEqual(csvField('@cmd'), \"'@cmd\");\n"
        "assert.strictEqual(csvField('safe =middle'), 'safe =middle');\n"
        "console.log('csv logic ok');\n"
    )
    proof = tmp_path / "csv_check.js"
    proof.write_text(harness, encoding="utf-8")
    result = subprocess.run([node, str(proof)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "csv logic ok" in result.stdout


def test_json_dump_round_trip(sample_data):
    import json

    build_flows(sample_data)
    run_checks(sample_data)
    blob = json.dumps(sample_data.to_json_dict(), default=str)
    assert "DEP-001" in blob and "capability_tags" in blob  # serializes cleanly


def test_render_survives_explicit_nulls_and_shows_gap_heading(sample_data, tmp_path):
    """Explicit JSON nulls from live documents (runnableType, deployment
    status) must render, not abort after a completed collection; and any
    SYS-001 finding renders under its own Collection Gaps heading."""
    build_flows(sample_data)
    sample_data.raw["deployments"]["deployments"].append(
        {"id": "null-dep", "name": "null-dep", "status": None, "resources": []}
    )
    sample_data.raw["extensibility"]["subscriptions"].append(
        {
            "id": "null-sub",
            "name": "internal-null",
            "eventTopicId": "t",
            "runnableType": None,
            "runnableName": "",
            "runnableId": "x",
            "scope": "global",
            "criteria": "",
            "blocking": False,
            "disabled": False,
            "builtin": True,
        }
    )
    sample_data.meta["include_system_subscriptions"] = True
    sample_data.record_error("governance", "policies", "HTTP 403")
    run_checks(sample_data)
    out = tmp_path / "report-nulls.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    assert "internal-null" in html
    assert '<details class="sec" id="system" open>' in html
    assert "<summary><h2>Collection Gaps</h2></summary>" in html


def test_flow_summary_counts_the_whole_estate_when_capped(sample_data, tmp_path, monkeypatch):
    import vcf_automation_assessment_tool.report.renderer as renderer

    monkeypatch.setattr(renderer, "MAX_FLOW_DIAGRAMS", 1)
    build_flows(sample_data)
    out = tmp_path / "report-capped-flows.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    # The cap is per section, so every part of the life still appears and
    # each says what it left out. Day 2 is the one all three items reach.
    assert 'Day 2 Change Flows <span class="count">(1 of 3 items)' in html
    assert 'Provisioning Flows <span class="count">(1 of 3 items)' in html
    assert 'Disposal Flows <span class="count">(1 of 2 items)' in html
    assert "2 more items not shown in this part" in html


def test_approval_gates_note_renders_even_with_no_drawable_chain(sample_data, tmp_path):
    """Every definition unreadable: the honesty note must still appear, or
    empty Gated-actions cells go unexplained."""
    build_flows(sample_data)
    for p in sample_data.raw["governance"]["approval_policies"]:
        p["actions"] = []
    out = tmp_path / "report-no-gates.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")
    assert "No readable action list on:" in html


def test_approval_gate_levels_tolerate_string_values(sample_data, tmp_path):
    build_flows(sample_data)
    sample_data.raw["governance"]["approval_policies"][0]["level"] = "1"
    out = tmp_path / "report-str-level.html"
    render_report(sample_data, str(out))  # must not TypeError on mixed levels


def test_render_a_completely_empty_estate(tmp_path):
    """A run where nothing was collected still renders: partial data is this
    tool's normal weather and the crash class lives in sparse documents."""
    from vcf_automation_assessment_tool.models import AssessmentData

    data = AssessmentData()
    data.meta = {"url": "https://empty.test", "generated_at": "now", "tool_version": "t"}
    data.record_error("infrastructure", "skipped", "area skipped via --skip")
    run_checks(data)
    out = tmp_path / "report-empty.html"
    render_report(data, str(out))
    html = out.read_text(encoding="utf-8")
    assert "Summary" in html


def test_a_diagram_holds_only_its_own_concern(sample_data, tmp_path):
    """The point of the split: opening Disposal shows the teardown events and
    nothing else. A single diagram carrying the whole life is what made the
    live report unreadable."""
    build_flows(sample_data)
    out = tmp_path / "report-concern-split.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    disposal = html[html.index("<summary>Disposal Flows") : html.index("<h4>Deployments</h4>")]
    assert "compute.removal.post" in disposal
    assert "compute.provision.post" not in disposal
    assert "deployment.resource.action.post" not in disposal

    provisioning = html[html.index("<summary>Provisioning Flows") :]
    provisioning = provisioning[: provisioning.index("<summary>Day 2 Change Flows")]
    assert "compute.provision.post" in provisioning
    assert "compute.removal.post" not in provisioning


def test_a_named_event_type_moves_the_subscription_out_of_request(sample_data, tmp_path):
    """A request-topic subscription that names DESTROY_DEPLOYMENT belongs
    under Disposal, and the Request section says why the rest stay there."""
    sub = next(s for s in sample_data.raw["extensibility"]["subscriptions"] if s["id"] == "sub2")
    sub["disabled"] = False
    sub["criteria"] = "event.data.eventType == 'DESTROY_DEPLOYMENT'"
    sub["scope"] = "conditional"
    sub["criteria_blueprint_ids"] = []
    sub["criteria_event_types_eq"] = ["DESTROY_DEPLOYMENT"]
    build_flows(sample_data)
    out = tmp_path / "report-event-type.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    disposal = html[html.index("<summary>Disposal Flows") : html.index("<h4>Deployments</h4>")]
    assert "deployment.request.pre" in disposal
    # And it has left the build it would otherwise have been shown with.
    provisioning = html[
        html.index("<summary>Provisioning Flows") : html.index("<summary>Day 2 Change Flows")
    ]
    assert "old-hook" not in provisioning
    assert "Unplaced Request Flows" not in html


def test_a_request_naming_two_kinds_gets_a_section_of_its_own(sample_data, tmp_path):
    """A subscription that fires on a create AND a destroy belongs to neither
    part on its own. The report keeps it apart rather than filing it under one
    of them."""
    sub = next(s for s in sample_data.raw["extensibility"]["subscriptions"] if s["id"] == "sub2")
    sub["disabled"] = False
    sub["criteria"] = (
        "event.data.eventType == 'CREATE_DEPLOYMENT'"
        " || event.data.eventType == 'DESTROY_DEPLOYMENT'"
    )
    sub["scope"] = "conditional"
    sub["criteria_blueprint_ids"] = []
    sub["criteria_event_types_eq"] = ["CREATE_DEPLOYMENT", "DESTROY_DEPLOYMENT"]
    build_flows(sample_data)
    out = tmp_path / "report-unplaced-request.html"
    render_report(sample_data, str(out))
    html = out.read_text(encoding="utf-8")

    assert "<summary>Unplaced Request Flows" in html
    assert "rule out a new deployment without saying" in html
    unplaced = html[html.index("<summary>Unplaced Request Flows") :]
    assert "deployment.request.pre" in unplaced[: unplaced.index("<h4>Deployments</h4>")]
    # Last of the four, after the parts of the life it could not be placed in.
    assert html.index("<summary>Disposal Flows") < html.index("<summary>Unplaced Request Flows")


def test_machines_by_project_lists_only_machines(sample_data, tmp_path):
    html = _render(sample_data, tmp_path)
    block = html[
        html.index('id="machines-by-project"') : html.index("<!-- /machines-by-project -->")
    ]
    # Every machine resource, under the project that owns its deployment.
    assert "Platform <span" in block
    assert "<td>vm-1</td><td>web-prod</td>" in block
    assert "<td>vm-ghost</td>" in block and "<td>MISSING</td>" in block
    # Networks and disks are not machines, and a deployment with no machines adds no row.
    assert "net-only" not in block and "lb-segment" not in block and "empty-dep" not in block


def test_machine_address_column_appears_only_when_a_row_has_one(sample_data, tmp_path):
    html = _render(sample_data, tmp_path)
    block = html[
        html.index('id="machines-by-project"') : html.index("<!-- /machines-by-project -->")
    ]
    assert "<th>Address</th>" not in block  # the fixture records no addresses
    sample_data.raw["deployments"]["deployments"][0]["resources"][0]["address"] = "192.0.2.10"
    html = _render(sample_data, tmp_path)
    block = html[
        html.index('id="machines-by-project"') : html.index("<!-- /machines-by-project -->")
    ]
    assert "<th>Address</th>" in block and "<td>192.0.2.10</td>" in block


def test_machine_table_prefers_hostname_and_falls_back_to_resource_name(sample_data, tmp_path):
    resource = sample_data.raw["deployments"]["deployments"][0]["resources"][0]
    resource["name"] = "Cloud_vSphere_Machine_1"
    resource["hostname"] = "web-prod-01.example.test"
    html = _render(sample_data, tmp_path)
    block = html[
        html.index('id="machines-by-project"') : html.index("<!-- /machines-by-project -->")
    ]
    assert block.count("<th>Hostname</th>") == block.count("<table>")
    assert "<td>web-prod-01.example.test</td>" in block
    assert "Cloud_vSphere_Machine_1" not in block
    resource["hostname"] = ""
    html = _render(sample_data, tmp_path)
    block = html[
        html.index('id="machines-by-project"') : html.index("<!-- /machines-by-project -->")
    ]
    assert "<td>Cloud_vSphere_Machine_1</td>" in block
