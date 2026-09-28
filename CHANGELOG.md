# Changelog

All notable changes to the VCF Automation Assessment Tool are documented in
this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The sample report now shows a realistic provisioning flow for Web Server:
  six events in lifecycle order, two subscriptions on one event, a conditional
  subscription and a blueprint-scoped one.

## [1.0.0] - 2026-09-23

First stable release.

### Added

- MIT license for the project's original code and documentation, permitting
  use, modification and redistribution, including commercial use. Third-party
  material retains its own terms; see [NOTICE.md](NOTICE.md).
- The tool: `vcf-automation-assessment-tool`, a read-only assessment of a
  VCF Automation 8.x estate over its REST APIs. It writes one self-contained
  HTML report with no external requests, and optionally the full raw dump as
  JSON. Configuration comes from `config.yaml`, command-line flags or `VCF_*`
  environment variables; the password is prompted or read from `VCF_PASSWORD`,
  never a flag or a file key. A leftover key or variable from an earlier name is
  reported by name rather than dropped.
- Progress output per phase while a run is under way, login failures that carry
  the server's own error detail, retries with `Retry-After` honoured for a busy
  or restarting appliance, bearer token refresh as often as a long collection
  needs it, and an exit code usable in CI: 0 clean, 1 the run itself failed,
  2 something CRITICAL was found.
- An executive summary opening with the estate at a glance, the platform
  version, severity tiles and the findings table, followed by one collapsible
  chapter per area: Infrastructure, Consumption, Policies and Governance, Design
  and Templates, Extensibility, Replatforming Readiness, and Collection Gaps.
  Every chapter has an inventory rail and a findings rail with its own severity
  counts.
- Infrastructure: cloud accounts and integrations with health status and
  capability tags, cloud zones with compute counts, network and storage
  profiles, IP ranges with the platform's allocation counters and a finding
  for a range that is full or nearly so, flavor and image mappings with region
  labels, projects, the platform's secrets by name and scope with the templates
  that read each one and a review list of the ones nothing reads, the groups
  granted on projects, a Project Zone Allocation table of each project's quota
  in every zone against what is allocated, and one table of every capability
  tag with where it is assigned and which templates consume it.
- Consumption: catalog usage headlines, an item table with deployment counts
  and custom request form markers, content source import health, a catalog
  access map resolved from item project lists, legacy entitlements and content
  sharing policies and folded into sharing patterns, per-item flow diagrams
  split into Provisioning, Day 2 Change and Disposal, a deployments status
  rollup with soft-deleted deployments, optional request history with outcomes
  grouped by what was requested, an ownership rollup with last activity and
  strongest project role, resolved through group membership, and every machine
  listed under its project, each project's table exportable on its own.
- Policies and Governance: one table per policy type with the UI's names,
  content sharing policies resolved to what they share and with whom, approval
  policies with their gate chains drawn as diagrams, and approval requests.
- Design and Templates: cloud templates with validation status, versions and
  constraint tags classified as hard, soft, negated or dynamic; property groups;
  custom resource types and their day-2 actions with what each lifecycle step
  runs, resolved by name, and a finding for a step bound to an ABX action that
  no longer exists; and Placement Diagrams showing
  where each template can actually be built, from resource through constraint
  to the places the requesting projects can reach, including the values a
  request-time constraint can take where the template or the input schema
  spells them out.
- Extensibility: the subscription inventory with blocking and disabled state,
  resolved runnables and criteria analysis; Orchestrator workflows resolved to
  names against the embedded and external Orchestrators; customer-authored
  Orchestrator actions and ABX actions inventoried with their source analysed
  (Python via AST, JavaScript via esprima with node as referee, PowerShell via
  its own parser where available), complexity rated, a Last run column from
  the platform's retained run history, and each action's runtime version with a
  finding for the ones on a runtime the platform has removed or deprecated.
- Replatforming Readiness Report, hidden by default through `ignore_sections`:
  an evidence-driven capability-to-replacement map against the target stack,
  per-catalog-item difficulty ratings, templates not under Git, and the
  Orchestrator dependency surface.
- Findings graded INFO, WARNING and CRITICAL, evidence-guarded so a check stays
  silent where the estate could not answer, and listed in full in the README's
  findings reference, which a test keeps in lockstep with the code:
  - Infrastructure: INF-001 to INF-007, PRJ-001 to PRJ-006, TAG-001 to TAG-005.
  - Consumption: CAT-001 to CAT-004, DEP-001 to DEP-010.
  - Policies and Governance: APR-001 to APR-002, POL-001 to POL-006.
  - Design and Templates: BLU-001 to BLU-003, REP-002.
  - Extensibility: EXT-001 to EXT-009, VRO-001 and VRO-002.
  - Replatforming: REP-001 and REP-003. System: SYS-001.
- Run controls: `ignore_sections` and `ignore_findings` (filtering the report,
  never the collection, with what was hidden named in the header), `project`
  to limit the scope, `request_history` and `request_history_limit`,
  `group_membership`, `pedantic` for hygiene-level code signals,
  `max_rows_per_finding`, `timeout` and `retries`. Seven pure inventory findings
  ship ignored in `config.example.yaml`.
- `--compare PATH`: the previous run's `--json` dump. The Executive Summary
  then opens with what changed since it: findings that appeared or were
  resolved, findings whose object list moved, and the estate's counts side by
  side. A dump that cannot be read fails the run before it logs in.
- A redacted copy of the report for sharing outside the organisation:
  `redact: true` writes a second file from the same collection pass with
  identities, hosts and tags replaced by stable aliases, and names and ids on
  request. Redaction runs after the checks, so findings and counts are those
  of the unredacted report. The rendered page is searched for every value the
  run learned, and the file is not written if one survives. `redact_key` saves
  the alias mapping for in-house tracing; the JSON dump is never redacted.
- An Export CSV button on every data table, assembled in the browser, with a
  capped table's export ending in the truncation note.
- A sample report built from synthetic test data, committed at the repository
  root, and a README that describes every area and every finding.

### Security

- CSV exports neutralise formula-leading characters (`=`, `+`, `-`, `@`, tab)
  with a leading apostrophe, so a hostile object name from the platform cannot
  open as a live formula in Excel.
- Request inputs and outputs are never stored, because they can carry
  credentials; credentials embedded in a URL are dropped by redaction rather
  than aliased. Secret values are never requested or stored: the secrets
  inventory holds names, scope and authorship only.
