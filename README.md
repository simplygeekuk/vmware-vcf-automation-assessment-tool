# vcf-automation-assessment-tool

Version **1.0.1** is the current stable release. See the
[changelog](CHANGELOG.md) for release details.

VCF Automation Assessment Tool for VMware VCF Automation 8.x. It interrogates
the platform read-only over its REST APIs and produces one self-contained HTML
report of estate health, hygiene, usage and complexity. The report covers broken
and stale content, unused configuration, extensibility wiring, code quality, and
who can consume what.

The assessment naturally supports upgrade or migration planning. A Replatforming
Readiness Report, hidden by default, scopes what replacing VCF Automation would
take. The target stack is OpenShift, GitLab CI/CD, Ansible Automation Platform
and Terraform.

<!-- ste:procedural -->

## Install

Python 3.11 or later is required. The commands below also require Git.

Clone the repository, enter its directory, and install the tool in a virtual
environment:

```powershell
git clone https://github.com/simplygeekuk/vmware-vcf-automation-assessment-tool.git
cd vmware-vcf-automation-assessment-tool
python -m venv .venv
.venv\Scripts\pip install -e .
```

Installing the tool also installs `pyflakes` and `esprima`, which is everything
needed to analyse Python and JavaScript action source. PowerShell is the one
exception. Real parsing uses PowerShell's own engine, so `pwsh` or `powershell`
has to be on the assessment host's PATH. Without it, PowerShell actions fall
back to regex heuristics. The report says which of the three parsers actually
ran.

<!-- ste:descriptive -->

## Authentication

Two flows, both ending in the IaaS bearer token used for every service:

1. `POST /csp/gateway/am/api/login?access_token` takes a username and password,
   with an optional domain, and returns a refresh token.
2. `POST /iaas/api/login` exchanges that refresh token for the bearer token.

With `--refresh-token` or `VCF_REFRESH_TOKEN`, step 1 is skipped. The password
is never a CLI flag and is never read from the config file. It is prompted for,
hidden, or taken from `VCF_PASSWORD`.

Full org-wide coverage needs Organization Owner plus the Assembler and Service
Broker admin roles. With less, the tool degrades per area, and the report states
exactly what could not be collected (SYS-001). Without catalog admin, for
example, it falls back to the entitlement-scoped item list and says so.

<!-- ste:procedural -->

## Run

```powershell
# username/password - password is prompted, never echoed
.venv\Scripts\vcf-automation-assessment-tool --url https://vra.example.com --username admin --insecure -v

# or with a pre-obtained refresh token
$env:VCF_REFRESH_TOKEN = "..."
.venv\Scripts\vcf-automation-assessment-tool --url https://vra.example.com --insecure

# or seed everything from a config file (see config.example.yaml)
Copy-Item config.example.yaml config.yaml   # then edit
.venv\Scripts\vcf-automation-assessment-tool -v
```

While the tool runs, one progress line per phase goes to stderr: authentication,
each collection area numbered, analysis, and rendering. `-v` switches to
detailed logging instead.

### Useful flags

| Flag | Effect |
|---|---|
| `--output PATH` | Where to write the report. The default is `reports/vcf-automation-assessment-report-<host>-<timestamp>.html`, and the folder is created as needed. |
| `--json PATH` | Also write the full raw dump. |
| `--compare PATH` | An earlier run's `--json` dump. The report then opens with what changed since it. See below. |
| `--project NAME` | Limit the report to this project. Repeatable. |
| `--domain corp.local` | The identity source domain, for LDAP and AD users. |
| `--ca-bundle PATH` | A CA bundle for TLS verification, instead of `--insecure`. |
| `--include-system-subscriptions` | Show the platform's built-in subscriptions, which are hidden from the report by default: Quota enforcement, Approval workflow, Migration Assessment and `ABX-CGS-*`. |
| `--ignore-section NAME` | Leave a report section out. Repeatable. See below. |
| `--ignore-finding ID` | Leave a finding out of the report. Repeatable. See below. |
| `--pedantic` | Add hygiene-level code-quality signals to the defect-level ones reported by default. |
| `--request-history` | Read every deployment's request history. One API call per deployment. |
| `--request-history-limit N` | Trial the request history over part of the estate first. |
| `--no-group-membership` | Skip expanding the groups projects grant to. |
| `--timeout N` | The per-request timeout, for a busy appliance. |
| `--retries N` | How many times to repeat a call that times out or drops. |
| `--max-rows-per-finding N` | Change the 500-row cap on each finding's affected-objects table. `max_rows_per_finding` does the same in the config file. |
| `--redact` | Write a shareable redacted copy alongside the report. See below. |

A call that times out or drops is repeated 3 times by default. The waits are 1,
2 and 4 seconds. After that the run gives up on the call and records the gap.

Every flag here has a config-file equivalent under the same name, with dashes as
underscores. See `config.example.yaml`.

<!-- ste:descriptive -->

### Leaving sections and findings out

The report is filtered, never the collection. Every area is collected on every
run, so the checks always see the whole estate and the `--json` dump is always
complete. What you choose not to read is a rendering decision.

`ignore_sections` lists the report sections to leave out, by anchor id. The ids
are `summary`, `infrastructure`, `consumption`, `design`, `extensibility`,
`governance`, `replatforming` and `system`. `--ignore-section NAME` is
repeatable and does the same for one run.

```yaml
ignore_sections:
  - replatforming
```

Hiding a section takes its findings with it wherever they render. Hiding
`replatforming` also removes REP-002 from Design and Templates, which is where
that one is displayed. The nav pill goes too, and the header names what was
hidden.

This is how the Replatforming Readiness Report is turned on and off, and
`config.example.yaml` ships with it hidden, so the base report is a pure estate
assessment. Delete the line to include the capability replacement map, the
per-item difficulty ratings and the Orchestrator dependency surface.

`ignore_findings` in the config file lists check ids the HTML report omits.
`--ignore-finding ID` is repeatable, does the same for one run, and overrides
the file.

```yaml
ignore_findings:
  - DEP-002
```

Ignored findings still run, and they still appear in the `--json` dump. Only the
HTML leaves them out, and its header names what it suppressed, so a reader is
never silently short of a finding. Ids are matched case-insensitively. An id
that matched nothing is reported at the end of the run, because that is almost
always a typo keeping a finding you meant to drop.

`config.example.yaml` ships with one finding ignored: DEP-002, which needs two
carve-outs to be usable. Remove the id to see that finding again.

### Sharing the report outside the organisation

`redact: true`, or `--redact`, writes a second report beside the normal one with
identifying values replaced by stable aliases. Both files come from one
collection pass, so an external copy costs no extra API calls:

```
reports/vcf-automation-assessment-report-vra01.corp.local-20260821-1530.html
reports/vcf-automation-assessment-report-redacted-20260821-1530.html
```

The redacted file is named from the timestamp alone, because a host name in a
filename undoes the work done on the contents. The report says on its own front
page that it is redacted, and what was replaced.

An alias is stable within a report. `person04` is the same person in the
ownership table and in the finding that names them, so the findings can still be
discussed with an outside party. The assessment underneath is untouched.
Redaction runs after the checks, so findings, counts, severities and dates are
exactly those of the unredacted report.

`redact_classes` chooses what is replaced. The default is `identity`, `hosts`
and `tags`:

| Class | Replaces | Alias |
|---|---|---|
| `identity` | user and group names, in every shape (UPN, `DOMAIN\user`, the project service's doubled form) | `person04@domain01.invalid` |
| `hosts` | host names, URLs, UNC paths and IP addresses; credentials embedded in a URL are dropped, never aliased | `host02.domain01.invalid`, `192.0.2.7` |
| `tags` | capability tag keys and values, and the composite | `tag06`, `tag06:tag07` |
| `names` | every object name: projects, templates, catalog items, deployments, subscriptions, actions, policies | `Project 04` |
| `ids` | internal identifiers | `id12` |

Add `names` where object names carry business unit, environment or site. Most
estates name things that way, and it is the one class whose cost is paid in
readability. `redact_extra` takes literal strings, replaced wherever they occur
and including inside longer identifiers. Use it for a company or site name the
classes cannot recognise on their own.

Nothing can prove a document carries no identifying value, so the tool checks
its own work. The rendered page is searched for the values the run learned. If
any survives, the redacted file is **not written**, and the run fails naming
what leaked.

Three limits are worth stating plainly:

- A value the tool never learned is neither replaced nor reported. A host name
  inside a free-text description, or an identifier in a catalog item's
  description, are both of that kind. The redacted report therefore still
  deserves the read-before-you-send that any document leaving the organisation
  gets.
- Values too short or too ordinary to tell from prose are replaced only where
  they stand alone. A tag spelled `no`, or one spelled `high`, are of that kind.
  For the same reason they are outside the scan, because searching for them
  would report the report itself. So are the words the report writes on its own
  account. An assessment account called `administrator` is replaced in the cell
  that names it, while the project role labels the report works out for itself
  are left as they are.
- Redaction is only as good as its classes. With `names` off, an object called
  `payments-prod-dr` says what it says.

`redact_key: PATH` writes the alias-to-real-value mapping as CSV, so a finding
can be traced back in-house. That file is as sensitive as the estate itself.
Keep it, and never send it with the report.

The `--json` dump is never redacted. It is the internal record of what was
collected, and a partially-redacted data dump would be a trap.

### Comparing with an earlier run

Every run is a snapshot. Keep the `--json` dump of each assessment and pass
the previous one as `--compare`, or as `compare` in the config file. The
Executive Summary then opens with what moved. It lists findings that appeared,
findings that were resolved, and findings whose object list grew or shrank,
with the estate's counts side by side. Objects are matched by the platform's id where it gave
one, else by name. A dump that is not this tool's, or cannot be read, fails
the run before it logs in. In a redacted copy the names of objects no longer
flagged are not printed, because they belong to the earlier run and were never
learned by this one.

<!-- ste:descriptive -->

## The report

One HTML file, with no external requests, because mermaid.js is vendored and
inlined. It can therefore be opened on an air-gapped jump host and attached to
assessment docs.

The Executive Summary sits up top, with severity tiles and the findings table.
Per-area inventory tables follow, in the order listed under
[What it reports](#what-it-reports). Affected-object
lists are collapsed and capped at 500 rows per finding, and the `--json` dump
has everything.

For a sample built from synthetic test data, run
`.venv\Scripts\python -m pytest tests/test_report.py`, or see
`vcf-automation-assessment-report-sample.html` if it is present.

## What it reports

One row per report section, in report order. Each row links to the subsection
below that describes it in full.

| Area | Contents |
|---|---|
| [Infrastructure](#infrastructure-and-projects) | Cloud accounts, integrations, cloud zones, network and storage profiles, IP ranges with their allocation, flavor and image mappings, projects, each project's quota in every zone it uses, and the platform's secrets with what reads them |
| [Infrastructure - Capability Tags](#capability-tags) | One table of every capability tag: where it is assigned, and which blueprints consume it |
| [Consumption - Catalog](#catalog) | Catalog usage numbers, an item table with deployment counts, content source import health, and a project access map |
| [Consumption - Catalog Flow Diagrams](#catalog-flow-diagrams) | Mermaid diagrams of what runs alongside a deployment, split into Provisioning, Day 2 Change and Disposal |
| [Consumption - Deployments](#deployments) | A status rollup, the soft-delete window, request outcomes, the deployment findings, an ownership rollup, and every machine listed under its project |
| [Policies and Governance](#policies-approvals-and-governance) | Policies grouped by type, approval policies with their gate chains drawn, and approval requests |
| [Design and Templates](#cloud-templates-and-design-content) | Cloud templates with their validation status, versions and constraint tags, plus property groups and custom resource types |
| [Design and Templates - Placement Diagrams](#placement-diagrams) | One mermaid diagram per template showing where it can actually be built, drawn only where the resolution is worth seeing |
| [Extensibility - Subscriptions](#subscriptions) | The full subscription inventory, with blocking and disabled state, resolved runnables, and criteria shown in full |
| [Extensibility - Orchestrator Workflows and Actions](#orchestrator-workflows-and-actions) | Referenced workflows resolved to names, and customer-authored Orchestrator actions inventoried with their source analysed |
| [Extensibility - ABX Actions](#abx-actions) | An ABX action inventory with static code-quality analysis, a complexity rating and a Last run column |
| [Replatforming Readiness Report](#replatforming-readiness-report) (hidden by default) | A capability-to-replacement map, a per-catalog-item difficulty rating, templates not in Git, and the Orchestrator dependency surface |

### Infrastructure and projects

Cloud accounts and integrations are listed with their health status, where the
build's API exposes one, and an endpoint not in OK status is flagged. Their
capability tags are listed too. A cloud account or Orchestrator integration
carrying no capability tags goes on a review list, because those tags steer
placement and workflow routing.

Cloud zones are listed with their compute counts, alongside network and storage
profiles and flavor and image mappings. Each internal IP range is listed with
the platform's own allocation counters, and a range that is full or within a
fifth of full is flagged. Ranges an IPAM integration manages are listed without
counters, because the platform does not expose their usage.

Each project is listed with its quota in every cloud zone it uses: instances,
memory, CPU and storage, each shown against what the platform reports as
allocated. A limit this estate never sets is left out of the table. A project
that has used up a quota is flagged, as is one within a fifth of a quota, and so
is a project holding no zone at all.

Platform secrets are listed by name and scope, with the cloud templates and
property groups that read each one as `${secret.name}`. Values are never read.
A secret nothing reads goes on a review list.

### Capability tags

One table lists every capability tag: where it is assigned, and which blueprints
consume it. Tags are assigned on cloud zones, fabric computes, profiles and
cloud accounts, and an account's computes inherit that account's tags.

Constraint matching honours the one documented exception to that inheritance.
Storage profiles never inherit account tags, so a storage constraint matched
only by an account tag is still flagged as unmatchable.

A tag that only a request-time (dynamic) constraint could select is marked
"possibly consumed", and is never called unreferenced. The unreferenced-tag list
is an INFO review list, because tags can also serve automation and external
tooling that the API cannot see.

### Catalog

Headline usage numbers open the section: orderable items, how many nobody has
ever ordered, the share of demand carried by the three most-ordered items, and
the request failure rate.

Under them sits an expanded table of items. Each row carries deployment counts -
total, successful and failed - and a custom-request-form flag. An item with zero
deployments is flagged as a deletion candidate. The section also reports content
source import health.

A project access map says which projects can request which items. It is resolved
from content sharing policies and entitlements, and items with an identical
sharing pattern are grouped together. An item shared with no project is flagged
as unrequestable.

### Catalog flow diagrams

Mermaid diagrams show what runs alongside a deployment. They are split into
Provisioning, Day 2 Change and Disposal sections, so that one diagram answers
one question. Each diagram runs item -> source -> blueprint -> that part's
lifecycle event topics -> subscriptions -> runnable, and an item appears under
every part it has something attached to.

The request events that open a deployment are shown with the build. A
subscription whose `eventType` conditions name a change or a destroy is shown in
that part instead. One naming several kinds goes to an Unplaced Request Flows
section, rather than being filed under a part its conditions contradict. Those
conditions never decide whether the subscription is shown at all.

Items no subscription reacts to are listed in a compact table instead of drawn.

### Deployments

A status rollup is headlined by size and health: deployments, machines, how many
are in a failed state, and projects in use. Soft-deleted deployments the
platform has not yet purged are listed with it. With `request_history`, request
outcomes over the retained window are reported too, and the failures are grouped
by what was requested.

The section then reports failed, stuck and lease-expired deployments, failed
deployments that still hold machines, multi-machine stacks, resources MISSING on
the endpoint, and orphans. A failed deployment that still holds machines lists
each machine's power state. A multi-machine stack counts machines only: disks
and networks do not count.

Deployments with no machine resources are off by default, via `ignore_findings`.
Each is cross-referenced against the source template. A row whose template
defines machines says so, because those machines are expected but absent. A
deployment whose template defines no machines at all is excluded as machineless
by design, as are runs of workflow, action and pipeline catalog items. Each
flagged row names the item it came from.

An ownership rollup is headlined by its concentration: owners, the share held by
the largest owner and by the top three, and deployments with no recorded owner.
It lists each owner's last activity and the strongest project role the collected
data confirms, including roles granted through groups. By default, the tool reads
membership for groups that projects grant roles to, where the API permits it.
An unreadable group is recorded as a gap, not treated as an empty group.
If an owner's access remains unresolved because of an unreadable group on their
project, the report shows "not determined". Use `--no-group-membership` to skip
collecting group membership.

Machines by Project lists every machine the platform still holds, under the
project that owns its deployment, with power state, sync status, owner,
creation date, and the address and hostname where the platform records them. Each project sits in its own collapsible with its own CSV export,
so one project's list can be handed to the people who own it.

### Policies, approvals and governance

Policies are grouped by type, with a table per type. Content sharing policies
are resolved to the sources and items they share, and to whom.

Three things are flagged: per-project copies that org scoping could replace,
policies scoped to since-deleted projects, and overlaps between
organization-scoped and project-scoped policies of the same type.

Approval policies are listed with their level, mode, approvers, gated actions
and auto-expiry behaviour. Their gate chains are drawn as mermaid diagrams,
running request -> each approval level in order -> outcome. Organization and
project policies are combined per context, and identical chains are merged.

Approval requests are listed, and pending ones are flagged, because they block
deletion and leave requesters waiting.

### Cloud templates and design content

Cloud templates are listed with their validation status and versions. Constraint
tags are extracted from the YAML and classified as hard, soft, negated or
dynamic. Hardcoded IP addresses, URLs and credential-looking values are flagged.

Property groups, custom resource types and their day-2 resource actions are
listed too. Each custom resource shows what its create, read, update and delete
steps run, resolved to the workflow or ABX action by name. A workflow the run
could not confirm on any Orchestrator is marked rather than called missing; an
ABX action absent from the inventory is flagged.

### Placement diagrams

One mermaid diagram per template shows where that template can actually be
built. Each diagram runs template -> each resource -> each constraint tag -> the
zones, profiles and computes whose capability tags satisfy it.

A diagram is drawn only where the resolution is worth seeing, which is one of
two cases. The first is a hard constraint nothing satisfies, which TAG-001 also
reports. The second is a constraint satisfied by a single place. No finding
reports that one, and it makes that zone or profile a single point of failure
for every deployment of the template.

Places shared by several constraints are drawn once, so converging arrows are
real convergence. A negated constraint is shown as the exclusion it is, rather
than counted as a match. A project-level constraint carrying the same tag is
counted beside the constraint as the extra condition it is, rather than drawn as
somewhere to build.

A request-time (dynamic) constraint names what decides it instead of printing
the expression: the inputs it reads, and the tag prefix it must come out as.
The tags it can produce are sometimes written down, either in the template or in
the values the platform declares for the input the constraint reads. Where they
are, each of those tags is resolved and drawn like any other tag. A request
whose answer lands nowhere is therefore visible, without the report claiming to
know which answer a request gives.

Where the request form fills that list by running an Orchestrator action, the
action is named and no value is claimed. The tool is read-only, so it never runs
the action.

A template is also drawn where one of those values matches nothing at all. Every
request choosing that value fails to place, and no finding reports it.

A project's own constraint tags appear as the condition they are: a requirement,
an exclusion or a soft preference.

### Subscriptions

The full subscription inventory carries blocking and disabled state, resolved
ABX and Orchestrator runnables, and broken references.

Criteria are shown in full, with scope analysis. Criteria pinned to blueprint or
project ids resolve each id to its current name, and they are flagged for
portability, because ids do not survive import into another tenant or instance.

### Orchestrator workflows and actions

Referenced workflows are resolved to names by targeted lookups against the
embedded Orchestrator and against external Orchestrator integration endpoints.
Both use the same bearer token.

Customer-authored Orchestrator actions are inventoried, with `com.vmware.*`
excluded. Their source is statically analysed like ABX code: Python via AST,
JavaScript via esprima, and PowerShell via PowerShell's own parser where it is
available.

### ABX actions

The ABX action inventory carries static code-quality analysis. It reports:

- bare, swallowed and re-raise-only exception handlers
- hardcoded IP addresses and credentials
- unpinned dependencies
- unused variables, unused imports and undefined names, via pyflakes
- Python syntax warnings, such as an invalid escape sequence

Each action's runtime and version are shown, and an action on a runtime the
platform has removed or deprecated is flagged.

Python is analysed via AST and JavaScript via esprima. PowerShell is analysed
via PowerShell's own parser where one is on the assessment host, and by
heuristics otherwise. Comment density and error handling are table metrics
rather than findings.

Every action also carries a LOW, MEDIUM or HIGH complexity rating. An ABX action
should stay a short glue script, so the ones grown into applications are
flagged.

A Last run column comes from one per-action lookup against the platform's
retained run history, and never-run actions are listed for review.

### Replatforming readiness report

An evidence-driven capability-to-replacement map takes each capability in use
and names a recommended solution from the target stack: Terraform, GitLab CI,
Ansible Automation Platform or OpenShift. Alternatives and caveats are given
with it.

The section also carries a per-catalog-item difficulty rating, the templates not
in Git, and the Orchestrator dependency surface.

It is hidden by default. Remove `replatforming` from `ignore_sections` to
include it.

### Severities and exit codes

Every finding carries a severity:

- CRITICAL - broken today
- WARNING - cleanup recommended
- INFO - inventory and awareness

The exit code is usable in CI:

| Code | Meaning |
|---|---|
| 0 | The run completed and nothing CRITICAL was found. |
| 1 | The run itself failed: bad configuration, an appliance it could not reach, or an output it was asked for that could not be written. |
| 2 | The run completed and something CRITICAL was found. |

### CSV export

Every data table in the report carries an Export CSV button, finding tables and
inventories alike. A list such as "412 failed deployments" can therefore be
worked through outside the report.

The file is assembled in the browser and saved through a download link, so the
report stays self-contained and no network is involved. Where a finding's table
is capped, the export's last row repeats the truncation note rather than
silently pretending to be complete. A field beginning with a formula character
is prefixed with an apostrophe, so a hostile object name cannot execute when the
file is opened in Excel.

## Findings reference

Everything the report can flag, by section.

Several checks are evidence-guarded. When the build's API gives no evidence
either way - no project list collected, no health signal on a document, no
sharing data - they stay silent rather than guess. Absence from a report
therefore does not mean the check found nothing.

A row marked "ignored by default" is listed in `config.example.yaml` under
`ignore_findings`, and it does not reach the report until you remove the id.

From the first release on, ids are never reused or renumbered, because a config
file, a ticket and an older report all refer to them. A section reads with a
gap where a check renders elsewhere: REP-002 renders under Design and Templates
with the templates it judges, so the Replatforming section holds REP-001 and
REP-003.

Tests keep this table in lockstep with the code, in both directions, including
which section each check appears under.

### Infrastructure

| ID | Severity | Reports |
|---|---|---|
| INF-001 | WARNING | Cloud zones with no computes or no project assignment |
| INF-002 | WARNING | Regions without flavor/image mappings, or broken image references |
| INF-003 | CRITICAL | Cloud accounts or integrations whose endpoint is not reporting OK. Silent per document when the build exposes no health signal. |
| INF-004 | INFO | Cloud accounts and Orchestrator integrations without capability tags. A review list: those tags steer placement and workflow routing. |
| INF-005 | WARNING | Internal IP ranges with no addresses left. The next build placed on that network fails after placement has chosen its zone. Silent when the ranges could not be read; IPAM-managed ranges carry no counters and are never judged. |
| INF-006 | INFO | Internal IP ranges within a fifth of full |
| INF-007 | INFO | Secrets no cloud template or property group reads. A review list: code the report does not see can also read a secret. Silent unless every template's content was read. |
| PRJ-003 | INFO | Projects granting to groups the organization does not list, whose membership therefore cannot be read |
| PRJ-001 | WARNING | Projects with no deployments and no blueprints |
| PRJ-002 | WARNING | Projects with no members of any role |
| PRJ-004 | WARNING | Projects that have used up their quota in a cloud zone. Nothing more can be built there until the limit rises or resources are freed. |
| PRJ-005 | INFO | Projects within a fifth of their quota in a cloud zone |
| PRJ-006 | WARNING | Projects with no cloud zone, so no template can be placed |
| TAG-001 | CRITICAL | Hard constraint tags no capability tag satisfies. Provisioning from those templates fails placement. |
| TAG-002 | WARNING | Soft constraint tags no capability tag satisfies. Request-time dynamic constraints are excluded, being unverifiable statically. |
| TAG-003 | INFO | Capability tags no visible constraint references. A review list: tags may also serve scripts, backup or monitoring that the API cannot see. Tags matching a dynamic constraint's static prefix are excluded. |
| TAG-004 | WARNING | Templates shared with projects that have no cloud zone satisfying their constraints. Every request from those projects fails to place. The question is asked per project and per resource, so a project holding one zone per tag, and no zone carrying both, is reported even though each constraint looks satisfied from there. The check is silent where no project carries a zone assignment. A project with no zones at all is PRJ-006. |
| TAG-005 | CRITICAL | Hard constraints on one resource that no single place satisfies together. Each tag matches something, so TAG-001 is silent, and every build still fails. Compute constraints are intersected over cloud zones, because that is what a machine lands in. |

### Consumption

| ID | Severity | Reports |
|---|---|---|
| CAT-001 | WARNING | Catalog items with no deployments (deletion candidates) |
| CAT-002 | WARNING | Content sources with import errors or incomplete imports |
| CAT-003 | INFO | Catalog item types in use |
| CAT-004 | INFO | Catalog items not shared with any project. Evidence-guarded: silent unless sharing data is demonstrably populated. |
| DEP-001 | CRITICAL | Deployments in a failed state |
| DEP-002 | WARNING | Deployments with no machine resources, cross-referenced against the source template (ignored by default: it needs two carve-outs to be usable, and a machine deleted on the endpoint is DEP-003's, not this one's) |
| DEP-003 | CRITICAL | Deployments with resources MISSING on the endpoint |
| DEP-004 | WARNING | Deployments stuck in progress for over 24 hours |
| DEP-005 | INFO | Deployments with expired leases still present |
| DEP-006 | INFO | Deployments with multiple machines |
| DEP-007 | WARNING | Deployments deleted while in a failed state, from the soft-delete window, so the record disappears once the platform purges them |
| DEP-008 | WARNING | Requests that failed across the retained request history, including retried ones and those whose deployment has since been deleted (needs `request_history`) |
| DEP-009 | WARNING | Deployment owners holding deployments in projects that grant them nothing, directly or through a group. The check is silent unless group membership was expanded, and silent for owners whose project uses a group that could not be read. |
| DEP-010 | WARNING | Failed deployments that still hold machines, each row grouping the machines by power state. This is the actionable part of DEP-001: the failures that left real compute behind. A machine whose document carries no power state is said to carry none, and is never reported as off. Machines already gone from the endpoint are not counted, and a deployment whose machines have all gone is left to DEP-003. An UPDATE_FAILED deployment is left out too, because its machines were in service before the change. |

### Policies and Governance

| ID | Severity | Reports |
|---|---|---|
| APR-001 | WARNING | Approval requests pending beyond 24 hours. They block deletion and leave requesters waiting. Younger ones are in-flight governance and stay in the requests table. |
| APR-002 | WARNING | Approval policies with no approvers defined. Nobody is asked, and gated requests sit until auto-expiry decides for them. Each row spells out that outcome. Role-resolved approver types and unread definitions are never flagged. |
| POL-001 | INFO | Per-project policy copies, identical in effect, that one org-scoped policy could replace |
| POL-002 | WARNING | Policies scoped to a project that no longer exists (evidence-guarded) |
| POL-003 | INFO | Projects covered by an org-scoped and a project-scoped policy of the same type at once. Day-2 action overlaps are classified per policy: delete candidates, grants that deletion would revoke, and enforcement supersession. |
| POL-004 | INFO | Projects with no day-2 action policy, project-scoped or organization-scoped. A review list, and evidence-guarded: silent when the project list or the policies could not be read. An org policy whose scope criteria could not be fully evaluated is named in a caveat as possibly covering the listed projects. |
| POL-005 | INFO | Projects with no approval policy, under the same coverage rules and evidence guards as POL-004 |
| POL-006 | INFO | Projects with no content sharing policy, under the same rules. Cross-check the catalog access map: content can also reach a project per-item, or through legacy entitlements. |

### Design and Templates

| ID | Severity | Reports |
|---|---|---|
| BLU-001 | WARNING | Templates failing validation or with unparseable YAML |
| BLU-002 | INFO | Draft-only templates (no released version) |
| BLU-003 | WARNING | Templates with hardcoded IPs, URLs or credential-looking values |
| REP-002 | WARNING | Templates not under Git source control. It renders here rather than in Replatforming, and is hidden with that section. |

### Extensibility

| ID | Severity | Reports |
|---|---|---|
| EXT-001 | WARNING | Subscriptions referencing missing runnables, blueprints or projects. An Orchestrator workflow is never called missing, because external and ACL-hidden workflows are indistinguishable from deleted ones. |
| EXT-002 | WARNING | Disabled event subscriptions: extensibility the platform is not running, so either the behaviour is silently absent or the subscription is dead weight |
| EXT-003 | WARNING | ABX actions with code-quality signals. These include probable defects such as a duplicated dictionary key or a declared entrypoint the source never defines. They also include bare, swallowed and re-raise-only handlers, hardcoded values, unpinned dependencies, unused and undefined names, and syntax warnings. |
| EXT-004 | INFO | ABX actions grown beyond a simple script (HIGH complexity rating) |
| EXT-005 | INFO | Subscription criteria pinned to instance-specific blueprint or project ids. They silently stop matching once content is imported into another tenant, or once the referenced object is recreated. Each pinned id is resolved to its current name. |
| EXT-006 | INFO | ABX actions with no recorded runs. A review list, from one per-action lookup against the platform's retained run history. Housekeeping prunes old runs, so absence is not proof an action never ran. The oldest record still retained is stated where it can be read in a verified order, which gives the window a visible floor. Each row says whether any subscription references the action. The finding is withheld when the lookups were unavailable or incomplete. |
| EXT-007 | INFO | Actions duplicated across the estate, with ABX and Orchestrator compared together. Source counts as duplicated when it is identical or near-identical once comments and formatting are ignored, so each group ports and gets fixed once rather than N times. Actions under 15 code lines are not compared. |
| EXT-008 | WARNING | ABX actions declared on a runtime the platform has removed or deprecated, from the action's own runtime and version: Python 3.7, Node.js 14 and 18, PowerShell 6.2 and 7.2. An action with no recorded version is not listed. |
| EXT-009 | WARNING | Custom resource lifecycle steps or day-2 actions bound to an ABX action the inventory does not hold. Every deployment of that resource fails at that step. Workflow bindings are never judged: an unconfirmed workflow is marked in the Custom Resources table instead. |
| VRO-001 | WARNING | Orchestrator actions with code-quality signals (same analysis as ABX) |
| VRO-002 | INFO | Complex Orchestrator workflows, rated from the orchestration graph (item count, decisions, sub-workflows, user-interaction and timer steps) |

### Replatforming Readiness Report (hidden by default)

| ID | Severity | Reports |
|---|---|---|
| REP-001 | INFO | The replatforming matrix: per-catalog-item difficulty and suggested target |
| REP-003 | INFO | The Orchestrator dependency surface: what a replacement must re-provide or re-design. REP-002 renders under Design and Templates. |

### System

| ID | Severity | Reports |
|---|---|---|
| SYS-001 | WARNING | Assessment incomplete: areas the run could not collect (permissions, missing endpoints), so the report may understate problems |

<!-- ste:procedural -->

## Development

```powershell
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\ruff format src tests     # format
.venv\Scripts\ruff check src tests      # lint (E/W/F, import order, bugbear, pyupgrade)
.venv\Scripts\python -m pytest tests/
```

Both ruff gates and the test suite must be clean before committing. Ruff is
configured in `pyproject.toml`, with line length 100 and the vendored
`report/static/mermaid.min.js` excluded.

The code lives under `src/vcf_automation_assessment_tool/`:

- `client.py` holds the two pagination dialects: `$top`/`$skip` for IaaS, and
  `page`/`size` for the Spring services.
- `collectors/` pull raw data.
- `checks/` are pure functions over the collected data, registered with
  `@check`.
- `report/` renders the jinja2 template.

Adding a check is one function in the right `checks/` module. Adding a collector
is one module plus a line in `collectors/__init__.py`.

<!-- ste:descriptive -->

### Local API references

Captured OpenAPI Specification (OAS) documents are optional development
references. Local copies can be kept under `docs/vcf_automation_oas_specs/`,
which Git ignores. They are excluded from the repository and are not required
to install or run the tool. These third-party documents retain their own terms,
as explained in [NOTICE.md](NOTICE.md).

<!-- ste:descriptive -->

## License

The project's original code and documentation are available under the
[MIT license](LICENSE). It permits free use, modification and redistribution,
including commercial use, provided the copyright and permission notices are
retained. The software is provided without warranty.

Third-party components retain their own license terms. See
[NOTICE.md](NOTICE.md) for details.
