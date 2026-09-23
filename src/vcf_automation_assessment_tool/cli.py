"""CLI entry point: parse args/config, authenticate, collect, check, render."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

from . import __version__, codequality
from .access import build_catalog_access
from .auth import AuthError
from .capability_map import build_capability_map
from .checks import run_checks
from .client import ApiClient, ApiError
from .collectors import COLLECTORS
from .comparison import compare_runs, load_previous, previous_path_problem
from .config import RunConfig
from .flows import build_flows
from .models import AssessmentData, Severity
from .redaction import Redactor
from .report.renderer import build_html, render_report, template_source

log = logging.getLogger("vcf_automation_assessment_tool")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vcf-automation-assessment-tool",
        description="Assessment tool for VMware VCF Automation 8.x: estate "
        "health, hygiene and complexity",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "--config",
        metavar="PATH",
        help="YAML config file (default: ./config.yaml if present)",
    )
    p.add_argument("--url", help="VCF Automation base URL, e.g. https://vra.example.com")
    p.add_argument(
        "--username",
        help="username for CSP login (password is prompted, never a flag; or set VCF_PASSWORD)",
    )
    p.add_argument("--domain", help="identity source domain for LDAP/AD users")
    p.add_argument(
        "--refresh-token",
        dest="refresh_token",
        help="pre-obtained refresh token (or env VCF_REFRESH_TOKEN)",
    )
    tls = p.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
        default=None,
        help="skip TLS certificate verification (self-signed certs)",
    )
    tls.add_argument(
        "--ca-bundle",
        dest="ca_bundle",
        metavar="PATH",
        help="path to a CA bundle for TLS verification",
    )
    p.add_argument("--output", metavar="PATH", help="HTML report output path")
    p.add_argument("--json", metavar="PATH", help="also dump collected data as JSON")
    p.add_argument(
        "--compare",
        metavar="PATH",
        help="an earlier run's --json dump; the report then says what changed since it",
    )
    p.add_argument(
        "--project",
        action="append",
        metavar="NAME",
        help="limit the report to this project (repeatable)",
    )
    p.add_argument(
        "--include-system-subscriptions",
        action="store_true",
        dest="include_system_subscriptions",
        default=None,
        help="show platform built-in subscriptions (Quota enforcement, "
        "Approval workflow, ...) in the report; hidden by default",
    )
    p.add_argument(
        "--pedantic",
        action="store_true",
        default=None,
        help="include hygiene-level code-quality signals (untidy but working "
        "code) alongside the defect-level ones; off by default",
    )
    p.add_argument(
        "--request-history",
        action="store_true",
        default=None,
        help="read every deployment's request history so failures that were "
        "retried or deleted are counted, not just deployments broken right "
        "now. Costs one API call per deployment; off by default",
    )
    p.add_argument(
        "--request-history-limit",
        metavar="N",
        type=int,
        default=None,
        help="read request history for at most N deployments (live first, then "
        "soft-deleted). Use for a trial run on a large estate; whatever is left "
        "out is reported as a collection gap",
    )
    p.add_argument(
        "--no-group-membership",
        action="store_true",
        default=None,
        help="skip expanding the groups projects grant to. Expansion is on by "
        "default (about one call per group); without it owners reached through "
        "a group cannot be resolved and are reported as undetermined",
    )
    p.add_argument(
        "--ignore-section",
        metavar="SECTION",
        action="append",
        help="report section to leave out (repeatable); also the "
        "ignore_sections list in the config file. Valid: summary, "
        "infrastructure, consumption, design, extensibility, governance, "
        "replatforming, system. Collection is unaffected - every area is "
        "always collected and the --json dump is always complete",
    )
    p.add_argument(
        "--ignore-finding",
        metavar="ID",
        action="append",
        help="check id to leave out of the report (repeatable); also the "
        "ignore_findings list in the config file. Ignored findings are still "
        "computed and still appear in the --json dump",
    )
    p.add_argument(
        "--redact",
        action="store_true",
        default=None,
        help="also write a redacted copy of the report, safe to share outside "
        "the organisation: identities, host names and capability tags are "
        "replaced with stable aliases. The normal report is written as well",
    )
    p.add_argument(
        "--redact-output",
        dest="redact_output",
        metavar="PATH",
        help="where to write the redacted copy (default: alongside the report, "
        "named vcf-automation-assessment-report-redacted-<timestamp>.html)",
    )
    p.add_argument(
        "--redact-class",
        dest="redact_class",
        action="append",
        metavar="CLASS",
        help="what the redacted copy replaces (repeatable, replaces the "
        "default set): identity, hosts, tags, names, ids. Default: identity, "
        "hosts, tags - object names stay readable unless 'names' is asked for",
    )
    p.add_argument(
        "--redact-extra",
        dest="redact_extra",
        action="append",
        metavar="TEXT",
        help="an extra string to replace wherever it appears, including inside "
        "longer words (repeatable). For a company or site name that the "
        "classes above would not catch on their own",
    )
    p.add_argument(
        "--redact-key",
        dest="redact_key",
        metavar="PATH",
        help="write the alias-to-real-value mapping as CSV, so findings can be "
        "traced back in-house. This file is as sensitive as the estate: keep it "
        "and never send it with the redacted report",
    )
    p.add_argument("--timeout", type=int, help="per-request timeout in seconds (default 60)")
    p.add_argument(
        "--retries",
        type=int,
        help="times to repeat a call that times out or drops before the run "
        "gives up on it (default 3, 0 to try each call once)",
    )
    p.add_argument("--page-size", dest="page_size", type=int, help="API page size (default 100)")
    p.add_argument(
        "--max-rows-per-finding",
        dest="max_rows_per_finding",
        type=int,
        help="cap on affected objects listed per finding table in the HTML report "
        "(default 500); the full list is always in the --json dump",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="-v: progress info, -vv: debug incl. request URLs",
    )
    return p


def setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)-7s %(name)s: %(message)s")
    if verbosity < 2:
        logging.getLogger("urllib3").setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    # Ctrl+C anywhere - the password prompt, a slow collection sweep, the
    # render - exits with one line instead of a traceback. 130 is the
    # conventional SIGINT exit code.
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


def _main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)

    try:
        cfg = RunConfig.load(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    errors = cfg.validate()
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1

    # Resolve and create output locations before login: an unwritable path
    # must fail in the first second, not after minutes of live collection
    # (mkdir(exist_ok=True) still raises when a FILE named reports exists).
    host = urlparse(cfg.url).hostname or "aria"
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    # Default runs collect under reports/ so repeated assessments do not
    # litter the working directory; an explicit output path is used as given.
    output = cfg.output or str(
        Path("reports") / f"vcf-automation-assessment-report-{host}-{stamp}.html"
    )
    redacted_output = _redacted_path(output, stamp, cfg) if cfg.redact else None
    target = output
    try:
        for target in filter(None, (output, cfg.json_path, redacted_output, cfg.redact_key)):
            parent = Path(target).parent
            if parent != Path("."):
                parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"error: cannot create the output location for {target}: {exc}", file=sys.stderr)
        return 1

    # The earlier dump is read before login: a wrong path must fail in the
    # first second, not after minutes of live collection.
    problem = previous_path_problem(cfg.compare_path)
    if problem:
        print(f"error: {problem}", file=sys.stderr)
        return 1
    previous = load_previous(cfg.compare_path) if cfg.compare_path else None

    # Progress lines on stderr so a redirected stdout stays clean. With -v the
    # INFO logging already narrates the run in more detail, so stay quiet then.
    def status(msg: str) -> None:
        if args.verbose == 0:
            print(msg, file=sys.stderr, flush=True)

    status(f"vcf-automation-assessment-tool {__version__} -> {cfg.url}")

    data = AssessmentData()
    data.meta = {
        "url": cfg.url,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "tool_version": __version__,
        "identity": cfg.username or "(refresh token)",
        "projects_filter": cfg.projects,
        "include_system_subscriptions": cfg.include_system_subscriptions,
        "pedantic": cfg.pedantic,
        # Read by the deployments collector, which has no access to the config.
        "request_history": cfg.request_history,
        "request_history_limit": cfg.request_history_limit,
        "group_membership": cfg.group_membership,
        "ignore_findings": cfg.ignore_findings,
        "ignore_sections": cfg.ignore_sections,
        "max_rows_per_finding": cfg.max_rows_per_finding,
        # Whether PowerShell sources get real AST analysis (PowerShell's own
        # parser on this host) or regex heuristics - the report says which.
        "powershell_parser": codequality.powershell_available(),
        # Whether JavaScript structure could be parsed at all (esprima is a
        # dependency, so this is only False on a broken install).
        "javascript_parser": codequality.esprima_available(),
    }

    client = ApiClient(cfg)
    try:
        status(f"authenticating as {cfg.username or '(refresh token)'} ...")
        client.login()
        about = client.pin_api_versions()
        data.meta["iaas_api_version"] = client.iaas_api_version
        data.meta["supported_apis"] = [a.get("apiVersion") for a in about.get("supportedApis", [])]
        # Best-effort platform version: the embedded Orchestrator's /about is
        # the one version endpoint present on every 8.x build, and its
        # version tracks the appliance release.
        try:
            vco_about = client.get("/vco/api/about")
            if isinstance(vco_about, dict) and vco_about.get("version"):
                data.meta["platform_version"] = vco_about["version"]
        except (ApiError, requests.RequestException):
            pass
        version_note = data.meta.get("platform_version", "")
        status(
            "authenticated ("
            + (f"VCF Automation {version_note}, " if version_note else "")
            + f"IaaS API version {client.iaas_api_version})"
        )
    except (AuthError, ApiError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except requests.RequestException as exc:
        # Unreachable host / TLS failure before any API answered - one clean
        # line, not a traceback.
        print(f"error: cannot reach {cfg.url}: {exc}", file=sys.stderr)
        return 1

    started = time.monotonic()
    for index, (area, collect) in enumerate(COLLECTORS, start=1):
        status(f"[{index}/{len(COLLECTORS)}] collecting {area} ...")
        log.info("collecting: %s", area)
        try:
            collect(client, data)
        except Exception as exc:  # a whole failed area must not kill the run
            log.exception("collector %s failed", area)
            data.record_error(area, "collector", f"{type(exc).__name__}: {exc}")
    status(f"collection finished in {time.monotonic() - started:.0f}s")

    def analysis(step_name: str, fn) -> None:
        # A broken analysis step must not cost the artifacts of a completed
        # collection: record the gap (SYS-001 reports it) and carry on with
        # whatever the remaining steps can still derive.
        try:
            fn()
        except Exception as exc:
            log.exception("analysis step %s failed", step_name)
            data.record_error("analysis", step_name, f"{type(exc).__name__}: {exc}")

    _apply_project_filter(data, cfg)
    # Access resolution first: it unions content-sharing-policy grants into
    # item projectIds, which flow matching then relies on.
    status("analyzing (catalog access, flows, checks) ...")
    analysis("catalog access", lambda: build_catalog_access(data))
    if cfg.projects:
        # Item project membership is only complete after sharing enrichment,
        # so the item filter runs here rather than with the deployment and
        # blueprint filters, and the access patterns are rebuilt over the
        # kept items (the enrichment union is idempotent).
        _apply_catalog_project_filter(data, cfg)
        analysis("catalog access (filtered)", lambda: build_catalog_access(data))
    analysis("flows", lambda: build_flows(data))
    analysis("capability map", lambda: build_capability_map(data))
    run_checks(data)
    if previous is not None:
        # After the checks, over this run's own findings, and before the
        # dump so the comparison travels with the data it was made from.
        data.derived["comparison"] = compare_runs(data, previous)
        data.meta["compared_with"] = data.derived["comparison"]["previous"]["generated_at"]

    # The raw dump is written before the report: if rendering breaks, the
    # collected data survives.
    output_failed = False
    if cfg.json_path:
        try:
            with open(cfg.json_path, "w", encoding="utf-8") as fh:
                json.dump(data.to_json_dict(), fh, indent=2, default=str)
        except OSError as exc:
            # The dump exists to protect a finished collection, so losing it
            # must not also cost the report it was meant to back up - a full
            # disk here used to end the run with a traceback and no artifacts
            # at all. The run still fails: something that was asked for is
            # missing.
            log.exception("json dump failed")
            print(f"error: could not write {cfg.json_path}: {exc}", file=sys.stderr)
            output_failed = True
        else:
            print(f"json dump written: {cfg.json_path}")

    status("rendering report ...")
    try:
        render_report(data, output)
    except Exception as exc:
        log.exception("report rendering failed")
        print(f"error: report rendering failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        if cfg.json_path:
            print(f"the raw data survived in {cfg.json_path}", file=sys.stderr)
        return 1
    print(f"report written: {output}")

    if redacted_output:
        status("rendering redacted copy ...")
        if not _write_redacted(data, cfg, redacted_output):
            return 1

    all_areas = [area for area, _ in COLLECTORS]
    areas_with_errors = {e.get("area") for e in data.errors}
    if all(a in areas_with_errors for a in all_areas) and not _collected_anything(data):
        # Every area failed and nothing came back: the report only documents
        # the gaps, and a CI wrapper must not read that as success.
        print("error: no data could be collected from any area", file=sys.stderr)
        return 1

    from .report.renderer import visible_findings

    shown = visible_findings(data.findings, cfg.ignore_findings, cfg.ignore_sections)
    criticals = sum(1 for f in shown if f.severity is Severity.CRITICAL)
    warnings = sum(1 for f in shown if f.severity is Severity.WARNING)
    print(
        f"findings: {criticals} critical, {warnings} warning, "
        f"{len(shown) - criticals - warnings} info"
    )
    if len(shown) != len(data.findings):
        print(f"({len(data.findings) - len(shown)} hidden per configuration)")
    # An id that matched nothing is usually a typo, and a typo silently keeps
    # a finding the operator meant to drop.
    unmatched = set(cfg.ignore_findings) - {f.check_id.upper() for f in data.findings}
    if unmatched:
        print(
            f"warning: ignore_findings entries matched no finding: {', '.join(sorted(unmatched))}",
            file=sys.stderr,
        )
    # A run that could not write something it was asked for failed, whatever
    # the findings said: 1 is "the tool did not do the job", and it outranks
    # the 2 that only reports what the estate looks like.
    if output_failed:
        return 1
    return 2 if criticals else 0


def _redacted_path(output: str, stamp: str, cfg: RunConfig) -> str:
    """Where the shareable copy goes.

    Named from the timestamp alone, never the appliance: it is the file that
    leaves the organisation, and a host name in the file name gives away what
    the contents were cleaned of. It sits beside the report so both artifacts
    of one run stay together.
    """
    if cfg.redact_output:
        return cfg.redact_output
    return str(Path(output).parent / f"vcf-automation-assessment-report-redacted-{stamp}.html")


def _write_redacted(data: AssessmentData, cfg: RunConfig, output: str) -> bool:
    """Render the shareable copy, or explain why it was not written.

    The audit is the point of the exercise. A report that only looks redacted
    is more dangerous than no redacted report at all, so a residue leaves the
    file unwritten and the run failing rather than producing something whose
    header claims it is safe to send.
    """
    try:
        redactor = Redactor(cfg.redact_classes, cfg.redact_extra)
        redactor.learn(data)
        shareable = redactor.redact(data)
        shareable.meta["redaction"] = redactor.summary()
        html = build_html(shareable)
        residue = redactor.audit(html, allowed=template_source())
    except Exception as exc:
        log.exception("redaction failed")
        print(f"error: redaction failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return False
    if residue:
        print(
            "error: the redacted report was NOT written - these values survived "
            "redaction and would have been shared:",
            file=sys.stderr,
        )
        for hit in residue[:20]:
            print(f"  {hit['class']}: {hit['value']} ({hit['count']}x)", file=sys.stderr)
        if len(residue) > 20:
            print(f"  ... and {len(residue) - 20} more", file=sys.stderr)
        return False
    # Both writes are guarded for the same reason the audit above exists: this
    # is the artifact that leaves the organisation, and a half-written file or
    # a key that never landed has to be said out loud rather than reaching the
    # caller as a traceback.
    try:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(html)
    except OSError as exc:
        print(f"error: could not write the redacted report to {output}: {exc}", file=sys.stderr)
        return False
    summary = shareable.meta["redaction"]
    print(f"redacted report written: {output} ({summary['replaced']} value(s) replaced)")
    if cfg.redact_key:
        try:
            with open(cfg.redact_key, "w", encoding="utf-8", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(("class", "alias", "real value"))
                writer.writerows(
                    tuple(_csv_safe(field) for field in row) for row in redactor.key_rows()
                )
        except OSError as exc:
            print(
                f"error: the redacted report was written, but the redaction key "
                f"could not be: {cfg.redact_key}: {exc}",
                file=sys.stderr,
            )
            return False
        print(f"redaction key written: {cfg.redact_key} - as sensitive as the estate, keep it")
    return True


def _csv_safe(field: str) -> str:
    """Same guard the report's own CSV export applies: a name beginning with a
    formula character runs as one when the file is opened in Excel."""
    return f"'{field}" if field and field[0] in "=+-@\t" else field


def _apply_project_filter(data: AssessmentData, cfg: RunConfig) -> None:
    """Client-side scoping: keep only objects belonging to the named projects."""
    if not cfg.projects:
        return
    wanted_names = set(cfg.projects)
    project_names = data.derived.get("project_names", {})
    wanted_ids = {pid for pid, name in project_names.items() if name in wanted_names} | wanted_names

    deps = data.raw.get("deployments", {}).get("deployments")
    if deps is not None:
        data.raw["deployments"]["deployments"] = [
            d
            for d in deps
            if d.get("projectId") in wanted_ids or d.get("projectName") in wanted_names
        ]
    bps = data.raw.get("blueprints", {}).get("blueprints")
    if bps is not None:
        # Snapshot the full id -> name map first: subscription criteria
        # resolution (EXT-001/EXT-005) must not call a filtered-out but
        # existing blueprint deleted.
        data.derived.setdefault("blueprint_names", {}).update(
            {b["id"]: b.get("name", "") for b in bps if b.get("id")}
        )
        data.raw["blueprints"]["blueprints"] = [
            b
            for b in bps
            if b.get("projectId") in wanted_ids or b.get("projectName") in wanted_names
        ]
    data.meta["projects_filter"] = sorted(wanted_names)


def _apply_catalog_project_filter(data: AssessmentData, cfg: RunConfig) -> None:
    """Filter catalog items on their post-enrichment project membership.

    Runs after build_catalog_access: on builds where sharing lives in content
    sharing policies, an item's collector-reported projectIds may be empty or
    stale until the policy grants are unioned in, and filtering on the
    pre-enrichment value dropped items actually shared into the wanted
    project. Items with no membership either way are kept: unknown is not
    "not in this project".
    """
    if not cfg.projects:
        return
    wanted_names = set(cfg.projects)
    project_names = data.derived.get("project_names", {})
    wanted_ids = {pid for pid, name in project_names.items() if name in wanted_names} | wanted_names
    items = data.raw.get("catalog", {}).get("items")
    if items is not None:
        data.raw["catalog"]["items"] = [
            i for i in items if not i.get("projectIds") or set(i["projectIds"]) & wanted_ids
        ]


def _collected_anything(data: AssessmentData) -> bool:
    """True when at least one collection area yielded at least one object."""
    for area_data in data.raw.values():
        if isinstance(area_data, dict) and any(
            isinstance(v, list) and v for v in area_data.values()
        ):
            return True
    return False


if __name__ == "__main__":
    sys.exit(main())
