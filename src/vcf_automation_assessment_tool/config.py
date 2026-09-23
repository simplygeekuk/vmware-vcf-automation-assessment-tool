"""Run configuration: CLI flags > environment variables > config file > defaults."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .redaction import CLASSES, DEFAULT_CLASSES, normalise_classes
from .retry import DEFAULT_RETRIES

log = logging.getLogger(__name__)

DEFAULT_CONFIG_FILES = ("config.yaml",)

CONFIG_KEYS = {
    "url",
    "username",
    "domain",
    "refresh_token",
    "insecure",
    "ca_bundle",
    "output",
    "json",
    "compare",
    "projects",
    "timeout",
    "retries",
    "page_size",
    "max_rows_per_finding",
    "include_system_subscriptions",
    "pedantic",
    "request_history",
    "request_history_limit",
    "group_membership",
    "ignore_findings",
    "ignore_sections",
    "redact",
    "redact_output",
    "redact_classes",
    "redact_extra",
    "redact_key",
}

# Options that were removed, mapped to what replaced them. A config file is
# edited far less often than the tool changes, so a leftover key has to say
# what happened rather than be dropped as "unknown".
RETIRED_KEYS = {
    "skip": (
        "collection no longer skips areas - every area is always collected so "
        "the data is complete; use ignore_sections to hide a section of the report"
    ),
    "replatforming": (
        "the Replatforming Readiness Report is always computed now; it is hidden "
        "by listing 'replatforming' in ignore_sections, and shown by removing it"
    ),
}

# Sections of the HTML report, by their anchor id.
REPORT_SECTIONS = {
    "summary",
    "infrastructure",
    "consumption",
    "design",
    "extensibility",
    "governance",
    "replatforming",
    "system",
}


@dataclass
class RunConfig:
    url: str = ""
    username: str | None = None
    password: str | None = None
    domain: str | None = None
    refresh_token: str | None = None
    insecure: bool = False
    ca_bundle: str | None = None
    output: str | None = None
    json_path: str | None = None
    compare_path: str | None = None
    projects: list[str] = field(default_factory=list)
    timeout: int = 60
    retries: int = DEFAULT_RETRIES
    page_size: int = 100
    max_rows_per_finding: int = 500
    include_system_subscriptions: bool = False
    pedantic: bool = False
    request_history: bool = False
    request_history_limit: int = 0
    group_membership: bool = True
    ignore_findings: list[str] = field(default_factory=list)
    ignore_sections: list[str] = field(default_factory=list)
    redact: bool = False
    redact_output: str | None = None
    redact_classes: list[str] = field(default_factory=lambda: list(DEFAULT_CLASSES))
    redact_extra: list[str] = field(default_factory=list)
    redact_key: str | None = None
    verbosity: int = 0

    @property
    def verify(self) -> bool | str:
        if self.insecure:
            return False
        if self.ca_bundle:
            return self.ca_bundle
        return True

    @classmethod
    def load(cls, args) -> RunConfig:
        """Merge argparse namespace, environment and optional YAML config file."""
        cfg = cls()

        file_values = _load_config_file(args.config)

        def pick(cli_value, env_name: str | None, file_key: str, default):
            # argparse leaves unset flags at None ([] for repeatables); an
            # explicit 0 must count as set - 0 == False in Python, so the old
            # membership test silently swallowed --timeout 0 and friends
            # before validation could reject them.
            if cli_value is not None and cli_value != []:
                return cli_value
            if env_name and os.environ.get(env_name):
                return os.environ[env_name]
            if file_key in file_values and file_values[file_key] is not None:
                return file_values[file_key]
            return default

        def listy(value) -> list:
            # A yaml scalar where a list is expected (projects: myproject)
            # used to be exploded into characters by list(), silently
            # filtering the report down to nothing.
            return [value] if isinstance(value, str) else list(value or [])

        cfg.url = str(pick(args.url, "VCF_URL", "url", "")).rstrip("/")
        cfg.username = pick(args.username, "VCF_USERNAME", "username", None)
        cfg.domain = pick(args.domain, "VCF_DOMAIN", "domain", None)
        cfg.refresh_token = pick(args.refresh_token, "VCF_REFRESH_TOKEN", "refresh_token", None)
        if "refresh_token" in file_values and file_values["refresh_token"]:
            log.warning(
                "refresh_token found in config file; prefer the VCF_REFRESH_TOKEN "
                "environment variable so the token is not stored on disk"
            )
        # Password is intentionally NOT read from the config file.
        cfg.password = os.environ.get("VCF_PASSWORD") or None
        # The same mid-migration trap as the config file rename: an ARIA_*
        # variable left in the shell is not read, and a run without it fails
        # with "URL is required", which says nothing about why.
        stale = sorted(k for k in os.environ if k.startswith("ARIA_"))
        if stale:
            log.warning(
                "%s no longer read since the rename to VCF_*; rename to be picked up",
                ", ".join(stale),
            )

        # TLS trust resolves as a pair per source level: a CLI choice of
        # either flag wins over BOTH file keys. Independently picked values
        # let a leftover `insecure: true` in the yaml silently defeat an
        # explicit --ca-bundle - the opposite of what was typed.
        if args.insecure is not None or args.ca_bundle is not None:
            cfg.insecure = bool(args.insecure)
            cfg.ca_bundle = args.ca_bundle
        elif os.environ.get("VCF_CA_BUNDLE"):
            cfg.insecure = False
            cfg.ca_bundle = os.environ["VCF_CA_BUNDLE"]
        else:
            cfg.insecure = bool(file_values.get("insecure") or False)
            cfg.ca_bundle = file_values.get("ca_bundle")
        if cfg.insecure and cfg.ca_bundle:
            log.warning(
                "both insecure and ca_bundle are set; insecure wins and TLS verification is OFF"
            )
        cfg.output = pick(args.output, None, "output", None)
        cfg.json_path = pick(args.json, None, "json", None)
        cfg.compare_path = pick(args.compare, None, "compare", None)
        cfg.projects = listy(pick(args.project, None, "projects", []))
        cfg.timeout = int(pick(args.timeout, None, "timeout", 60))
        cfg.retries = int(pick(args.retries, None, "retries", DEFAULT_RETRIES))
        cfg.page_size = int(pick(args.page_size, None, "page_size", 100))
        cfg.max_rows_per_finding = int(
            pick(args.max_rows_per_finding, None, "max_rows_per_finding", 500)
        )
        cfg.include_system_subscriptions = bool(
            pick(args.include_system_subscriptions, None, "include_system_subscriptions", False)
        )
        cfg.pedantic = bool(pick(args.pedantic, None, "pedantic", False))
        cfg.request_history = bool(pick(args.request_history, None, "request_history", False))
        # 0 means the collector's own backstop; a value here is a deliberate
        # trial run over part of the estate.
        cfg.request_history_limit = int(
            pick(args.request_history_limit, None, "request_history_limit", 0)
        )
        # On by default: it costs roughly one call per group a project grants
        # to, and without it most owners on an AD estate cannot be resolved.
        # The flag is a negation, so it cannot go through pick() - that would
        # read "skip this" as the value of "do this".
        cfg.group_membership = bool(pick(None, None, "group_membership", True))
        if args.no_group_membership:
            cfg.group_membership = False
        # Ids are matched upper-case: a config saying dep-002 must work.
        cfg.ignore_findings = sorted(
            {
                str(i).strip().upper()
                for i in listy(pick(args.ignore_finding, None, "ignore_findings", []))
                if str(i).strip()
            }
        )
        cfg.ignore_sections = sorted(
            {
                str(i).strip().lower()
                for i in listy(pick(args.ignore_section, None, "ignore_sections", []))
                if str(i).strip()
            }
        )
        cfg.redact = bool(pick(args.redact, None, "redact", False))
        cfg.redact_output = pick(args.redact_output, None, "redact_output", None)
        cfg.redact_key = pick(args.redact_key, None, "redact_key", None)
        cfg.redact_extra = [
            str(e).strip()
            for e in listy(pick(args.redact_extra, None, "redact_extra", []))
            if str(e).strip()
        ]
        classes, unknown_classes = normalise_classes(
            listy(pick(args.redact_class, None, "redact_classes", list(DEFAULT_CLASSES)))
        )
        if unknown_classes:
            log.warning(
                "Unknown redact_classes entries ignored: %s (valid: %s)",
                ", ".join(unknown_classes),
                ", ".join(CLASSES),
            )
        # An empty list after filtering is a configuration mistake with a
        # dangerous result - a "redacted" report that redacts nothing - so it
        # falls back to the default set rather than to nothing.
        if not classes:
            if unknown_classes:
                log.warning("no valid redact_classes left; using the default set")
            classes = list(DEFAULT_CLASSES)
        cfg.redact_classes = classes
        cfg.verbosity = args.verbose

        unknown_sections = set(cfg.ignore_sections) - REPORT_SECTIONS
        if unknown_sections:
            log.warning(
                "Unknown ignore_sections entries ignored: %s (valid: %s)",
                ", ".join(sorted(unknown_sections)),
                ", ".join(sorted(REPORT_SECTIONS)),
            )
            cfg.ignore_sections = [s for s in cfg.ignore_sections if s in REPORT_SECTIONS]
        return cfg

    def validate(self) -> list[str]:
        errors = []
        if not self.url:
            errors.append("URL is required (--url, VCF_URL or 'url' in the config file)")
        elif not self.url.startswith(("http://", "https://")):
            errors.append(f"URL must start with http:// or https:// (got {self.url!r})")
        elif self.url.startswith("http://"):
            log.warning("http:// URL: credentials and tokens will travel unencrypted")
        if not self.username and not self.refresh_token:
            errors.append(
                "credentials required: --username (password will be prompted) "
                "or --refresh-token / VCF_REFRESH_TOKEN"
            )
        if self.timeout < 1:
            errors.append("timeout must be at least 1 second")
        if self.retries < 0:
            errors.append("retries cannot be negative (0 means try each call once)")
        if self.max_rows_per_finding < 1:
            errors.append("max_rows_per_finding must be at least 1")
        if self.redact_output and not self.redact:
            errors.append("redact_output is set but redaction is off (--redact / redact: true)")
        if self.redact_key and not self.redact:
            errors.append("redact_key is set but redaction is off (--redact / redact: true)")
        # Two outputs at one path means the second silently overwrites the
        # first, and the pairing that matters most here is the redacted copy
        # landing on the report it was made from.
        # Resolved before comparison: reports/x.html and ./reports/x.html are
        # one file, and the pairing this exists to stop - the redacted copy
        # landing on the report it was made from - is exactly where somebody
        # types the same path two ways.
        written = [
            Path(p).resolve()
            for p in (self.output, self.json_path, self.redact_output, self.redact_key)
            if p
        ]
        if len(set(written)) != len(written):
            errors.append(
                "output, json, redact_output and redact_key must be different files "
                "(one would overwrite another)"
            )
        return errors


def _load_config_file(explicit_path: str | None) -> dict:
    if explicit_path:
        path = Path(explicit_path)
        if not path.is_file():
            raise FileNotFoundError(f"config file not found: {explicit_path}")
    else:
        path = next((p for p in map(Path, DEFAULT_CONFIG_FILES) if p.is_file()), None)
        if path is None:
            legacy = Path("aria-automation-assessment-tool.yaml")
            if legacy.is_file():
                # The mid-migration trap after the config.yaml rename: the
                # old file sits there looking authoritative and the run fails
                # with "URL is required", which says nothing about why.
                log.warning(
                    "found %s, which is no longer read since the rename to "
                    "config.yaml; rename it to be picked up",
                    legacy,
                )
            return {}
    with open(path, encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            # Surfaces as the cli's clean one-line error, not a traceback.
            raise ValueError(f"config file {path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"config file {path} must contain a YAML mapping")
    if "password" in data:
        log.warning(
            "'password' in the config file is not supported and is ignored; "
            "the password is prompted or read from VCF_PASSWORD"
        )
        data.pop("password")
    for key, replacement in RETIRED_KEYS.items():
        if key in data:
            log.warning("'%s' in the config file is no longer used: %s", key, replacement)
            data.pop(key)
    unknown = set(data) - CONFIG_KEYS
    if unknown:
        log.warning("Unknown config keys ignored: %s", ", ".join(sorted(unknown)))
    log.info("Loaded config from %s", path)
    return data
