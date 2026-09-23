"""Pseudonymisation of a finished assessment, for a report shared outside the
organisation.

The design rests on three rules, in order of importance:

* The findings must not change. Redaction runs *after* the checks, over a copy
  of the finished assessment, so a redacted report says exactly what the
  unredacted one says with different words in the name columns. Redacting
  before the checks would quietly alter tag matching, built-in classification
  and every other rule that reads a real value.
* One real value gets one alias, everywhere it appears. Names are embedded in
  finding prose ("nothing consumes tag env:prod"), in diagram sources and in
  table cells, so a per-field replacement would leave the prose intact and
  make the tables unreadable at the same time. Substitution is textual, driven
  by a map learned from the whole assessment before anything is rewritten.
* Silence is not evidence. Nothing here can prove a report carries no
  identifying value, so `audit()` re-reads the rendered HTML looking for every
  value it knows about. A hit means a path was missed, and the caller refuses
  to write the file rather than hand over a document that only looks redacted.

What gets replaced is chosen by class - identity, hosts, tags, names, ids -
and the first three are on by default. Object names stay readable unless
`names` is asked for, because most estates need the findings discussable by
name; whether that is safe depends on how this estate names things, which is
configuration rather than a default anybody should inherit blindly.

Over-redaction is possible and deliberate: a tag value that is also an
ordinary word is replaced wherever it stands as a whole token, including
inside recommendation prose. A mangled sentence is a cosmetic fault; a leaked
value is not.
"""

from __future__ import annotations

import copy
import html as html_module
import logging
import re
from typing import Any

from .identity_map import PROJECT_ROLES
from .models import AffectedObject, AssessmentData, Finding
from .tagutil import normalize_tag

log = logging.getLogger(__name__)

CLASSES = ("identity", "hosts", "tags", "names", "ids")
DEFAULT_CLASSES = ("identity", "hosts", "tags")

# Reserved by RFC 6761 and RFC 5737, so an alias can never resolve to anything
# real and reads as obviously synthetic to whoever receives the report.
ALIAS_TLD = "invalid"
TEST_NET_BLOCKS = ("192.0.2", "198.51.100", "203.0.113")
# The documentation blocks hold 762 addresses between them, which a fabric
# inventory passes on its own: a live run exhausted them and collapsed every
# address after that onto one alias, so two machines read as one host.
# 198.18.0.0/15 is kept for benchmarking by RFC 2544 and listed as neither
# routable nor forwardable in RFC 6890, so it can no more belong to somebody
# than TEST-NET can, and it carries another 130,048 addresses.
BENCHMARK_BLOCKS = tuple(f"198.{second}.{third}" for second in (18, 19) for third in range(256))
ALIAS_BLOCKS = TEST_NET_BLOCKS + BENCHMARK_BLOCKS
IGNORED_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}  # noqa: S104

# A value is replaced only as a whole token. Dots and hyphens count as part of
# the token, so "corp.local" is not rewritten inside "vra.corp.local" - the
# longer name owns that occurrence and carries its own alias.
_EDGE = r"[\w.-]"
_LEFT = rf"(?<!{_EDGE})"
_RIGHT = rf"(?!{_EDGE})"

UPN_RE = re.compile(
    # name@domain, plus the name@domain@domain form the project service uses
    # for group principals - its own schema documents that convention.
    rf"{_LEFT}([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+?)(@\2)?{_RIGHT}"
)
NTLM_RE = re.compile(rf"(?<![\w.\\-])([A-Za-z0-9][\w.-]*)\\([A-Za-z0-9][\w.$-]*){_RIGHT}")
UNC_RE = re.compile(r"\\\\([A-Za-z0-9][\w.-]*)")
URL_RE = re.compile(
    r"(?i)\b(https?|ftps?|ldaps?)://(?:([^/@\s]+)@)?([A-Za-z0-9._-]+)(?=[:/?#]|[\s'\"<>)}]|$)"
)
IP_RE = re.compile(rf"{_LEFT}(\d{{1,3}}(?:\.\d{{1,3}}){{3}}){_RIGHT}")
UUID_RE = re.compile(
    r"(?<![\w-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![\w-])", re.I
)

# Keys whose value names a person or a group, wherever they appear in the
# collected documents. Policy definitions and identity records vary enough
# between builds that walking by key name beats listing paths.
PRINCIPAL_KEYS = frozenset(
    {
        "acct",
        "approvers",
        "authorities",
        "createdby",
        "email",
        "emailaddress",
        "lastupdatedby",
        "members",
        "orgowner",
        "ownedby",
        "owner",
        "principal",
        "requestedby",
        "updatedby",
        "user",
        "username",
    }
)
# "USER:" / "GROUP:" prefixes on day-2 policy authorities and approver lists.
_AUTHORITY_PREFIX = re.compile(r"(?i)^(USER|GROUP|ROLE)\s*:\s*")
# The tool's own stand-ins for an identity it does not have: "(refresh token)"
# where a run authenticated without a username, "(unknown)" where a deployment
# records nobody. Parentheses are how this codebase writes "not a name".
PLACEHOLDER_RE = re.compile(r"\(.+\)")

# Where a name is authoritative, by (raw area, collection), so the alias says
# what kind of object it stands for. Anything unlisted falls back to Object.
NAME_LABELS = {
    ("blueprints", "blueprints"): "Template",
    ("blueprints", "custom_resource_actions"): "Resource Action",
    ("blueprints", "custom_resource_types"): "Custom Resource",
    ("blueprints", "property_groups"): "Property Group",
    ("catalog", "items"): "Catalog Item",
    ("catalog", "sources"): "Catalog Source",
    ("deployments", "deleted"): "Deployment",
    ("deployments", "deployments"): "Deployment",
    ("extensibility", "abx_actions"): "ABX Action",
    ("extensibility", "subscriptions"): "Subscription",
    ("governance", "approval_policies"): "Approval Policy",
    ("governance", "policies"): "Policy",
    ("infrastructure", "cloud_accounts"): "Cloud Account",
    ("infrastructure", "fabric_computes"): "Compute",
    ("infrastructure", "fabric_networks"): "Network",
    ("infrastructure", "flavor_profiles"): "Flavor Profile",
    ("infrastructure", "image_profiles"): "Image Profile",
    ("infrastructure", "integrations"): "Integration",
    ("infrastructure", "network_profiles"): "Network Profile",
    ("infrastructure", "projects"): "Project",
    ("infrastructure", "naming_profiles"): "Naming Profile",
    ("infrastructure", "regions"): "Region",
    ("infrastructure", "storage_profiles"): "Storage Profile",
    ("infrastructure", "zones"): "Cloud Zone",
    ("vro", "actions"): "vRO Action",
    ("vro", "workflows"): "Workflow",
}
# Keys that reference a name owned elsewhere. They matter on their own: the
# object referenced may have been filtered out of this run, or may live on a
# system this run never inventoried.
REFERENCE_NAME_KEYS = {
    "actionname": "ABX Action",
    "blueprintname": "Template",
    "deploymentname": "Deployment",
    # On vSphere this is the datacenter's own name, which is why it answers to
    # the names class as well as to ids - it is read as a label, not an id.
    "externalregionid": "Region",
    "item_name": "Catalog Item",
    "itemname": "Catalog Item",
    "policyname": "Policy",
    "projectname": "Project",
    "runnablename": "Runnable",
    "sourcename": "Catalog Source",
}
NAME_KEYS = frozenset({"name", "displayname", "fqn"})
TAG_KEYS = frozenset({"tags", "tagstomatch", "tag", "expression"})
# Identifiers of objects in this estate. Deliberately NOT here: typeId,
# eventTopicId and the other platform constants, which name a product concept
# rather than anything of this estate's, and which the report groups and
# labels by - aliasing those would turn the policy sections into nonsense
# without hiding a thing. externalRegionId is here because on vSphere it
# carries a datacenter's own name.
ID_KEYS = frozenset(
    {
        "actionid",
        "blueprintid",
        "catalogitemid",
        "deploymentid",
        "externalregionid",
        "groupid",
        "id",
        "itemid",
        "orgid",
        "parentresourceid",
        "policyid",
        "projectid",
        "resourceid",
        "runnableid",
        "sourceid",
    }
)

# Maps whose KEYS are estate data rather than field names. Everywhere else a
# dictionary key is part of the document schema and must survive untouched -
# one fixture tag is spelled "no:such:tag", and rewriting keys wholesale
# renamed the "tag" field itself out from under the code that reads it.
KEYED_MAPS = frozenset(
    {
        "blueprint_names",
        "by_action",
        "capability_tags",
        "project_names",
        "vro_workflow_names",
        "zone_compute_counts",
    }
)

# Below this length a value cannot be told apart from ordinary prose, and
# replacing it would rewrite the report rather than redact it.
MIN_ATOM = 2
MIN_FREE_TEXT_ATOM = 3
MIN_AUDIT_ATOM = 4

# Values per compiled alternation. Big enough that a whole estate is a handful
# of passes, small enough that no single pattern is one the regex engine
# refuses to compile.
_CHUNK = 500

# Words that are ordinary English as often as they are somebody tag. They
# still get an alias, but only where the whole string is the value: replacing
# "no" inside running prose would rewrite the report rather than redact it.
COMMON_WORDS = frozenset(
    {
        "all",
        "and",
        "any",
        "are",
        "but",
        "can",
        "for",
        "has",
        "have",
        "high",
        "how",
        "its",
        "key",
        "low",
        "med",
        "name",
        "new",
        "none",
        "not",
        "off",
        "old",
        "one",
        "out",
        "raw",
        "set",
        "tag",
        "the",
        "two",
        "type",
        "use",
        "value",
        "was",
        "who",
        "why",
        "yes",
        "no",
    }
)

# Words the report writes on its own account rather than reading from the
# estate. Every owner's row names the project role that grants them access,
# and the renderer works that out after redaction has run, so the word lands
# on the page whatever the redactor did to the data underneath.
#
# An estate whose assessment account is called "administrator", or whose
# policies address an audience by role, would otherwise learn one of these as
# a person: the report's own role labels would be rewritten into somebody's
# alias, and the audit - which reads the finished page, generated words and
# all - would report the report's own vocabulary as a leak and refuse to write
# the file. A live run failed exactly that way on "administrator" and
# "member". They still get an alias wherever one stands alone as a whole
# value, so a Run-as cell naming the account is still replaced.
REPORT_WORDS = frozenset(word for _field, word in PROJECT_ROLES)

# How each class reads in the report's own header, for a reader who has to
# understand what they are looking at without the tool's documentation.
CLASS_WORDS = {
    "identity": "user and group names",
    "hosts": "host names, URLs and addresses",
    "tags": "capability tags",
    "names": "object names",
    "ids": "internal identifiers",
    "extra": "strings named in the run configuration",
}


def normalise_classes(values) -> tuple[list[str], list[str]]:
    """(classes to apply, names that are not classes) from whatever was configured."""
    wanted: list[str] = []
    unknown: list[str] = []
    for value in values or ():
        name = str(value).strip().lower()
        if not name:
            continue
        if name in CLASSES:
            if name not in wanted:
                wanted.append(name)
        elif name not in unknown:
            unknown.append(name)
    return wanted, unknown


class Redactor:
    """Learns identifying values from an assessment, then rewrites a copy.

    Learning is a separate pass on purpose: every value has to be known before
    the first string is rewritten, or the same person reads as person03 in a
    table and person07 in the finding that names them.
    """

    def __init__(self, classes=DEFAULT_CLASSES, extra=()):
        self.classes = set(classes or ())
        self._alias: dict[str, str] = {}  # real value, lower-cased -> alias
        self._kind: dict[str, str] = {}  # real value, lower-cased -> class
        self._real: dict[str, str] = {}  # real value, lower-cased -> as first seen
        self._emitted: set[str] = set()  # every alias handed out, lower-cased
        self._counters: dict[str, int] = {}
        self._domains: list[str] = []  # DNS suffixes seen, for sibling hosts
        self._domain_re: re.Pattern | None = None
        self._known_res: list[re.Pattern] = []
        self._extra = [str(e).strip() for e in extra or () if str(e).strip()]
        self._extra_keys: set[str] = set()
        self._exact_only: set[str] = set()  # replaced only as a whole string
        self._extra_re: re.Pattern | None = None
        self._noted: set[str] = set()  # conditions already reported once
        self._sealed = False

    # ------------------------------------------------------------------ learn

    def learn(self, data: AssessmentData) -> None:
        """Index every identifying value the finished assessment carries."""
        self._learn_node(data.meta, key="meta", area="meta")
        for area, payload in (data.raw or {}).items():
            self._learn_node(payload, key=str(area), area=str(area))
        self._learn_node(data.derived, key="derived", area="derived")
        self._learn_node(data.errors, key="errors", area="errors")
        for finding in data.findings or []:
            self._learn_text(finding.title)
            self._learn_text(finding.recommendation)
            for obj in finding.affected:
                self._learn_text(obj.name)
                self._learn_text(obj.detail or "")
                self._learn_text(obj.project or "")
                # Some affected ids are composed by the check itself
                # ("infrastructure / zone-computes:<name>") rather than taken
                # from a document, so they are worth their own look.
                self._learn_text(obj.id)
        self._seal()

    def _learn_node(self, node: Any, key: str, area: str, collection: str = "") -> None:
        if isinstance(node, dict):
            if "tags" in self.classes:
                if key.lower() in TAG_KEYS and ("key" in node or "value" in node):
                    # A tag document, {"key": "env", "value": "prod"}. Its two
                    # halves render in columns of their own and the composite
                    # renders everywhere else, so both are learned here.
                    self._learn_tag(normalize_tag(node))
                elif key == "capability_tags":
                    # The one map the report keys by tag rather than by id.
                    for child_key in node:
                        if isinstance(child_key, str):
                            self._learn_tag(child_key)
                elif key == "inputs" and area == "blueprints":
                    # A template input that a constraint reads offers tags,
                    # and the placement diagrams print them beside the
                    # constraint, so they are learned as tags too.
                    for value in list(node.get("values") or ()) + [node.get("default")]:
                        if isinstance(value, str):
                            self._learn_tag(value)
            for child_key, value in node.items():
                if isinstance(child_key, str):
                    self._learn_text(child_key)
                # The collection is the key directly under a raw area - the
                # level that says what kind of object these documents are.
                child_collection = collection or (
                    str(child_key) if _is_area(area) and isinstance(value, list) else ""
                )
                self._learn_node(value, key=str(child_key), area=area, collection=child_collection)
            return
        if isinstance(node, (list, tuple)):
            for item in node:
                self._learn_node(item, key=key, area=area, collection=collection)
            return
        if isinstance(node, str) and node.strip():
            self._learn_value(node, key.lower(), area, collection)

    def _learn_value(self, value: str, key: str, area: str, collection: str) -> None:
        if key == "hostname" and "hosts" in self.classes:
            self.host_alias(value)
        if "identity" in self.classes:
            if key in PRINCIPAL_KEYS or (area == "identity" and key in NAME_KEYS):
                self.principal_alias(_principal_in(value))
            elif area == "meta" and key == "identity":
                self.principal_alias(value)
        if "tags" in self.classes and key in TAG_KEYS:
            self._learn_tag(value)
        if "ids" in self.classes and key in ID_KEYS:
            self._alias_for(value, "ids", "id")
        if "names" in self.classes:
            label = REFERENCE_NAME_KEYS.get(key)
            if key in NAME_KEYS:
                label = NAME_LABELS.get((area, collection), label or "Object")
            if label:
                self._alias_for(value, "names", label, space=True)
        self._learn_text(value)

    def _learn_tag(self, value: str) -> None:
        """A tag arrives as "key:value", as a bare key, or as one half of a
        {key, value} document.

        The composite and each half are learned separately: the tables render
        the halves in columns of their own, while findings and diagrams speak
        the composite. A value may itself contain a colon, so the split is on
        the first one only.
        """
        text = value.strip().lstrip("!")
        if text.endswith((":hard", ":soft")):
            text = text.rpartition(":")[0]
        # The ${input.x} half of a dynamic constraint names an input, not a
        # tag, and the report reads better keeping it.
        if not text or "${" in text:
            return
        key, sep, tag_value = text.partition(":")
        if sep:
            self._alias_for(text, "tags", "tag")
        for part in (key, tag_value) if sep else (key,):
            if part.strip():
                self._alias_for(part.strip(), "tags", "tag")

    def _learn_text(self, text: str) -> None:
        """Pattern-driven learning: what a key name never announces."""
        if not text or not isinstance(text, str):
            return
        # https://svc:secret@host reads as a UPN to the identity pattern, and
        # learning it as one would turn a password into somebody's alias and
        # keep it in the report. URLs are claimed first and their credentials
        # are dropped whole, never aliased.
        urls = [m.span() for m in URL_RE.finditer(text)]
        if "identity" in self.classes:
            for match in UPN_RE.finditer(text):
                if not _inside(match.start(), urls):
                    self.principal_alias(match.group(0))
            for match in NTLM_RE.finditer(text):
                if not _inside(match.start(), urls):
                    self.principal_alias(match.group(0))
        if "hosts" in self.classes:
            for match in URL_RE.finditer(text):
                self.host_alias(match.group(3))
            for match in UNC_RE.finditer(text):
                self.host_alias(match.group(1))
            for match in IP_RE.finditer(text):
                self.ip_alias(match.group(1))
        if "ids" in self.classes:
            for match in UUID_RE.finditer(text):
                self._alias_for(match.group(0), "ids", "id")

    def _seal(self) -> None:
        """Compile the substitution patterns. After this, only the pattern
        passes may resolve a value, and they allocate as they go."""
        for pattern in self._extra:
            self._register(pattern, self._next("redacted"), "extra")
            self._extra_keys.add(pattern.lower())
        if self._extra_keys:
            # Configured strings match anywhere, not just as whole tokens:
            # they exist to catch a name inside a longer identifier, which is
            # exactly where the token rule would let it through.
            ordered = sorted(self._extra_keys, key=len, reverse=True)
            self._extra_re = re.compile("|".join(re.escape(e) for e in ordered), re.I)
        skip = self._extra_keys | self._exact_only
        values = sorted(
            (v for low, v in self._real.items() if low not in skip),
            key=lambda v: (-len(v), v.lower()),
        )
        # Chunked so thousands of names cannot produce one pattern the regex
        # engine refuses. Longest first within and across chunks, so a domain
        # never takes an occurrence away from a host underneath it.
        for start in range(0, len(values), _CHUNK):
            chunk = values[start : start + _CHUNK]
            alternation = "|".join(re.escape(v) for v in chunk)
            self._known_res.append(re.compile(rf"{_LEFT}({alternation}){_RIGHT}", re.I))
        if self._domains:
            suffixes = "|".join(re.escape(d) for d in sorted(self._domains, key=len, reverse=True))
            self._domain_re = re.compile(
                rf"{_LEFT}([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:{suffixes})){_RIGHT}", re.I
            )
        self._sealed = True

    # ------------------------------------------------------------- allocation

    def _alias_for(self, real: str, klass: str, kind: str, space: bool = False) -> str:
        """The stable alias for one real value, allocated on first sight."""
        value = (real or "").strip().strip(".-")
        if len(value) < MIN_ATOM:
            return real
        low = value.lower()
        if low in self._alias:
            return self._alias[low]
        if low in self._emitted or not _free_text_safe(low):
            # Two different reasons to replace this value only where it is the
            # whole string. An ordinary word ("no", "high") would rewrite the
            # report's own prose. A value spelled like an alias already handed
            # out - host01 is both this scheme's alias and an entirely
            # ordinary host name - cannot join the free-text pass either: one
            # chunk would produce that alias and the next would rewrite it,
            # leaving two objects reading as one. Both still get an alias and
            # both stay in the audit's sights; refusing to register them was a
            # silent leak the audit could not see.
            if low in self._emitted:
                log.info("redaction: %r is spelled like an alias already in use", value)
            elif low in REPORT_WORDS:
                log.info(
                    "redaction: %r is a word the report writes itself, so it is replaced "
                    "only where it stands alone as a whole value",
                    value,
                )
            self._exact_only.add(low)
        return self._register(value, self._next(kind, space, avoid=low), klass)

    def _next(self, kind: str, space: bool = False, avoid: str = "") -> str:
        while True:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            alias = f"{kind}{' ' if space else ''}{self._counters[kind]:02d}"
            # Never mint an alias that is a real value in this estate - the one
            # being registered included, since it is not in the map yet.
            if alias.lower() not in self._alias and alias.lower() != avoid:
                return alias

    def principal_alias(self, value: str) -> str:
        """Alias for a person or a group, keeping the shape of the original.

        Shape carries meaning a reader uses: a UPN says the identity source is
        a directory, DOMAIN\\user says it is not, and the doubled
        name@domain@domain form says the grant came from a project document.
        """
        value = (value or "").strip()
        if not value or "identity" not in self.classes:
            return value
        if PLACEHOLDER_RE.fullmatch(value):
            # "(refresh token)", "(unknown)": the tool's own words for "nobody
            # was named". Aliasing one puts a person's name where the report
            # means to say there is nobody.
            return value
        low = value.lower()
        if low in self._alias:
            return self._alias[low]
        ntlm = NTLM_RE.fullmatch(value)
        if ntlm:
            domain = self._alias_for(ntlm.group(1), "identity", "domain").upper()
            person = self._alias_for(ntlm.group(2), "identity", "person")
            return self._register(value, f"{domain}\\{person}", "identity")
        upn = UPN_RE.fullmatch(value)
        if upn:
            local = self._alias_for(upn.group(1), "identity", "person")
            domain = self._domain_alias(upn.group(2))
            doubled = f"@{domain}" if upn.group(3) else ""
            return self._register(value, f"{local}@{domain}{doubled}", "identity")
        return self._alias_for(value, "identity", "person")

    def host_alias(self, value: str) -> str:
        """Alias for one host name or address, keeping it under its domain."""
        value = (value or "").strip().strip(".")
        if not value or "hosts" not in self.classes:
            return value
        if IP_RE.fullmatch(value):
            return self.ip_alias(value)
        low = value.lower()
        if low in self._alias:
            return self._alias[low]
        host, _, domain = value.partition(".")
        if domain:
            alias = f"{self._alias_for(host, 'hosts', 'host')}.{self._domain_alias(domain)}"
            return self._register(value, alias, "hosts")
        return self._alias_for(value, "hosts", "host")

    def ip_alias(self, value: str) -> str:
        octets = value.split(".")
        if value in IGNORED_IPS or any(not o.isdigit() or int(o) > 255 for o in octets):
            return value
        if "hosts" not in self.classes:
            return value
        low = value.lower()
        if low in self._alias:
            return self._alias[low]
        self._counters["ip"] = self._counters.get("ip", 0) + 1
        block, host = divmod(self._counters["ip"] - 1, 254)
        if block >= len(ALIAS_BLOCKS):
            # Past 130,810 addresses nobody is reading addresses. They collapse
            # onto one rather than spilling into a range that might belong to
            # somebody real - which does cost the reader something, so it is
            # worth saying out loud.
            if self._once("exhausted"):
                log.warning(
                    "redaction: this estate has more than %d addresses, which is more than "
                    "the reserved ranges hold; the rest share one alias, so hosts that "
                    "differ read alike in the redacted report",
                    len(ALIAS_BLOCKS) * 254,
                )
            return self._register(value, f"{ALIAS_BLOCKS[-1]}.255", "hosts")
        if block >= len(TEST_NET_BLOCKS) and self._once("benchmark"):
            # Nothing is wrong here and there is nothing to do about it, so it
            # is a note about the run rather than a warning: an operator who
            # reads WARNING as "look into this" would find nothing to look at.
            log.info(
                "redaction: this estate has more than %d addresses, so the aliases for the "
                "rest come from 198.18.0.0/15 - reserved and unroutable like the "
                "documentation blocks, and every address still gets its own",
                len(TEST_NET_BLOCKS) * 254,
            )
        return self._register(value, f"{ALIAS_BLOCKS[block]}.{host + 1}", "hosts")

    def _once(self, key: str) -> bool:
        """True the first time a condition is met, so a note about a whole run
        is one line rather than one line per value."""
        if key in self._noted:
            return False
        self._noted.add(key)
        return True

    def _domain_alias(self, domain: str) -> str:
        """Alias for a DNS suffix, remembered so sibling hosts are caught even
        where this run never saw them spelled out."""
        domain = (domain or "").strip().strip(".")
        if not domain:
            return domain
        low = domain.lower()
        if low in self._alias:
            return self._alias[low]
        if "." in low and not self._sealed:
            self._domains.append(low)
        return self._register(domain, f"{self._next('domain')}.{ALIAS_TLD}", "hosts")

    def _register(self, real: str, alias: str, klass: str) -> str:
        low = real.lower()
        self._alias[low] = alias
        self._kind[low] = klass
        self._real[low] = real
        self._emitted.add(alias.lower())
        return alias

    # ------------------------------------------------------------- substitute

    def text(self, value: str) -> str:
        """One string with every known value and matching pattern replaced."""
        if not value or not isinstance(value, str):
            return value
        # A value that is the whole string resolves directly. This is where a
        # short or ordinary-looking tag ("no", "high") is replaced: as a cell
        # of its own it is unambiguous, inside a sentence it is not.
        exact = self._alias.get(value.strip().lower())
        if exact is not None:
            return exact
        out = value
        if self._extra_re is not None:
            # The empty string is a deliberate fallback, not an oversight. Every
            # configured string is registered in _seal, so a miss means the
            # match's own lower() differs from the pattern's - which Unicode
            # case folding can do under re.I. Dropping the text is the safe
            # answer for a redactor: a mangled sentence is cosmetic, and
            # returning the match would hand back the value the operator named
            # precisely because it must not appear.
            out = self._extra_re.sub(lambda m: self._alias.get(m.group(0).lower(), ""), out)
        # URLs go before anything else for the same reason they do when
        # learning: the credentials in one must be dropped, not aliased into
        # something that reads like a person.
        if "hosts" in self.classes:
            out = URL_RE.sub(self._sub_url, out)
        for pattern in self._known_res:
            out = pattern.sub(lambda m: self._alias.get(m.group(1).lower(), m.group(1)), out)
        if "hosts" in self.classes:
            out = UNC_RE.sub(lambda m: "\\\\" + self._maybe(m.group(1), self.host_alias), out)
            if self._domain_re is not None:
                out = self._domain_re.sub(lambda m: self._maybe(m.group(1), self.host_alias), out)
            out = IP_RE.sub(lambda m: self._maybe(m.group(1), self.ip_alias), out)
        if "identity" in self.classes:
            out = UPN_RE.sub(lambda m: self._maybe(m.group(0), self.principal_alias), out)
            out = NTLM_RE.sub(lambda m: self._maybe(m.group(0), self.principal_alias), out)
        if "ids" in self.classes:
            out = UUID_RE.sub(
                lambda m: self._maybe(m.group(0), lambda v: self._alias_for(v, "ids", "id")), out
            )
        return out

    def _maybe(self, value: str, alias_fn) -> str:
        """Alias a match unless it is already one of ours: the passes run in
        sequence, and an emitted alias still looks like what it stands for."""
        if value.lower() in self._emitted:
            return value
        return alias_fn(value)

    def _sub_url(self, match: re.Match) -> str:
        scheme, userinfo, host = match.group(1), match.group(2), match.group(3)
        # Credentials in a URL are the one thing that must not survive in any
        # form, so the whole userinfo goes instead of being aliased.
        alias = self._maybe(host, self.host_alias)
        if not userinfo:
            return f"{scheme}://{alias}"
        # The marker itself has to be immune to the identity pass that follows,
        # which would otherwise read "redacted@host01.domain01.invalid" as one
        # more UPN and give the marker a person's alias.
        self._emitted.add(f"redacted@{alias}".lower())
        return f"{scheme}://redacted@{alias}"

    def redact(self, data: AssessmentData) -> AssessmentData:
        """A copy of the assessment with every string rewritten."""
        out = AssessmentData()
        out.meta = self._node(data.meta)
        out.raw = self._node(data.raw)
        out.derived = self._node(data.derived)
        out.errors = self._node(data.errors)
        out.findings = [
            Finding(
                check_id=f.check_id,
                title=self.text(f.title),
                severity=f.severity,
                recommendation=self.text(f.recommendation),
                affected=[
                    AffectedObject(
                        kind=a.kind,
                        id=self.text(a.id),
                        name=self.text(a.name),
                        project=self.text(a.project) if a.project else a.project,
                        detail=self.text(a.detail) if a.detail else a.detail,
                    )
                    for a in f.affected
                ],
            )
            for f in data.findings
        ]
        return out

    def _node(self, node: Any, keyed: bool = False) -> Any:
        if isinstance(node, dict):
            # Keys are rewritten only in the maps whose keys are estate data -
            # a tag map, an id lookup - because those stop resolving when one
            # side is rewritten and the other is not. Field names are schema
            # and stay as they are, whatever an estate has named an object.
            return {
                (self.text(k) if keyed and isinstance(k, str) else k): self._node(
                    v, keyed=isinstance(k, str) and k in KEYED_MAPS
                )
                for k, v in node.items()
            }
        if isinstance(node, list):
            return [self._node(v) for v in node]
        if isinstance(node, tuple):
            return tuple(self._node(v) for v in node)
        if isinstance(node, str):
            return self.text(node)
        if node is None or isinstance(node, (int, float, bool)):
            return node
        return copy.deepcopy(node)

    # ------------------------------------------------------------------ audit

    def audit(self, html: str, allowed: str = "") -> list[dict]:
        """Every known value still present in the rendered report.

        A clean result proves nothing on its own - only this map is checked,
        and the map is only as complete as the learning pass. A dirty result
        does prove something, which is what this is for.

        `allowed` is text the report carries whatever the estate holds (the
        template's own prose). A value occurring there cannot be told apart
        from a leak, so it is skipped rather than reported as one.

        Values too short or too ordinary to tell from prose are left out: they
        would report the report itself. That is the one blind spot here, and
        it is the same set that substitution replaces only where it stands
        alone.

        One leaked stretch of text is one hit, named by the longest value
        covering it - a leaked UPN is not also reported as its local part and
        its domain, which is three lines about one mistake. A half leaking on
        its own still matches on its own.
        """
        body = _visible_text(html)
        wanted = {
            low: real
            for low, real in self._real.items()
            if low in self._extra_keys or (_free_text_safe(low) and len(real) >= MIN_AUDIT_ATOM)
        }
        counts: dict[str, int] = {}
        for pattern in self._residue_patterns(wanted):
            for match in pattern.finditer(body):
                hit = match.group(1).lower()
                counts[hit] = counts.get(hit, 0) + 1
        if counts and allowed:
            # Only what the page actually carries needs checking against the
            # template's own words, which is a far smaller set to compile.
            for pattern in self._residue_patterns({low: wanted[low] for low in counts}):
                for match in pattern.finditer(allowed):
                    counts.pop(match.group(1).lower(), None)
        hits = [
            {"class": self._kind.get(low, "?"), "value": wanted.get(low, low), "count": count}
            for low, count in counts.items()
        ]
        hits.sort(key=lambda h: (h["class"], h["value"].lower()))
        return hits

    def _residue_patterns(self, values: dict[str, str]) -> list[re.Pattern]:
        """One compiled alternation per chunk of the values to scan for.

        Scanning the page once per chunk rather than once per value is what
        keeps the audit usable at estate scale: a three-thousand value map
        took 47 seconds a value at a time and half a second this way, and the
        audit runs on every redacted report.
        """
        patterns = []
        for substring in (False, True):
            # Configured strings match inside longer words by design; every
            # other value is a whole token.
            group = sorted(
                (real for low, real in values.items() if (low in self._extra_keys) == substring),
                key=len,
                reverse=True,
            )
            for start in range(0, len(group), _CHUNK):
                alternation = "|".join(re.escape(v) for v in group[start : start + _CHUNK])
                body = f"({alternation})"
                patterns.append(re.compile(body if substring else f"{_LEFT}{body}{_RIGHT}", re.I))
        return patterns

    # ----------------------------------------------------------------- output

    def summary(self) -> dict:
        """What was replaced, for the report's own header."""
        counts: dict[str, int] = {}
        for klass in self._kind.values():
            counts[klass] = counts.get(klass, 0) + 1
        described = [CLASS_WORDS[c] for c in CLASSES if c in self.classes]
        if self._extra_keys:
            described.append(CLASS_WORDS["extra"])
        return {
            "classes": sorted(self.classes),
            "counts": counts,
            "replaced": len(self._alias),
            "described": _join_words(described),
        }

    def key_rows(self) -> list[tuple[str, str, str]]:
        """(class, alias, real value) for the mapping file kept in-house."""
        rows = [
            (self._kind.get(low, "?"), alias, self._real.get(low, low))
            for low, alias in self._alias.items()
        ]
        return sorted(rows, key=lambda row: (row[0], row[1]))


def _inside(position: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in spans)


def _principal_in(value: str) -> str:
    """The identity an authority string names, or "" where it names a role.

    A policy addresses its audience as "USER:x", "GROUP:y" or by the project
    role that holds the grant. A role is the platform's word for a kind of
    access, held by every estate alike, so aliasing one renames a concept
    rather than hiding a person - and hands the report's own role labels a
    person's alias into the bargain.
    """
    prefix = _AUTHORITY_PREFIX.match(value or "")
    if prefix and prefix.group(1).upper() == "ROLE":
        return ""
    return _AUTHORITY_PREFIX.sub("", value or "").strip()


def _free_text_safe(low: str) -> bool:
    """Whether a value may be replaced inside a longer string.

    Anything shorter than three characters, purely numeric, an ordinary
    English word or a word the report writes itself is replaced only where it
    stands alone. The alternative is a report whose prose has been rewritten
    around the estate vocabulary.
    """
    return (
        len(low) >= MIN_FREE_TEXT_ATOM
        and not low.isdigit()
        and low not in COMMON_WORDS
        and low not in REPORT_WORDS
    )


def _join_words(words: list[str]) -> str:
    # A plain comma list: several of the phrases carry their own "and", and a
    # final conjunction on top of those reads as a mistake.
    return ", ".join(words) if words else "nothing"


def _is_area(area: str) -> bool:
    return area not in ("meta", "derived", "errors")


_SCRIPT_RE = re.compile(r"(?is)<(script|style)\b.*?</\1>")
_TAG_RE = re.compile(r"(?s)<[^>]+>")


def _visible_text(html: str) -> str:
    """The report's readable text: script and style blocks dropped, markup
    replaced by whitespace, entities resolved.

    The vendored mermaid build carries its own URLs and addresses, so a
    residue scan over it reports nothing but noise. Dropping the markup with
    it costs nothing: the only data in an attribute is a check id.
    """
    return html_module.unescape(_TAG_RE.sub(" ", _SCRIPT_RE.sub(" ", html)))
