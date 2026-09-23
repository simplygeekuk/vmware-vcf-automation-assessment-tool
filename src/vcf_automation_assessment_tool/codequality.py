"""Static quality heuristics for automation code (ABX actions, blueprint YAML).

Honest scope: these are signals for a replatforming assessment, not a code
review. Python is analyzed via the ast module and pyflakes, JavaScript via
esprima, PowerShell via PowerShell's own parser when one is on the host;
anything bundled as a zip is not analyzable over the API.
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import warnings

try:  # a hard dependency, but analysis must not be what breaks a run
    import esprima
except ImportError:  # pragma: no cover
    esprima = None

log = logging.getLogger(__name__)

# Literal scans. ${...} bindings are runtime references, not hardcoding.
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
URL_RE = re.compile(r"https?://[^\s'\"`<>)}]+")
SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|bearer)\b\s*[:=]\s*"
    r"['\"]([^'\"$]{4,})['\"]"
)
IGNORED_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}  # noqa: S104

# Re-throw-only handlers for the runtimes without a real parser. JS: the whole
# catch body is "throw <the caught name>". PowerShell: the body is a bare
# "throw" (which rethrows inside catch) or "throw $_"; a rethrow catch that is
# FOLLOWED by another catch is the type-filter pattern and stays unflagged,
# hence the lookahead. Single-statement bodies only - regex cannot see deeper.
JS_RETHROW_RE = re.compile(r"catch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{\s*throw\s+\1\s*;?\s*\}")
PS_RETHROW_RE = re.compile(
    r"catch\b(?:\s*\[[^\]]+\]\s*,?)*\s*\{\s*throw(?:\s+\$_)?\s*;?\s*\}(?!\s*catch\b)",
    re.IGNORECASE,
)


def scan_literals(text: str, runtime: str | None = None) -> dict:
    """Hardcoded IPs, URLs and credential-looking assignments in source text.

    With a runtime, URLs are scanned over the source with its comment lines
    removed: a URL in a comment is a documentation pointer, a URL in code is
    environment coupling. This is the rule the blueprint scan already applies
    to YAML. IPs and credential literals keep the full-text scan - an address
    or a password sitting in a comment is still an address or a password.
    """
    ips = sorted(
        {
            m.group(1)
            for m in IP_RE.finditer(text)
            if m.group(1) not in IGNORED_IPS and all(int(o) <= 255 for o in m.group(1).split("."))
            # Skip obvious version strings picked up as dotted quads (1.2.3.4
            # inside semver-ish contexts is rare; octet>u8 already filtered).
        }
    )
    url_text = strip_comments(text, runtime) if runtime is not None else text
    urls = set()
    for match in URL_RE.finditer(url_text):
        url = match.group(0).rstrip(".,;")
        authority = re.split(r"[/#?]", url.split("://", 1)[1], maxsplit=1)[0]
        # A template expression in the authority is not a fixed endpoint.
        # The lexical match stops at }, so never report that truncated fragment.
        if "{" in authority or "$" in authority:
            continue
        # A fixed host still couples code to an endpoint when the path is
        # dynamic. Report only its literal prefix, not half an expression.
        url = re.split(r"\$?\{", url, maxsplit=1)[0]
        if authority:
            urls.add(url)
    secrets = sorted({m.group(1) for m in SECRET_RE.finditer(text)})
    return {"ips": ips, "urls": sorted(urls), "secrets": secrets}


def analyze_python(source: str) -> dict:
    """AST-based structural analysis of a Python ABX/vRO action."""
    result = {
        "parses": True,
        "parse_error": None,
        "lines": len(source.splitlines()),
        "functions": 0,
        "branches": 0,
        "has_error_handling": False,
        "bare_excepts": 0,
        "swallowed_excepts": 0,
        "reraise_only_excepts": 0,
        "uses_logging": False,
        "print_calls": 0,
        "unused_variables": [],
        "unused_imports": [],
        "undefined_names": [],
        "pyflakes_defects": [],
        "pyflakes_hygiene": [],
        "syntax_warnings": [],
        "top_level_functions": [],
        "read_input_keys": _read_input_keys(source, "python"),
        **comment_metrics(source, "python"),
    }
    # Compiling third-party source emits SyntaxWarnings ("invalid escape
    # sequence '\T'" from un-raw Windows paths, most commonly) on the
    # console, where they read as tool errors. Capture them instead: they
    # are a signal about the analyzed action, so they belong in its issue
    # list, not on stderr.
    tree = None
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            # Won't parse as Python 3 - possibly Python 2 or templated source.
            result["parses"] = False
            result["parse_error"] = "source does not parse as Python 3 (Python 2 legacy?)"
    result["syntax_warnings"] = sorted(
        {f"{w.message} (line {w.lineno})" for w in caught if issubclass(w.category, SyntaxWarning)}
    )
    if tree is None:
        return result

    result.update(_pyflakes_signals(tree))
    # Module-level definitions only: an ABX entrypoint has to be reachable as
    # a module attribute, so a nested helper of the same name proves nothing.
    result["top_level_functions"] = [
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    result["read_input_keys"] = _python_input_keys(tree)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result["functions"] += 1
        elif isinstance(node, (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.Match)):
            result["branches"] += 1
        elif isinstance(node, ast.Try):
            result["has_error_handling"] = True
            # Only the LAST handler can be a pointless re-raise: an earlier
            # "except KeyError: raise" in front of a broader handler is the
            # deliberate filter pattern (it keeps KeyError out of the generic
            # handler below). A trailing one changes nothing - the exception
            # would propagate identically without it.
            if node.handlers and _reraise_only(node.handlers[-1]):
                result["reraise_only_excepts"] += 1
        elif isinstance(node, ast.ExceptHandler):
            result["branches"] += 1
            if node.type is None:
                result["bare_excepts"] += 1
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                result["swallowed_excepts"] += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names]
            module = getattr(node, "module", "") or ""
            if "logging" in names or module.startswith("logging"):
                result["uses_logging"] = True
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "print":
                result["print_calls"] += 1
    return result


def _reraise_only(handler: ast.ExceptHandler) -> bool:
    """A handler whose whole body is "raise" or "raise e" of the caught name.

    "raise Other(...) from e" is exception translation and "raise e from None"
    suppresses context - both change behaviour, so any "from" clause opts out.
    """
    if len(handler.body) != 1 or not isinstance(handler.body[0], ast.Raise):
        return False
    stmt = handler.body[0]
    if stmt.exc is None:
        return True
    return (
        stmt.cause is None
        and isinstance(stmt.exc, ast.Name)
        and handler.name is not None
        and stmt.exc.id == handler.name
    )


# inputs["x"] / inputs['x'] / inputs.x - the three spellings across the three
# runtimes. Only literal keys are visible; a key built at runtime is invisible
# here, which is why the unread-input signal needs at least one literal read
# before it will claim anything.
INPUT_KEY_RE = re.compile(r"\$?\binputs\s*(?:\[\s*['\"](\w+)['\"]\s*\]|\.(\w+))")


def _read_input_keys(source: str, runtime: str) -> list[str]:
    """Action input names read by literal key, for the non-AST runtimes."""
    keys = {m.group(1) or m.group(2) for m in INPUT_KEY_RE.finditer(source)}
    return sorted(k for k in keys if k and k != "get")


def _python_input_keys(tree) -> list[str]:
    """Action input names read by literal key: inputs["x"] and inputs.get("x")."""
    keys: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "inputs"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            keys.add(node.slice.value)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "inputs"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            keys.add(node.args[0].value)
    return sorted(keys)


def analyze_script(source: str, runtime: str) -> dict:
    """Dispatch by runtime. This is the first pass only: JavaScript and
    PowerShell get regex heuristics here, which the collectors then upgrade
    with real parser metrics (esprima; PowerShell's own parser when one is on
    the host). Unused-variable detection stays Python-only either way - it
    needs scope analysis, which only pyflakes gives us."""
    runtime = (runtime or "").lower()
    if runtime.startswith("python"):
        return analyze_python(source)
    result = {
        "parses": None,  # not statically parsed for these runtimes
        "parse_error": None,
        "lines": len(source.splitlines()),
        "functions": None,
        "branches": None,
        "has_error_handling": bool(
            re.search(r"\btry\b[\s\S]{0,400}?\bcatch\b", source, re.IGNORECASE)
        ),
        "bare_excepts": 0,
        "swallowed_excepts": 0,
        "reraise_only_excepts": len(
            (PS_RETHROW_RE if runtime.startswith("powershell") else JS_RETHROW_RE).findall(source)
        ),
        "uses_logging": bool(
            re.search(r"Write-(Error|Warning)|console\.(error|warn)|System\.(error|warn)", source)
        ),
        "print_calls": len(re.findall(r"console\.log|Write-Host", source)),
        "unused_variables": [],
        "unused_imports": [],
        "undefined_names": [],
        "pyflakes_defects": [],
        "pyflakes_hygiene": [],
        "syntax_warnings": [],
        # No reliable way to name a JavaScript function without a parser, and
        # PowerShell fills this in from its own parser during the upgrade pass.
        "top_level_functions": [],
        "read_input_keys": _read_input_keys(source, runtime),
        **comment_metrics(source, runtime),
    }
    return result


# pyflakes messages that describe a defect rather than untidiness: code that
# is already wrong, or that does something other than what it reads as. Matched
# on the message CLASS NAME, never by attribute lookup on the messages module -
# the pin is pyflakes>=3.2 and the class list differs between versions, so a
# name that does not exist in the installed pyflakes must simply never match.
# Anything unlisted falls through to the hygiene bucket, which means a pyflakes
# upgrade can add messages without breaking collection.
PYFLAKES_DEFECTS = frozenset(
    {
        "IsLiteral",  # `x is "abc"` - identity where equality was meant
        "MultiValueRepeatedKeyLiteral",  # duplicate dict key: one value is lost
        "MultiValueRepeatedKeyVariable",
        "AssertTuple",  # assert (a, b) is always true
        "IfTuple",  # if (a, b): is always true
        "DuplicateArgument",
        "DefaultExceptNotLast",  # bare except before others: later ones are dead
        "UndefinedLocal",
        "UndefinedExport",
        "ReturnOutsideFunction",
        "YieldOutsideFunction",
        "ContinueOutsideLoop",
        "BreakOutsideLoop",
        "TwoStarredExpressions",
        "TooManyExpressionsInStarredAssignment",
        "ForwardAnnotationSyntaxError",
        "RaiseNotImplemented",  # raise NotImplemented raises TypeError
        "StringDotFormatExtraPositionalArguments",
        "StringDotFormatExtraNamedArguments",
        "StringDotFormatMissingArgument",
        "StringDotFormatUnsupportedFormatCharacter",
        "StringDotFormatInvalidFormat",
        "PercentFormatInvalidFormat",
        "PercentFormatExpectedMapping",
        "PercentFormatExpectedSequence",
        "PercentFormatExtraNamedArguments",
        "PercentFormatMissingArgument",
        "PercentFormatMixedPositionalAndNamed",
        "PercentFormatPositionalCountMismatch",
        "PercentFormatStarRequiresSequence",
        "PercentFormatUnsupportedFormatCharacter",
    }
)

# Handled by their own dedicated fields and issue strings; excluded from both
# new buckets so nothing is reported twice.
_PYFLAKES_OWN_FIELDS = frozenset({"UnusedVariable", "UnusedImport", "UndefinedName"})


def _pyflakes_signals(tree) -> dict:
    """Every pyflakes message, split by whether it describes a defect.

    Unused variables, unused imports and undefined names keep their own fields
    (they have their own issue wording); everything else is routed to
    pyflakes_defects or pyflakes_hygiene by class name.
    """
    from pyflakes import checker

    unused_vars: list[str] = []
    unused_imports: list[str] = []
    undefined: list[str] = []
    defects: list[str] = []
    hygiene: list[str] = []
    try:
        result = checker.Checker(tree, filename="<action>")
    except Exception:  # pyflakes internal error must not kill the collector
        return {}
    for message in result.messages:
        name = type(message).__name__
        arg = str(message.message_args[0]) if message.message_args else "?"
        if name == "UnusedVariable":
            unused_vars.append(arg)
        elif name == "UnusedImport":
            unused_imports.append(arg)
        elif name == "UndefinedName":
            undefined.append(arg)
        elif name not in _PYFLAKES_OWN_FIELDS:
            bucket = defects if name in PYFLAKES_DEFECTS else hygiene
            bucket.append(_pyflakes_text(message))
    return {
        "unused_variables": sorted(set(unused_vars)),
        "unused_imports": sorted(set(unused_imports)),
        "undefined_names": sorted(set(undefined)),
        "pyflakes_defects": sorted(set(defects)),
        "pyflakes_hygiene": sorted(set(hygiene)),
    }


def _pyflakes_text(message) -> str:
    """One pyflakes message as its own English sentence plus a line number.

    str(message) prefixes the fake "<action>" filename, which would leak into
    the report, so the format string is applied directly.
    """
    try:
        text = message.message % message.message_args
    except (TypeError, ValueError):  # a message shape this pyflakes renders differently
        text = type(message).__name__
    return f"{text} (line {message.lineno})"


def _comment_markers(runtime: str) -> tuple[str, tuple[str, str] | None]:
    runtime = (runtime or "").lower()
    if runtime.startswith("powershell"):
        # PowerShell has real block comments; counting their interior as
        # code inflated the size-only complexity rating.
        return "#", ("<#", "#>")
    if runtime.startswith("python"):
        return "#", None
    return "//", ("/*", "*/")  # javascript / node


def _split_lines(source: str, runtime: str) -> tuple[list[str], list[str]]:
    """Non-blank lines of the source, split into comment lines and code lines.

    Whole-line comments only. A trailing comment is left on its code line on
    purpose: cutting at the first `//` would also cut "http://host" in a string
    literal, and silently losing real environment coupling is a worse error
    than keeping a documentation URL that happens to sit at the end of a line.
    """
    line_marker, block = _comment_markers(runtime)
    comments: list[str] = []
    code: list[str] = []
    in_block = False
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if in_block:
            comments.append(line)
            if block and block[1] in line:
                in_block = False
            continue
        if line.startswith(line_marker):
            comments.append(line)
        elif block and line.startswith(block[0]):
            comments.append(line)
            if block[1] not in line[len(block[0]) :]:
                in_block = True
        else:
            code.append(line)
    return comments, code


def strip_comments(source: str, runtime: str) -> str:
    """The source with whole-line comments removed."""
    return "\n".join(_split_lines(source, runtime)[1])


def comment_metrics(source: str, runtime: str) -> dict:
    """Comment vs code line counts. A metric, not a finding - zero-comment
    code is not per se broken, but density belongs in the assessment."""
    comments, code = _split_lines(source, runtime)
    total = len(comments) + len(code)
    return {
        "comment_lines": len(comments),
        "code_lines": len(code),
        "comment_ratio": round(len(comments) / total, 2) if total else 0.0,
    }


# PowerShell has a compiler-grade parser built into every PowerShell binary
# ([System.Management.Automation.Language.Parser]); no comparable pure-Python
# parser exists. When a binary is on PATH the whole batch of sources is parsed
# in ONE subprocess call (spawning per action would add minutes to a run);
# without one, the regex heuristics stay in force. Sources travel via a
# UTF-8 temp file - piping them through stdin trips console encodings.
_PS_METRICS_SCRIPT = r"""
using namespace System.Management.Automation.Language
$ErrorActionPreference = 'Stop'
# PS 5.1: ConvertFrom-Json emits a JSON array as ONE pipeline item - no @()
# wrapper here, foreach enumerates the object[] itself (a single-element
# array arrives as a bare string, which foreach treats as one iteration).
$srcs = (Get-Content -Raw -LiteralPath $env:VCF_PS_BATCH -Encoding UTF8) | ConvertFrom-Json
$out = New-Object System.Collections.ArrayList
foreach ($s in $srcs) {
  $tokens = $null; $errors = $null
  $ast = [Parser]::ParseInput([string]$s, [ref]$tokens, [ref]$errors)
  if (@($errors).Count -gt 0) { [void]$out.Add(@{ok=$false}); continue }
  $funcAsts = @($ast.FindAll({param($n) $n -is [FunctionDefinitionAst]}, $true))
  $functions = $funcAsts.Count
  # Names only for functions defined at the top level of the script: an ABX
  # entrypoint has to be reachable as a script-level function.
  # Top level means the function's block hangs off the ROOT script block:
  # a nested function's parent chain reaches a NamedBlockAst too, so the
  # test is that nothing encloses its grandparent.
  $top = @($funcAsts | Where-Object {
    $_.Parent -is [NamedBlockAst] -and $null -eq $_.Parent.Parent.Parent })
  $names = @($top | ForEach-Object { $_.Name })
  $branches = @($ast.FindAll({param($n)
    $n -is [IfStatementAst] -or $n -is [ForEachStatementAst] -or
    $n -is [ForStatementAst] -or $n -is [WhileStatementAst] -or
    $n -is [DoWhileStatementAst] -or $n -is [DoUntilStatementAst] -or
    $n -is [SwitchStatementAst] -or $n -is [CatchClauseAst]}, $true)).Count
  $catches = @($ast.FindAll({param($n) $n -is [CatchClauseAst]}, $true))
  $trys = @($ast.FindAll({param($n) $n -is [TryStatementAst]}, $true))
  $bare = @($catches | Where-Object { $_.CatchTypes.Count -eq 0 }).Count
  $swallowed = @($catches | Where-Object { $_.Body.Statements.Count -eq 0 }).Count
  # Rethrow-only handlers: only the LAST catch of a try can be pointless (an
  # earlier "catch [X] { throw }" filters X away from a broader catch below).
  # Bare "throw" rethrows inside catch; "throw $_" is the explicit spelling.
  $reraise = 0
  foreach ($t in $trys) {
    $cc = @($t.CatchClauses)
    if ($cc.Count -eq 0) { continue }
    $stmts = @($cc[$cc.Count - 1].Body.Statements)
    if ($stmts.Count -ne 1 -or -not ($stmts[0] -is [ThrowStatementAst])) { continue }
    $p = $stmts[0].Pipeline
    if ($null -eq $p -or $p.Extent.Text.Trim() -eq '$_') { $reraise++ }
  }
  [void]$out.Add(@{ok=$true; functions=$functions; branches=$branches;
    has_error_handling=($trys.Count -gt 0); bare_excepts=$bare; swallowed_excepts=$swallowed;
    reraise_only_excepts=$reraise; function_names=[string[]]$names})
}
ConvertTo-Json -InputObject $out -Depth 4 -Compress
"""


def powershell_available() -> bool:
    return _powershell_exe() is not None


def _powershell_exe() -> str | None:
    return shutil.which("pwsh") or shutil.which("powershell")


def parse_powershell_batch(sources: list[str]) -> list[dict | None] | None:
    """Real AST metrics for PowerShell sources, one subprocess for the batch.

    Returns None when no PowerShell binary is on PATH or the call fails (the
    regex heuristics stay in force); a per-source None marks a source with
    parse errors - its heuristic analysis is kept rather than downgraded.
    """
    exe = _powershell_exe()
    if not exe or not sources:
        return None
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    try:
        json.dump(list(sources), tmp)
        tmp.close()
        proc = subprocess.run(  # noqa: S603 - fixed argv, sources go via file
            [exe, "-NoProfile", "-NonInteractive", "-Command", _PS_METRICS_SCRIPT],
            capture_output=True,
            text=True,
            timeout=180,
            env={**os.environ, "VCF_PS_BATCH": tmp.name},
        )
        if proc.returncode != 0:
            log.warning("PowerShell parse batch failed (rc=%d): %s", proc.returncode, proc.stderr)
            return None
        rows = json.loads(proc.stdout)
        if isinstance(rows, dict):
            rows = [rows]
        if len(rows) != len(sources):
            log.warning(
                "PowerShell parse batch: %d results for %d sources", len(rows), len(sources)
            )
            return None
        # Shaped inside the try: a malformed row (a JSON null where a
        # hashtable was expected) must degrade like every other batch
        # failure, not escape into the collector.
        return [
            {
                "parses": True,
                "functions": int(r.get("functions") or 0),
                "branches": int(r.get("branches") or 0),
                "has_error_handling": bool(r.get("has_error_handling")),
                "bare_excepts": int(r.get("bare_excepts") or 0),
                "swallowed_excepts": int(r.get("swallowed_excepts") or 0),
                "reraise_only_excepts": int(r.get("reraise_only_excepts") or 0),
                # A script with no functions serializes as null, not [].
                "top_level_functions": [str(n) for n in (r.get("function_names") or [])],
            }
            if isinstance(r, dict) and r.get("ok")
            else None
            for r in rows
        ]
    except Exception as exc:  # a parse upgrade must never break collection
        log.warning("PowerShell parse batch unavailable: %s", exc)
        return None
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


# Node compiles JavaScript without running it (new vm.Script), which is the
# only real parse signal available for these actions - there is no comparable
# pure-Python JavaScript parser. It answers "does this parse", nothing more:
# unused-variable and structural analysis still need a full AST walk.
#
# Each source is wrapped in a function expression before compiling. An
# Orchestrator action IS a function body, so a top-level `return` is correct
# there and would otherwise be reported as a syntax error on every healthy
# action. The wrapper is harmless for ABX Node modules, which are valid in
# either position.
_NODE_SYNTAX_SCRIPT = r"""
const fs = require('fs');
const vm = require('vm');
const srcs = JSON.parse(fs.readFileSync(process.env.VCF_JS_BATCH, 'utf8'));
const out = srcs.map(function (s) {
  try {
    new vm.Script('(function(){\n' + s + '\n})');
    return { ok: true };
  } catch (e) {
    return { ok: false, message: String((e && e.message) || e).split('\n')[0] };
  }
});
process.stdout.write(JSON.stringify(out));
"""


def node_available() -> bool:
    return shutil.which("node") is not None


def esprima_available() -> bool:
    return esprima is not None


# Branch points, mirroring the Python path: every construct that adds a way
# through the code. CatchClause counts here as well as marking error handling,
# the same as ast.ExceptHandler does.
_JS_BRANCH_TYPES = frozenset(
    {
        "IfStatement",
        "ConditionalExpression",
        "ForStatement",
        "ForInStatement",
        "ForOfStatement",
        "WhileStatement",
        "DoWhileStatement",
        "SwitchCase",
        "CatchClause",
    }
)
_JS_FUNCTION_TYPES = frozenset(
    {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}
)


def _js_nodes(node):
    """Every node of an esprima AST rendered as plain dicts."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _js_nodes(value)
    elif isinstance(node, list):
        for value in node:
            yield from _js_nodes(value)


def _js_catch_shape(catch: dict) -> tuple[bool, bool]:
    """(swallowed, re-raise only) for one catch clause."""
    body = (catch.get("body") or {}).get("body") or []
    if not body:
        return True, False
    if len(body) == 1 and body[0].get("type") == "ThrowStatement":
        thrown = body[0].get("argument") or {}
        param = catch.get("param") or {}
        # `catch (e) { throw e }` adds nothing; `throw new Error(...)` is a
        # deliberate translation and is left alone, matching the Python rule.
        if thrown.get("type") == "Identifier" and thrown.get("name") == param.get("name"):
            return False, True
    return False, False


def _js_parse_attempts(source: str):
    """(parser, source, wrapped) in the order worth trying.

    An Orchestrator action IS a function body - a top-level `return` is
    correct there and illegal in a bare script - so the wrapped form is tried
    the moment the bare one fails, exactly as the node check has always
    wrapped. ES modules are last: `import`/`export` are legal in neither of
    the first two.
    """
    yield esprima.parseScript, source, False
    yield esprima.parseScript, "(function(){\n" + source + "\n})", True
    yield esprima.parseModule, source, False


def parse_javascript_structure(source: str) -> tuple[dict | None, str | None]:
    """Structural metrics from esprima, or (None, reason) if it will not parse.

    esprima is an ECMAScript 2017 parser, so a rejection means either a real
    syntax error or syntax newer than that (optional chaining, private class
    fields). The caller decides which - this returns the reason, never a
    verdict.
    """
    if esprima is None:  # pragma: no cover - esprima is a hard dependency
        return None, "esprima not installed"
    reason = "syntax error"
    for parse, text, wrapped in _js_parse_attempts(source):
        try:
            tree = parse(text).toDict()
        except Exception as exc:  # esprima raises its own Error type
            if not wrapped:  # the bare reading is the one worth reporting
                reason = str(exc)
            continue
        result = {
            "parses": True,
            "parse_error": None,
            "functions": 0,
            "branches": 0,
            "has_error_handling": False,
            "bare_excepts": 0,  # JavaScript has no untyped-catch equivalent
            "swallowed_excepts": 0,
            "reraise_only_excepts": 0,
            "top_level_functions": [],
        }
        for node in _js_nodes(tree):
            kind = node.get("type")
            if kind in _JS_FUNCTION_TYPES:
                result["functions"] += 1
            if kind in _JS_BRANCH_TYPES:
                result["branches"] += 1
            if kind == "TryStatement":
                result["has_error_handling"] = True
            elif kind == "CatchClause":
                swallowed, reraise = _js_catch_shape(node)
                result["swallowed_excepts"] += int(swallowed)
                result["reraise_only_excepts"] += int(reraise)
        body = tree.get("body") or []
        if wrapped:
            # Unwrap: the synthetic function is not the action's own, and the
            # action's top level is that function's body.
            result["functions"] -= 1
            body = _js_wrapper_body(tree)
        result["top_level_functions"] = [
            (node.get("id") or {}).get("name")
            for node in body
            if node.get("type") == "FunctionDeclaration" and (node.get("id") or {}).get("name")
        ]
        return result, None
    return None, reason


def _js_wrapper_body(tree: dict) -> list:
    """Statements inside the synthetic "(function(){...})" wrapper."""
    for node in _js_nodes(tree):
        if node.get("type") == "FunctionExpression":
            return (node.get("body") or {}).get("body") or []
    return []  # pragma: no cover - the wrapper always parses to one


def parse_javascript_batch(sources: list[str]) -> list[dict | None] | None:
    """Structure for JavaScript sources, from esprima with node as referee.

    esprima runs in-process and needs nothing on the host, so this is the
    normal path. Sources it rejects go to node when node is available: node
    parsing them means esprima met syntax newer than it knows, which is a
    limitation of ours and must not be reported as a broken action. With no
    node to ask, such a source keeps its heuristics and no claim is made
    either way.
    """
    if not sources:
        return None
    if esprima is None:  # pragma: no cover - esprima is a hard dependency
        return _node_syntax_batch(sources)

    results: list[dict | None] = []
    rejected: list[int] = []
    reasons: dict[int, str] = {}
    for index, source in enumerate(sources):
        metrics, reason = parse_javascript_structure(source)
        results.append(metrics)
        if metrics is None:
            rejected.append(index)
            reasons[index] = reason or "syntax error"

    if rejected:
        verdicts = _node_syntax_batch([sources[i] for i in rejected])
        if verdicts is None:
            log.info(
                "%d JavaScript source(s) esprima could not parse and no node to check them "
                "against; heuristics kept, no parse claim made",
                len(rejected),
            )
        else:
            for index, verdict in zip(rejected, verdicts, strict=True):
                if verdict is None:
                    continue
                if verdict.get("parses"):
                    # Valid JavaScript, just newer than esprima. Structure
                    # stays unanalyzed; the action is not called broken.
                    results[index] = {"parses": True, "parse_error": None}
                else:
                    results[index] = verdict
    return results


def _node_syntax_batch(sources: list[str]) -> list[dict | None] | None:
    """Syntax validity for JavaScript sources, one subprocess for the batch.

    Same contract as parse_powershell_batch: None when node is not on PATH or
    the call fails, so the heuristics stay in force and nothing is downgraded
    on the strength of a tool that did not run.
    """
    exe = shutil.which("node")
    if not exe or not sources:
        return None
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    try:
        json.dump(list(sources), tmp)
        tmp.close()
        proc = subprocess.run(  # noqa: S603 - fixed argv, sources go via file
            [exe, "-e", _NODE_SYNTAX_SCRIPT],
            capture_output=True,
            text=True,
            timeout=180,
            env={**os.environ, "VCF_JS_BATCH": tmp.name},
        )
        if proc.returncode != 0:
            log.warning("node syntax batch failed (rc=%d): %s", proc.returncode, proc.stderr)
            return None
        rows = json.loads(proc.stdout)
        if len(rows) != len(sources):
            log.warning("node syntax batch: %d results for %d sources", len(rows), len(sources))
            return None
        return [
            {
                "parses": bool(r.get("ok")),
                "parse_error": None
                if r.get("ok")
                else f"does not parse as JavaScript: {r.get('message') or 'syntax error'}",
            }
            if isinstance(r, dict)
            else None
            for r in rows
        ]
    except Exception as exc:  # a parse upgrade must never break collection
        log.warning("node syntax check unavailable: %s", exc)
        return None
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def complexity_rating(analysis: dict | None) -> str | None:
    """LOW/MEDIUM/HIGH from structural metrics; None when there is nothing
    trustworthy to rate (no analysis, or source that does not parse).

    Serverless actions are meant to be short glue scripts, so the thresholds
    are anchored to that intent, not to general software size. Statically
    parsed sources (Python via ast; JavaScript via esprima; PowerShell via
    PowerShell's own parser when one is on PATH) are rated on code lines +
    functions + branch points; anything left unparsed - a PowerShell source
    with no binary to parse it, JavaScript newer than esprima - is rated on
    code size alone.
    """
    if not analysis or analysis.get("parses") is False:
        return None
    code = analysis.get("code_lines") or 0
    if analysis.get("functions") is None:  # unparsed - size is all we have
        if code > 250:
            return "HIGH"
        return "MEDIUM" if code > 120 else "LOW"
    functions = analysis.get("functions") or 0
    branches = analysis.get("branches") or 0
    if code > 200 or functions > 8 or branches > 30:
        return "HIGH"
    if code > 100 or functions > 5 or branches > 15:
        return "MEDIUM"
    return "LOW"


# Copy-paste detection works from a fingerprint, never from the source: the
# collectors drop action source after analysis to keep the JSON dump lean.
# A sketch is 64 8-byte hashes, roughly 300 bytes per action, which buys
# near-duplicate detection - real copy-paste is nearly always edited a little,
# so exact hashing alone would find almost nothing.
SKETCH_SIZE = 64
# Two-line shingles, not the usual three. An edited line invalidates every
# shingle it appears in, so at the short end of the eligible range (15-20
# code lines) a three-line window drops a single-line edit to 0.64 - under
# any threshold that unrelated code stays clear of. Two lines puts the same
# edit at 0.80 and a two-line edit at 0.73, while two actions sharing a
# ten-line preamble still measure 0.41.
SHINGLE_LINES = 2
# Short glue scripts are legitimately alike (read an input, call one API,
# return). Below this they are excluded rather than reported as duplicates.
MIN_DUPLICATE_CODE_LINES = 15


def source_sketch(source: str, runtime: str) -> dict:
    """Fingerprint and similarity sketch for one action's source.

    Comments and blank lines are dropped and internal whitespace collapsed, so
    reformatting does not hide a copy. Case is kept: PowerShell is
    case-insensitive but Python is not, and folding case would merge sources
    that genuinely differ.
    """
    code = [re.sub(r"\s+", " ", line) for line in _split_lines(source, runtime)[1]]
    text = "\n".join(code)
    shingles = {
        _hash64("\n".join(code[i : i + SHINGLE_LINES]))
        for i in range(max(1, len(code) - SHINGLE_LINES + 1))
    }
    return {
        "fingerprint": hashlib.blake2b(text.encode("utf-8", "replace"), digest_size=8).hexdigest(),
        "sketch": sorted(shingles)[:SKETCH_SIZE],
        "code_lines": len(code),
    }


def _hash64(text: str) -> int:
    # byteorder is explicit rather than relying on the 3.11+ default: a fingerprint
    # that changes with the interpreter would read as a source that changed.
    digest = hashlib.blake2b(text.encode("utf-8", "replace"), digest_size=8).digest()
    return int.from_bytes(digest, "big")


def sketch_similarity(a: list[int], b: list[int]) -> float:
    """Estimated Jaccard overlap of two sketches (bottom-k estimator).

    k is the smaller of the two sketch lengths: a source with fewer shingles
    than SKETCH_SIZE has a complete sketch, not a truncated one, and using the
    longer length would count its missing hashes as genuine differences.
    """
    if not a or not b:
        return 0.0
    set_a, set_b = set(a), set(b)
    k = min(len(set_a), len(set_b))
    union = sorted(set_a | set_b)[:k]
    return sum(1 for h in union if h in set_a and h in set_b) / k


# Copy-paste-then-adjust is the case worth catching, and it lands at 0.73 or
# above (measured on one and two-line edits to a 16-line action). Actions that
# merely share a preamble measure 0.41 and unrelated ones 0.0, so 0.7 sits in
# clear air between the two.
DUPLICATE_THRESHOLD = 0.7


def duplicate_clusters(
    entries: list[dict],
    threshold: float = DUPLICATE_THRESHOLD,
    min_code_lines: int = MIN_DUPLICATE_CODE_LINES,
) -> list[dict]:
    """Group actions whose source is the same or nearly the same.

    Each entry needs "key", "fingerprint", "sketch" and "code_lines". Returns
    one dict per cluster: members (sorted keys), exact (every member shares a
    fingerprint) and similarity (the lowest estimated overlap in the cluster,
    1.0 when exact).
    """
    candidates = [
        e
        for e in entries
        if e.get("sketch") and (e.get("code_lines") or 0) >= min_code_lines and e.get("key")
    ]
    parent: dict[str, str] = {e["key"]: e["key"] for e in candidates}

    def find(key: str) -> str:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    lowest: dict[tuple[str, str], float] = {}
    for i, left in enumerate(candidates):
        for right in candidates[i + 1 :]:
            if left["fingerprint"] == right["fingerprint"]:
                score = 1.0
            else:
                score = sketch_similarity(left["sketch"], right["sketch"])
                if score < threshold:
                    continue
            lowest[(left["key"], right["key"])] = score
            a, b = find(left["key"]), find(right["key"])
            if a != b:
                parent[a] = b

    grouped: dict[str, list[str]] = {}
    for entry in candidates:
        grouped.setdefault(find(entry["key"]), []).append(entry["key"])
    prints = {e["key"]: e["fingerprint"] for e in candidates}

    clusters = []
    for members in grouped.values():
        if len(members) < 2:
            continue
        members = sorted(members)
        scores = [
            score
            for (a, b), score in lowest.items()
            # A cluster can be linked transitively, so only the pairs whose
            # both ends are inside it describe this cluster's similarity.
            if a in members and b in members
        ]
        clusters.append(
            {
                "members": members,
                "exact": len({prints[m] for m in members}) == 1,
                "similarity": round(min(scores), 2) if scores else 1.0,
            }
        )
    return sorted(clusters, key=lambda c: (-len(c["members"]), c["members"][0]))


def unpinned_dependencies(dependencies: str) -> list[str]:
    """Requirement lines with no version pin - non-reproducible builds.

    pip option lines (--trusted-host, --index-url, -r, ...) are configuration,
    not packages, and are never reported.
    """
    out = []
    for line in (dependencies or "").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        # A pin is what makes the install reproducible: ==, ~= or an @ source.
        # Range constraints (>=, <=, >, <, !=) all leave the version floating
        # and were inconsistently split by the old pattern.
        if not re.search(r"==|~=|@", line):
            out.append(line)
    return out


def _named(values: list[str], cap: int = 3) -> str:
    shown = ", ".join(values[:cap])
    extra = len(values) - cap
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def code_issues(
    analysis: dict, literals: dict, unpinned: list[str], entrypoint: str = ""
) -> list[str]:
    """Defect-level issue list for one action; empty means no signals.

    Absence of try/except is deliberately NOT a signal: letting exceptions
    propagate is often correct (the platform marks the run failed, callers
    handle errors), and flagging it labelled nearly every action on live
    data. Only actively harmful patterns are reported - bare excepts,
    swallowed exceptions, and handlers that only re-raise (a try/catch must
    do something - log, clean up, translate - to justify existing; one that
    just re-throws is dead weight the exception would traverse anyway).

    Hygiene-level signals live in pedantic_issues, off unless --pedantic.
    """
    named = _named
    issues = []
    if analysis.get("parses") is False:
        issues.append(
            analysis.get("parse_error") or "source does not parse as Python 3 (Python 2 legacy?)"
        )
    if entrypoint and _entrypoint_missing(analysis, entrypoint):
        issues.append(f"declared entrypoint '{entrypoint}' is not defined in the action source")
    if analysis.get("pyflakes_defects"):
        issues.append(f"probable defect(s): {named(analysis['pyflakes_defects'])}")
    if analysis.get("undefined_names"):
        issues.append(
            f"undefined name(s): {named(analysis['undefined_names'])} - would fail at runtime"
        )
    if analysis.get("syntax_warnings"):
        issues.append(
            f"syntax warning(s): {named(analysis['syntax_warnings'])} - "
            "usually an un-raw Windows path; invalid escapes become hard "
            "errors in future Python versions"
        )
    if analysis.get("unused_variables"):
        issues.append(f"unused variable(s): {named(analysis['unused_variables'])}")
    if analysis.get("unused_imports"):
        issues.append(f"unused import(s): {named(analysis['unused_imports'])}")
    if analysis.get("bare_excepts"):
        issues.append(f"{analysis['bare_excepts']} bare except clause(s)")
    if analysis.get("swallowed_excepts"):
        issues.append(
            f"{analysis['swallowed_excepts']} except clause(s) that swallow errors (pass)"
        )
    if analysis.get("reraise_only_excepts"):
        issues.append(
            f"{analysis['reraise_only_excepts']} handler(s) that only re-raise - "
            "the try/catch adds nothing"
        )
    if literals.get("secrets"):
        issues.append(f"credential-looking literal(s): {', '.join(literals['secrets'][:3])}")
    if literals.get("ips"):
        issues.append(f"hardcoded IP(s): {', '.join(literals['ips'][:3])}")
    if literals.get("urls"):
        issues.append(f"hardcoded URL(s): {', '.join(literals['urls'][:3])}")
    if unpinned:
        issues.append(f"unpinned dependencies: {', '.join(unpinned[:3])}")
    return issues


def _entrypoint_missing(analysis: dict, entrypoint: str) -> bool:
    """Whether a declared entrypoint is demonstrably absent from the source.

    Silent unless the source was parsed AND named at least one top-level
    function: with no names to compare against, the source is a shape this
    analyzer does not understand (a bundle, a JavaScript action, a PowerShell
    action on a host with no PowerShell), and a missing-entrypoint claim there
    would be a guess. Only the last dotted segment is compared - ABX spells
    bundled entrypoints "module.function".
    """
    names = analysis.get("top_level_functions") or []
    if analysis.get("parses") is not True or not names:
        return False
    return entrypoint.rsplit(".", 1)[-1] not in names


def pedantic_issues(analysis: dict, declared_inputs: list[str] | None = None) -> list[str]:
    """Hygiene-level issue list for one action: reported only under --pedantic.

    These describe untidiness rather than defects. They are always collected
    and always present in the JSON dump; the flag decides whether the report
    and the findings count them.
    """
    named = _named
    issues = []
    if analysis.get("pyflakes_hygiene"):
        issues.append(f"minor code issue: {named(analysis['pyflakes_hygiene'])}")
    unread = _unread_inputs(analysis, declared_inputs)
    if unread:
        issues.append(f"declared input(s) never read: {named(unread)}")
    if analysis.get("print_calls") and not analysis.get("uses_logging"):
        issues.append(
            f"{analysis['print_calls']} print/console call(s) and no logger - "
            "run output carries no severity"
        )
    return issues


def _unread_inputs(analysis: dict, declared_inputs: list[str] | None) -> list[str]:
    """Declared inputs the source never reads by name.

    The opposite direction - a key read but not declared - is deliberately not
    reported: the event broker merges topic payload fields into inputs at run
    time, so a subscription-driven action legitimately reads keys that appear
    nowhere in its declaration. Silent unless at least one input is read by a
    literal key, which is the evidence that this source addresses inputs in a
    way the analyzer can see at all.
    """
    read = analysis.get("read_input_keys") or []
    if not declared_inputs or not read:
        return []
    return sorted(set(declared_inputs) - set(read))
