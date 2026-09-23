"""Static code-quality analyzer behaviour."""

from vcf_automation_assessment_tool.codequality import (
    analyze_python,
    analyze_script,
    code_issues,
    scan_literals,
    unpinned_dependencies,
)

GOOD_PY = """
import logging

log = logging.getLogger(__name__)


def handler(context, inputs):
    try:
        return {"ok": do_work(inputs)}
    except ValueError as exc:
        log.error("bad input: %s", exc)
        raise


def do_work(inputs):
    return inputs["name"]
"""

BAD_PY = """
import requests

def handler(context, inputs):
    password = "SuperSecret1"
    resp = requests.get("http://10.20.30.40/api", auth=("svc", password))
    print(resp.status_code)
    try:
        cleanup()
    except:
        pass
    return resp.json()
"""


def test_good_python_has_no_issues():
    analysis = analyze_python(GOOD_PY)
    assert analysis["parses"] and analysis["has_error_handling"]
    assert analysis["uses_logging"] and analysis["bare_excepts"] == 0
    # log-then-raise DOES something before re-raising - never flagged.
    assert analysis["reraise_only_excepts"] == 0
    literals = scan_literals(GOOD_PY)
    assert code_issues(analysis, literals, []) == []


def test_bad_python_flags_everything():
    analysis = analyze_python(BAD_PY)
    assert analysis["has_error_handling"]  # a try exists...
    assert analysis["bare_excepts"] == 1  # ...but it's a bare except
    assert analysis["swallowed_excepts"] == 1  # ...that swallows the error
    assert analysis["print_calls"] == 1
    literals = scan_literals(BAD_PY)
    assert literals["ips"] == ["10.20.30.40"]
    assert "password" in literals["secrets"]
    issues = code_issues(analysis, literals, ["requests"])
    joined = " | ".join(issues)
    assert "bare except" in joined
    assert "swallow" in joined
    assert "10.20.30.40" in joined
    assert "unpinned" in joined


RERAISE_ONLY_PY = """
def handler(context, inputs):
    try:
        return do_work(inputs)
    except Exception:
        raise


def named(inputs):
    try:
        return do_work(inputs)
    except ValueError as exc:
        raise exc
"""

FILTER_PATTERN_PY = """
def handler(context, inputs):
    try:
        return do_work(inputs)
    except KeyError:
        raise
    except Exception:
        return {"error": True}
"""

TRANSLATE_PY = """
def handler(context, inputs):
    try:
        return do_work(inputs)
    except KeyError as exc:
        raise RuntimeError("bad input") from exc
"""


def test_reraise_only_handlers_flagged():
    # A handler whose whole body is "raise" (or "raise e" of the caught name)
    # adds nothing - the exception would propagate identically without the
    # try. User request 2026-08-06: a try/catch must be doing something to
    # justify itself.
    analysis = analyze_python(RERAISE_ONLY_PY)
    assert analysis["reraise_only_excepts"] == 2
    issues = code_issues(analysis, {"ips": [], "urls": [], "secrets": []}, [])
    assert any("only re-raise" in i for i in issues)


def test_reraise_filter_pattern_not_flagged():
    # "except KeyError: raise" in front of a broader handler keeps KeyError
    # out of the generic handler - deliberate, so only the LAST handler of a
    # try can be a pointless re-raise.
    analysis = analyze_python(FILTER_PATTERN_PY)
    assert analysis["reraise_only_excepts"] == 0


def test_exception_translation_not_flagged():
    # "raise Other(...) from exc" changes the exception - that justifies the
    # try. Any "from" clause opts out, including "raise exc from None".
    analysis = analyze_python(TRANSLATE_PY)
    assert analysis["reraise_only_excepts"] == 0


def test_reraise_only_javascript_heuristic():
    src = "exports.handler = async () => { try { x(); } catch (e) { throw e; } };"
    assert analyze_script(src, "nodejs")["reraise_only_excepts"] == 1
    handled = "try { x(); } catch (e) { console.error(e); throw e; }"
    assert analyze_script(handled, "nodejs")["reraise_only_excepts"] == 0


def test_reraise_only_powershell_heuristic():
    assert (
        analyze_script("try { Do-Thing } catch { throw }", "powershell")["reraise_only_excepts"]
        == 1
    )
    assert (
        analyze_script("try { Do-Thing } catch { throw $_ }", "powershell")["reraise_only_excepts"]
        == 1
    )
    # A rethrow catch followed by another catch is the type-filter pattern.
    filtered = "try { Do-Thing } catch [System.IO.IOException] { throw } catch { Write-Error $_ }"
    assert analyze_script(filtered, "powershell")["reraise_only_excepts"] == 0
    handled = "try { Do-Thing } catch { Write-Error $_; throw }"
    assert analyze_script(handled, "powershell")["reraise_only_excepts"] == 0


def test_python2_source_reported_as_unparseable():
    analysis = analyze_python('print "hello"\n')
    assert analysis["parses"] is False
    issues = code_issues(analysis, {"ips": [], "urls": [], "secrets": []}, [])
    assert any("Python 3" in i for i in issues)


def test_invalid_escape_captured_as_signal_not_console_noise():
    # Live lesson (2026-08-05): an action holding "C:\Temp" in a non-raw
    # string made ast.parse print "SyntaxWarning: invalid escape sequence"
    # on the operator's console mid-run. The warning must be captured and
    # reported as a per-action signal instead of leaking to stderr.
    import warnings

    src = 'import os\ntemp = "C:\\Temp"\nprint(os.path.exists(temp))\n'
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any leaked warning fails the test
        analysis = analyze_python(src)
    assert any("\\T" in w for w in analysis["syntax_warnings"])
    assert "(line 2)" in " ".join(analysis["syntax_warnings"])
    issues = code_issues(analysis, {"ips": [], "urls": [], "secrets": []}, [])
    assert any("syntax warning" in i for i in issues)


def test_clean_source_has_no_syntax_warnings():
    analysis = analyze_python('import os\npath = os.path.join("a", "b")\nprint(path)\n')
    assert analysis["syntax_warnings"] == []


def test_powershell_batch_real_parser():
    # Self-skips on hosts without PowerShell - the fallback heuristics are
    # what runs there, covered by the other tests.
    import shutil

    import pytest

    if not (shutil.which("pwsh") or shutil.which("powershell")):
        pytest.skip("no PowerShell binary on PATH")
    from vcf_automation_assessment_tool.codequality import parse_powershell_batch

    good = "function Get-Thing {\n  param($x)\n  if ($x) { try { Get-Item $x } catch { } }\n}\n"
    bad = "function { this is not valid"
    # Trailing catch is a bare rethrow (pointless); the typed one in front is
    # the filter pattern and must not count.
    rethrow = (
        "try { Get-Item $x }\n"
        "catch [System.IO.IOException] { throw }\n"
        "catch { throw $_ }\n"
        "try { Get-Item $y } catch { Write-Error $_; throw }\n"
    )
    rows = parse_powershell_batch([good, bad, rethrow])
    assert rows is not None
    parsed, broken, rethrown = rows
    assert parsed["parses"] is True
    assert parsed["functions"] == 1
    assert parsed["branches"] == 2  # if + catch clause
    assert parsed["has_error_handling"] is True
    # catch {} has no type filter and an empty body: bare AND swallowed.
    assert parsed["bare_excepts"] == 1 and parsed["swallowed_excepts"] == 1
    assert parsed["reraise_only_excepts"] == 0
    assert broken is None  # parse errors -> heuristics stay in force
    assert rethrown["reraise_only_excepts"] == 1


def test_complexity_rating_tiers():
    from vcf_automation_assessment_tool.codequality import complexity_rating

    # Python is rated on structure: lines + functions + branch points.
    assert complexity_rating({"code_lines": 30, "functions": 2, "branches": 4}) == "LOW"
    assert complexity_rating({"code_lines": 130, "functions": 2, "branches": 4}) == "MEDIUM"
    assert complexity_rating({"code_lines": 30, "functions": 9, "branches": 4}) == "HIGH"
    assert complexity_rating({"code_lines": 30, "functions": 2, "branches": 31}) == "HIGH"
    # No parser for JS/PowerShell (functions is None): size is all we have.
    assert complexity_rating({"code_lines": 130, "functions": None}) == "MEDIUM"
    assert complexity_rating({"code_lines": 300, "functions": None}) == "HIGH"
    # Nothing trustworthy to rate: no analysis, or source that does not parse.
    assert complexity_rating(None) is None
    assert complexity_rating({"parses": False, "code_lines": 500}) is None


def test_branches_counted_from_ast():
    src = (
        "def handler(c, i):\n"
        "    for x in i:\n"
        "        if x:\n"
        "            try:\n"
        "                print(x)\n"
        "            except ValueError:\n"
        "                pass\n"
        "    return i\n"
    )
    analysis = analyze_python(src)
    # for + if + except handler = 3 branch points.
    assert analysis["branches"] == 3


def test_ignores_localhost_and_bindings():
    literals = scan_literals("bind = '0.0.0.0'; local = '127.0.0.1'; ref = '${input.ip}'")
    assert literals["ips"] == []


def test_nodejs_heuristics():
    src = "exports.handler = async () => { try { x(); } catch (e) { console.error(e); } };"
    analysis = analyze_script(src, "nodejs")
    assert analysis["has_error_handling"] and analysis["uses_logging"]
    src_bad = "exports.handler = async () => { console.log('hi'); };"
    analysis = analyze_script(src_bad, "nodejs")
    assert not analysis["has_error_handling"] and analysis["print_calls"] == 1


def test_powershell_heuristics():
    src = "try { Do-Thing } catch { Write-Error $_ }"
    analysis = analyze_script(src, "powershell")
    assert analysis["has_error_handling"] and analysis["uses_logging"]


UNTIDY_PY = """
import os
import requests

# fetch the record
def handler(context, inputs):
    unused_thing = 42
    result = requests.get(inputs["url"])
    return missing_helper(result)
"""


def test_unused_and_undefined_names_detected():
    analysis = analyze_python(UNTIDY_PY)
    assert analysis["unused_variables"] == ["unused_thing"]
    assert analysis["unused_imports"] == ["os"]
    assert analysis["undefined_names"] == ["missing_helper"]
    issues = code_issues(analysis, {"ips": [], "urls": [], "secrets": []}, [])
    joined = " | ".join(issues)
    assert "undefined name(s): missing_helper" in joined and "fail at runtime" in joined
    assert "unused variable(s): unused_thing" in joined
    assert "unused import(s): os" in joined


def test_comment_metrics_python():
    analysis = analyze_python(UNTIDY_PY)
    assert analysis["comment_lines"] == 1
    assert analysis["code_lines"] == 6
    assert analysis["comment_ratio"] == round(1 / 7, 2)


def test_comment_metrics_javascript_blocks():
    src = "/* header\n   more header */\n// inline\nvar x = 1;\nrun(x);\n"
    analysis = analyze_script(src, "nodejs")
    assert analysis["comment_lines"] == 3
    assert analysis["code_lines"] == 2
    # No scope analysis outside Python: never claims unused/undefined names.
    assert analysis["unused_variables"] == [] and analysis["undefined_names"] == []


def test_comments_are_metric_not_issue():
    # The handler prints before re-raising so it isn't a re-raise-only handler
    # (print is a metric, not an issue).
    src = (
        "def handler(c, i):\n"
        "    try:\n"
        "        return i\n"
        "    except ValueError:\n"
        "        print(i)\n"
        "        raise\n"
    )
    analysis = analyze_python(src)  # zero comments
    assert analysis["comment_lines"] == 0
    assert code_issues(analysis, {"ips": [], "urls": [], "secrets": []}, []) == []


def test_unpinned_dependencies():
    # Only a reproducible pin passes: >= is a floating constraint, exactly
    # like a bare name (the old pattern split >= and > inconsistently).
    deps = "requests==2.31.0\ndnspython\n# comment\npyyaml>=6.0\nlxml~=5.0\n"
    assert unpinned_dependencies(deps) == ["dnspython", "pyyaml>=6.0"]


def test_unpinned_dependencies_ignores_pip_options():
    # pip option lines are configuration, not packages (seen on live data:
    # --trusted-host was reported as an unpinned dependency).
    deps = "--trusted-host pypi.org\n--trusted-host files.pythonhosted.org\n-r base.txt\nparamiko\n"
    assert unpinned_dependencies(deps) == ["paramiko"]
