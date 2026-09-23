"""The defect/hygiene split, entrypoint resolution and the Node syntax check.

Companion to test_codequality, which covers the signals that pre-date the
two-tier split.
"""

from __future__ import annotations

import shutil

import pytest

from vcf_automation_assessment_tool.codequality import (
    analyze_python,
    analyze_script,
    code_issues,
    node_available,
    parse_javascript_batch,
    parse_javascript_structure,
    pedantic_issues,
    scan_literals,
    strip_comments,
)

NO_LITERALS = {"ips": [], "urls": [], "secrets": []}

DEFECTS_PY = (
    "def handler(context, inputs):\n"
    "    limits = {'cpu': 1, 'cpu': 2}\n"
    "    if inputs['mode'] is 'prod':\n"
    "        assert (limits, 'must be set')\n"
    "    return limits\n"
)

HYGIENE_PY = "from json import *\n\ndef handler(context, inputs):\n    return dumps(inputs)\n"


def test_defect_class_pyflakes_messages_are_reported_by_default():
    analysis = analyze_python(DEFECTS_PY)
    joined = " | ".join(analysis["pyflakes_defects"])
    assert "repeated" in joined  # duplicate dict key: one value is silently lost
    assert "==/!=" in joined  # `is` against a literal
    assert "always true" in joined  # assert on a tuple
    # Every defect carries a line number so the reader can find it.
    assert all("(line " in message for message in analysis["pyflakes_defects"])
    assert any(i.startswith("probable defect(s):") for i in code_issues(analysis, NO_LITERALS, []))


def test_hygiene_class_messages_stay_out_of_the_default_issue_list():
    analysis = analyze_python(HYGIENE_PY)
    assert analysis["pyflakes_hygiene"]
    assert not analysis["pyflakes_defects"]
    assert code_issues(analysis, NO_LITERALS, []) == []
    assert any(i.startswith("minor code issue:") for i in pedantic_issues(analysis))


def test_dedicated_fields_are_not_also_reported_as_defects_or_hygiene():
    # Unused imports/variables and undefined names have their own wording;
    # routing them twice would double-count every action that has one.
    analysis = analyze_python("import os\n\ndef handler(c, i):\n    return missing_helper()\n")
    assert analysis["unused_imports"] == ["os"]
    assert analysis["undefined_names"] == ["missing_helper"]
    everything = analysis["pyflakes_defects"] + analysis["pyflakes_hygiene"]
    assert not any("os" in m or "missing_helper" in m for m in everything)


def test_message_the_installed_pyflakes_does_not_classify_falls_through_to_hygiene():
    # The classifier matches on class NAME, so a message class this pyflakes
    # version happens to emit but PYFLAKES_DEFECTS does not list must land in
    # hygiene rather than crash or vanish.
    analysis = analyze_python("def handler(c, i):\n    x = 1\n    x = 2\n    return x\n")
    assert analysis["parses"] is True


def test_entrypoint_present_is_silent_and_missing_is_flagged():
    src = "def handler(context, inputs):\n    return inputs\n"
    analysis = analyze_python(src)
    assert analysis["top_level_functions"] == ["handler"]
    assert code_issues(analysis, NO_LITERALS, [], entrypoint="handler") == []
    missing = code_issues(analysis, NO_LITERALS, [], entrypoint="main")
    assert missing == ["declared entrypoint 'main' is not defined in the action source"]


def test_entrypoint_matches_on_the_last_dotted_segment():
    # ABX spells bundled entrypoints "module.function".
    analysis = analyze_python("def handler(context, inputs):\n    return 1\n")
    assert code_issues(analysis, NO_LITERALS, [], entrypoint="main.handler") == []


def test_entrypoint_claim_withheld_when_no_function_names_are_known():
    # A nested-only definition, a JavaScript action, a PowerShell action on a
    # host with no PowerShell: nothing to compare against, so no accusation.
    nested = analyze_python(
        "def outer():\n    def handler(c, i):\n        return 1\n    return 1\n"
    )
    assert nested["top_level_functions"] == ["outer"]
    js = analyze_script("exports.handler = function () { return 1; };", "nodejs")
    assert js["top_level_functions"] == []
    assert code_issues(js, NO_LITERALS, [], entrypoint="handler") == []


def test_entrypoint_claim_withheld_when_the_source_does_not_parse():
    broken = analyze_python("def handler(c, i)\n    return 1\n")
    assert broken["parses"] is False
    issues = code_issues(broken, NO_LITERALS, [], entrypoint="main")
    assert not any("entrypoint" in i for i in issues)


def test_url_in_a_comment_is_documentation_and_a_url_in_code_is_coupling():
    src = (
        "# runbook: https://wiki.corp.local/abx-runbook\n"
        "def handler(context, inputs):\n"
        "    return context.request('https://vra.corp.local/iaas/api')\n"
    )
    literals = scan_literals(src, "python")
    assert literals["urls"] == ["https://vra.corp.local/iaas/api"]
    assert any("hardcoded URL(s)" in i for i in code_issues(analyze_python(src), literals, []))
    # Without a runtime the caller gets the old whole-text behaviour.
    assert len(scan_literals(src)["urls"]) == 2


def test_interpolated_hosts_are_not_hardcoded_urls():
    for source in (
        "const url = `https://${aria.host}/api`; ",
        'var url = "https://{aria.host}/api";',
        'url = f"https://{aria.host}/api"',
        "const url = `https://api.${domain}/api`;",
    ):
        assert scan_literals(source)["urls"] == []


def test_dynamic_path_does_not_hide_a_fixed_endpoint():
    source = "const url = `https://api.example.test/items/${item.id}`;"
    assert scan_literals(source, "javascript")["urls"] == ["https://api.example.test/items/"]
    assert scan_literals("const url = `https://api.example.test/api`;")["urls"] == [
        "https://api.example.test/api"
    ]


def test_addresses_and_secrets_still_count_inside_comments():
    # A leaked address or password does not stop being one because it sits in
    # a comment; only the URL scan treats comments as documentation.
    src = "# old host was 10.20.30.40\n# password = 'Sekret123'\nx = 1\n"
    literals = scan_literals(src, "python")
    assert literals["ips"] == ["10.20.30.40"]
    assert literals["secrets"] == ["password"]


def test_strip_comments_handles_block_comments():
    js = "/* header\n   still header */\nvar x = 1; // trailing\n"
    assert strip_comments(js, "nodejs") == "var x = 1; // trailing"
    ps = "<# help #>\nWrite-Output 1\n# note\n"
    assert strip_comments(ps, "powershell") == "Write-Output 1"


def test_declared_inputs_never_read_is_pedantic_and_needs_evidence():
    analysis = analyze_python("def handler(c, inputs):\n    return inputs['host']\n")
    assert analysis["read_input_keys"] == ["host"]
    assert pedantic_issues(analysis, ["host", "domain"]) == ["declared input(s) never read: domain"]
    # Reads nothing by literal key: the source may build keys at runtime, so
    # no claim is made about any declared input.
    opaque = analyze_python("def handler(c, inputs):\n    return list(inputs.values())\n")
    assert pedantic_issues(opaque, ["host", "domain"]) == []


def test_input_keys_read_through_get_and_in_the_regex_runtimes():
    py = analyze_python("def handler(c, inputs):\n    return inputs.get('mode')\n")
    assert py["read_input_keys"] == ["mode"]
    js = analyze_script("exports.handler = (c, inputs) => inputs.mode;", "nodejs")
    assert js["read_input_keys"] == ["mode"]
    ps = analyze_script("Write-Output $inputs.mode", "powershell")
    assert ps["read_input_keys"] == ["mode"]


def test_print_without_a_logger_is_pedantic_only():
    analysis = analyze_python("def handler(c, i):\n    print('done')\n")
    assert code_issues(analysis, NO_LITERALS, []) == []
    assert any("no logger" in i for i in pedantic_issues(analysis))
    logged = analyze_python("import logging\n\ndef handler(c, i):\n    print('done')\n")
    assert not any("no logger" in i for i in pedantic_issues(logged))


def test_javascript_structure_from_esprima():
    """Real metrics, not size alone: the whole point of bundling a parser."""
    metrics, reason = parse_javascript_structure(
        "function pad(n) { return n < 10 ? '0' + n : n }\n"
        "try { for (var i = 0; i < 3; i++) { log(pad(i)) } } catch (e) { throw e }\n"
        "try { risky() } catch (e) {}\n"
    )
    assert reason is None
    assert metrics["parses"] is True
    assert metrics["functions"] == 1
    assert metrics["top_level_functions"] == ["pad"]
    # ternary, for, and both catch clauses
    assert metrics["branches"] == 4
    assert metrics["has_error_handling"] is True
    assert metrics["reraise_only_excepts"] == 1  # catch (e) { throw e }
    assert metrics["swallowed_excepts"] == 1  # catch (e) {}


def test_a_translating_catch_is_not_a_reraise():
    """`throw new Error(...)` changes behaviour, exactly as a Python `raise
    Other(...) from e` does, so it must not be flagged."""
    metrics, _ = parse_javascript_structure("try { x() } catch (e) { throw new Error('nope') }")
    assert metrics["reraise_only_excepts"] == 0
    assert metrics["swallowed_excepts"] == 0


def test_an_action_body_parses_and_the_wrapper_is_not_counted():
    """An Orchestrator action IS a function body: a top-level return is
    correct there and illegal in a bare script. The synthetic wrapper used to
    parse it must not show up as one of the action's own functions."""
    metrics, reason = parse_javascript_structure(
        "function helper() { return 1 }\nif (inputs.host) { return helper() }\nreturn null;"
    )
    assert reason is None
    assert metrics["functions"] == 1  # helper, not helper + wrapper
    assert metrics["top_level_functions"] == ["helper"]
    assert metrics["branches"] == 1


def test_broken_javascript_is_reported_as_broken():
    metrics, reason = parse_javascript_structure("var x = ;")
    assert metrics is None and reason


@pytest.mark.skipif(shutil.which("node") is None, reason="no node binary on PATH")
def test_node_refereest_syntax_newer_than_esprima():
    """esprima is an ES2017 parser. Optional chaining is valid JavaScript it
    cannot read, and calling such an action broken would be a false defect -
    so node is asked, and a source it accepts keeps its heuristics instead."""
    assert node_available() is True
    results = parse_javascript_batch(
        [
            "return inputs.host;",
            "exports.handler = function (context, inputs) { return 1; };",
            "var x = ;",
            "const x = a?.b ?? c;",
        ]
    )
    assert results is not None
    assert results[0]["parses"] is True
    assert results[1]["parses"] is True
    assert results[2]["parses"] is False
    assert results[2]["parse_error"].startswith("does not parse as JavaScript:")
    # Accepted by node, so not broken - but no structure is claimed for it.
    assert results[3] == {"parses": True, "parse_error": None}


def test_no_node_means_no_verdict_on_what_esprima_rejected(monkeypatch):
    """With nothing to referee an esprima rejection, the source keeps its
    heuristics and no parse claim is made either way."""
    monkeypatch.setattr("vcf_automation_assessment_tool.codequality.shutil.which", lambda _: None)
    results = parse_javascript_batch(["var ok = 1;", "const x = a?.b ?? c;"])
    assert results is not None
    assert results[0]["parses"] is True
    assert results[1] is None  # untouched, not downgraded
    assert node_available() is False


def test_javascript_parse_error_wording_replaces_the_python_one():
    analysis = analyze_script("var x = ;", "nodejs")
    analysis.update({"parses": False, "parse_error": "does not parse as JavaScript: bad token"})
    assert code_issues(analysis, NO_LITERALS, []) == ["does not parse as JavaScript: bad token"]


def test_empty_batches_are_no_ops():
    assert parse_javascript_batch([]) is None


@pytest.mark.skipif(
    shutil.which("pwsh") is None and shutil.which("powershell") is None,
    reason="no PowerShell binary on PATH",
)
def test_powershell_reports_only_script_level_function_names():
    # A nested helper is not reachable as an entrypoint, so it must not count
    # as one - otherwise a genuinely unreachable entrypoint reads as resolved.
    from vcf_automation_assessment_tool.codequality import parse_powershell_batch

    rows = parse_powershell_batch(
        [
            "function Invoke-Handler { param($c, $i) Write-Output $i }\nInvoke-Handler",
            "function Outer { function Inner { 1 }; Inner }",
            "Write-Output 'no functions here'",
        ]
    )
    assert rows is not None
    assert rows[0]["top_level_functions"] == ["Invoke-Handler"]
    assert rows[1]["top_level_functions"] == ["Outer"]
    assert rows[2]["top_level_functions"] == []
