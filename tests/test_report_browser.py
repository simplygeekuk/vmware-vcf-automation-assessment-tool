"""Optional real-browser validation using an installed Chromium and Node 22+."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from vcf_automation_assessment_tool.checks import run_checks
from vcf_automation_assessment_tool.flows import build_flows
from vcf_automation_assessment_tool.report.renderer import render_report


def test_offline_report_browser_controls(sample_data, tmp_path):
    node = shutil.which("node")
    candidates = []
    if os.environ.get("REPORT_TEST_CHROME"):
        candidates.append(Path(os.environ["REPORT_TEST_CHROME"]))
    if os.environ.get("LOCALAPPDATA"):
        candidates.extend(
            (Path(os.environ["LOCALAPPDATA"]) / "ms-playwright").glob(
                "chromium-*/chrome-win64/chrome.exe"
            )
        )
    for name in ("chromium", "chromium-browser", "google-chrome"):
        if shutil.which(name):
            candidates.append(Path(shutil.which(name)))
    chrome = next((p for p in candidates if p.is_file()), None)
    if not node or not chrome:
        pytest.skip("Node 22+ and Chromium required; REPORT_TEST_CHROME can name a browser")
    version = subprocess.run([node, "--version"], capture_output=True, text=True, check=True)
    if int(version.stdout.lstrip("v").split(".")[0]) < 22:
        pytest.skip("Node 22+ required for built-in WebSocket")
    build_flows(sample_data)
    run_checks(sample_data)
    report = tmp_path / "browser-report.html"
    render_report(sample_data, str(report))
    result = subprocess.run(
        [
            node,
            str(Path(__file__).with_name("report_browser.cjs")),
            str(chrome),
            str(report),
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Browser checks passed:" in result.stdout, result.stdout + result.stderr
