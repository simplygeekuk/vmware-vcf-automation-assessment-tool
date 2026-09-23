"""The README findings reference must track the report's own layout.

It drifted once already: Capability Tags kept its own heading after the
section was folded into Infrastructure, and Consumption stayed below Design
after the report moved it up. Both facts live in code, so bind the doc to it -
section order to the template, each id's placement to the router.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (
    ROOT / "src" / "vcf_automation_assessment_tool" / "report" / "templates" / "report.html.j2"
)

# README heading -> the report section key it documents. A new section has to
# be added here deliberately, which is the point: the test then checks it is
# in the right place and holds the right ids.
HEADING_KEY = {
    "Infrastructure": "infrastructure",
    "Consumption": "consumption",
    "Design and Templates": "design",
    "Extensibility": "extensibility",
    "Policies and Governance": "governance",
    "Replatforming Readiness Report (hidden by default)": "replatforming",
    "System": "system",
}


def _reference_section() -> str:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("## Findings reference")
    end = readme.find("\n## ", start + 1)
    return readme[start:end] if end != -1 else readme[start:]


def _report_order() -> list[str]:
    """Finding chapters in report order, excluding summary and coverage inventories."""
    template = TEMPLATE.read_text(encoding="utf-8")
    keys = re.findall(r'<details class="sec" id="([a-z]+)"', template)
    return [k for k in keys if k not in {"summary", "coverage"}]


def test_reference_headings_are_the_report_sections_in_report_order():
    headings = re.findall(r"^### (.+)$", _reference_section(), re.MULTILINE)
    unknown = [h for h in headings if h not in HEADING_KEY]
    assert not unknown, f"README findings sections not mapped to a report section: {unknown}"
    documented = [HEADING_KEY[h] for h in headings]
    assert documented == _report_order(), (
        f"README documents sections as {documented}, the report renders {_report_order()}"
    )


def test_every_documented_check_sits_under_the_section_it_renders_in():
    from vcf_automation_assessment_tool.report.renderer import _section_for

    section = _reference_section()
    headings = re.findall(r"^### (.+)$", section, re.MULTILINE)
    bodies = re.split(r"^### .+$", section, flags=re.MULTILINE)[1:]

    misplaced = []
    for heading, body in zip(headings, bodies, strict=True):
        for check_id in re.findall(r"^\| ([A-Z]{3}-\d{3}) \|", body, re.MULTILINE):
            renders_in = _section_for(check_id)
            if renders_in != HEADING_KEY[heading]:
                misplaced.append(
                    f"{check_id} is documented under {heading!r} but renders in {renders_in!r}"
                )
    assert not misplaced, misplaced
