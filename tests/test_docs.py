"""Docs that can be checked mechanically are: the README findings reference
must list exactly the check ids the code can emit, in both directions - a
check added without a reference row and a row left behind after a check is
retired both fail here instead of waiting for a reader to notice."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTED_ROW = re.compile(r"^\| ([A-Z]{3}-\d{3}) \|", re.MULTILINE)
# Only actual emission points count as implemented: an id can also appear
# in a comment or a docstring that talks about it.
EMITTED_ID = re.compile(r'check_id="([A-Z]{3}-\d{3})"')


def test_readme_findings_reference_matches_the_check_registry():
    src_ids = set()
    for p in (ROOT / "src" / "vcf_automation_assessment_tool" / "checks").glob("*.py"):
        src_ids |= set(EMITTED_ID.findall(p.read_text(encoding="utf-8")))

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("## Findings reference")
    end = readme.find("\n## ", start + 1)
    section = readme[start:end] if end != -1 else readme[start:]
    doc_ids = set(DOCUMENTED_ROW.findall(section))

    ghost = sorted(doc_ids - src_ids)
    undocumented = sorted(src_ids - doc_ids)
    assert not ghost, f"README documents checks the code does not implement: {ghost}"
    assert not undocumented, f"checks missing from the README findings reference: {undocumented}"


def test_every_config_key_is_documented_in_the_example_file():
    """A key the loader accepts but config.example.yaml never mentions is a
    key nobody finds. --pedantic shipped that way and had to be chased."""
    from vcf_automation_assessment_tool.config import CONFIG_KEYS

    example = (ROOT / "config.example.yaml").read_text(encoding="utf-8")
    missing = sorted(k for k in CONFIG_KEYS if k not in example)
    assert not missing, f"config keys absent from config.example.yaml: {missing}"


def test_pedantic_is_settable_from_the_config_file(tmp_path):
    """The flag has to work from config.yaml, not only from the CLI: a config
    file is how this tool is normally run."""
    from vcf_automation_assessment_tool.cli import build_parser
    from vcf_automation_assessment_tool.config import RunConfig

    def load(*body, argv=()):
        lines = ["url: https://x.local", "username: someone", *body]
        path = tmp_path / "config.yaml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        args = build_parser().parse_args(["--config", str(path), *argv])
        return RunConfig.load(args).pedantic

    assert load("pedantic: true") is True
    assert load() is False  # absent from the file
    assert load("pedantic: false") is False
    # An explicit CLI flag still wins over the file, like every other option.
    assert load("pedantic: false", argv=["--pedantic"]) is True


def test_config_example_is_a_template_not_somebody_estate():
    """The file is committed and copied by hand, so it must parse, hold only
    keys the loader accepts, and carry placeholders rather than whatever
    environment it was last edited against."""
    import yaml

    from vcf_automation_assessment_tool.config import CONFIG_KEYS

    text = (ROOT / "config.example.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)

    unknown = sorted(set(data) - CONFIG_KEYS)
    assert not unknown, f"config.example.yaml sets keys the loader ignores: {unknown}"
    # Everything optional stays commented out, so a copy of this file runs as
    # shipped and every uncommented line is a deliberate default.
    assert set(data) == {"url", "username", "ignore_sections", "ignore_findings"}

    # Placeholders, not a real appliance or account.
    assert data["url"].endswith("example.com"), data["url"]
    assert "example" in data["username"], data["username"]

    # The defaults the report is documented as producing.
    assert data["ignore_sections"] == ["replatforming"]
    assert "DEP-002" in data["ignore_findings"]


def test_config_example_loads_through_the_real_config_path(tmp_path):
    """Copying it to config.yaml is the documented way to start, so that copy
    has to survive the loader untouched."""
    from vcf_automation_assessment_tool.cli import build_parser
    from vcf_automation_assessment_tool.config import RunConfig

    path = tmp_path / "config.yaml"
    path.write_text((ROOT / "config.example.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    cfg = RunConfig.load(build_parser().parse_args(["--config", str(path)]))

    assert cfg.url == "https://vra.example.com"
    assert cfg.ignore_sections == ["replatforming"]
    # The contents are an editorial choice that moves; that they survive the
    # loader as upper-case check ids is the contract.
    assert cfg.ignore_findings
    assert all(re.fullmatch(r"[A-Z]{3}-\d{3}", i) for i in cfg.ignore_findings)
    # Defaults survive being commented out rather than arriving as None.
    assert cfg.timeout == 60
    assert cfg.page_size == 100
    assert cfg.max_rows_per_finding == 500
    assert cfg.insecure is False
    assert cfg.validate() == []
