"""End to end: the real slsec-sast hook, the real bundled rule packs and the pinned engine.

Each insecure fixture must raise every rule listed in tests/fixtures/sast-expected.yaml and
fail in block mode. Each secure counterpart must come back clean. This is the check that the
hook, the rule bundles and the pinned engine version agree with each other.
"""

import json
import shutil
from pathlib import Path

import pytest
import yaml

from slsec import tools
from slsec.hooks import sast_hook as hook

from conftest import FIXTURES

EXPECTED = yaml.safe_load((FIXTURES / "sast-expected.yaml").read_text(encoding="utf-8"))["fixtures"]


def _matches(check_id: str, rule_id: str) -> bool:
    return check_id == rule_id or check_id.endswith("." + rule_id)


def _scan(repo: Path, monkeypatch, src: Path, engine: str):
    for old in repo.glob("target.*"):
        old.unlink()
    target = repo / f"target{src.suffix}"
    shutil.copy(src, target)
    reports = repo / "reports"
    shutil.rmtree(reports, ignore_errors=True)
    (repo / ".slsec.yaml").write_text(f"mode: block\nproviders:\n  sast_engine: {engine}\n")
    monkeypatch.setenv("SLSEC_REPORT_DIR", str(reports))
    rc = hook.run([target.name])
    sarif = json.loads((reports / "slsec-sast.sarif").read_text(encoding="utf-8"))
    found = {r["ruleId"] for run in sarif["runs"] for r in run.get("results", [])}
    return rc, found


@pytest.fixture
def repo(git_repo, monkeypatch):
    monkeypatch.delenv("SLSEC_SAST_RULES_DIR", raising=False)  # use the real bundled packs
    return git_repo


def _engine_or_skip(engine: str) -> None:
    if engine == "opengrep":
        try:
            tools.ensure_tool("opengrep")
        except tools.ToolError as exc:
            pytest.skip(f"opengrep unavailable (offline?): {exc}")
    elif hook.find_semgrep() is None:
        pytest.skip("semgrep not installed (pip install 'slsec[semgrep]')")


@pytest.mark.integration
@pytest.mark.parametrize("engine", ["opengrep", "semgrep"])
@pytest.mark.parametrize("insecure", sorted(EXPECTED))
def test_bundled_rules_on_fixtures(repo, monkeypatch, engine, insecure):
    _engine_or_skip(engine)
    spec = EXPECTED[insecure]

    rc, found = _scan(repo, monkeypatch, FIXTURES / insecure, engine)
    missing = [r for r in spec["rules"] if not any(_matches(f, r) for f in found)]
    assert not missing, f"{insecure}: expected rules not raised: {missing}; got {sorted(found)}"
    assert rc == 1, f"{insecure}: block mode should fail on findings"

    rc, found = _scan(repo, monkeypatch, FIXTURES / spec["secure"], engine)
    assert not found, f"{spec['secure']}: expected clean, got {sorted(found)}"
    assert rc == 0
