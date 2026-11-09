import json
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from conftest import FIXTURES
from slsec import tools
from slsec.config import ConfigError, load_config
from slsec.hooks import sast_hook as hook

RULES = FIXTURES / "sast-rules-test"
TARGETS = RULES / "targets"
STUB = RULES / "stub_engine.py"


@pytest.fixture
def repo(git_repo, monkeypatch):
    """A git repo (cwd) with the test rule packs and stub-engine plumbing."""
    monkeypatch.setenv("SLSEC_SAST_RULES_DIR", str(RULES))
    monkeypatch.delenv("SLSEC_OPENGREP_PATH", raising=False)
    log = git_repo / "stub.log"
    monkeypatch.setenv("STUB_LOG", str(log))
    monkeypatch.delenv("STUB_RC", raising=False)
    shutil.copy(TARGETS / "insecure.py", git_repo / "app.py")
    shutil.copy(TARGETS / "insecure.js", git_repo / "app.js")
    (git_repo / "README.md").write_text("hi\n")
    return git_repo


@pytest.fixture
def stub(monkeypatch, repo):
    """Replace the real engine with the stub script; returns a reader for its calls."""
    import os

    def fake_resolve(name, env=None):
        return [sys.executable, str(STUB)], dict(os.environ)

    monkeypatch.setattr(hook, "resolve_engine", fake_resolve)

    def calls():
        log = repo / "stub.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    return calls


def write_cfg(root: Path, text: str) -> None:
    (root / ".slsec.yaml").write_text(text)


# ------------------------------------------------------------------ pack selection


@pytest.mark.parametrize(
    "path,pack",
    [
        ("src/Main.java", "java"),
        ("app/Build.kt", "kotlin"),
        ("build.gradle.kts", "kotlin"),
        ("web/app.js", "javascript"),
        ("web/app.TSX", "javascript"),
        ("web/view.jsx", "javascript"),
        ("lib/x.mjs", "javascript"),
        ("lib/x.cjs", "javascript"),
        ("lib/x.ts", "javascript"),
        ("pkg/x.py", "python"),
        ("cmd/main.go", "go"),
        ("Svc/Program.cs", "csharp"),
        ("README.md", None),
        ("main.tf", None),
    ],
)
def test_pack_for(path, pack):
    assert hook.pack_for(path) == pack


def test_select_packs_by_extension(repo):
    packs, targets = hook.select_packs(["app.py", "app.js", "README.md", "gone.py"], RULES)
    assert [p for p, _ in packs] == ["javascript", "python"]
    assert targets == ["app.js", "app.py"]  # deleted file and non-source file dropped


def test_missing_or_empty_pack_is_skipped(repo, tmp_path):
    root = tmp_path / "rules"
    (root / "go").mkdir(parents=True)  # empty pack
    (root / "python").mkdir()
    (root / "python" / "r.yaml").write_text("rules: []\n")
    (repo / "main.go").write_text("package main\n")
    (repo / "Main.java").write_text("class Main {}\n")  # no java pack at all
    packs, targets = hook.select_packs(["main.go", "Main.java", "app.py"], root)
    assert [p for p, _ in packs] == ["python"]
    assert targets == ["app.py"]


def test_windows_separators_normalised(repo):
    (repo / "pkg").mkdir()
    shutil.copy(TARGETS / "insecure.py", repo / "pkg" / "m.py")
    _, targets = hook.select_packs(["pkg\\m.py"], RULES)
    assert targets == ["pkg/m.py"]


def test_rules_root_default_is_bundled(monkeypatch):
    assert hook.rules_root({}).parts[-2:] == ("configs", "sast-rules")
    assert hook.rules_root({"SLSEC_SAST_RULES_DIR": "x"}) == Path("x")


# ------------------------------------------------------------------ argument building


def test_build_args_opengrep(tmp_path):
    cfg = load_config(tmp_path, env={})
    packs = [("python", RULES / "python"), ("javascript", RULES / "javascript")]
    args = hook.build_args("opengrep", packs, cfg)
    assert args[0] == "scan"
    assert "--error" in args and "--disable-version-check" in args and "--no-rewrite-rule-ids" in args
    assert not any(a.startswith("--metrics") for a in args)  # opengrep rejects --metrics
    assert [args[i + 1] for i, a in enumerate(args) if a == "--config"] == [str(p) for _, p in packs]
    assert "--exclude-rule" not in args


def test_build_args_semgrep_and_reports(tmp_path):
    write_cfg(tmp_path, "sast:\n  exclude_rules:\n    - {id: rule-a, reason: noisy}\n    - {id: rule-b, reason: fp}\n")
    cfg = load_config(tmp_path, env={})
    args = hook.build_args("semgrep", [("python", RULES / "python")], cfg, tmp_path / "o.sarif", tmp_path / "o.xml")
    assert "--metrics=off" in args
    assert [args[i + 1] for i, a in enumerate(args) if a == "--exclude-rule"] == ["rule-a", "rule-b"]
    assert f"--sarif-output={tmp_path / 'o.sarif'}" in args
    assert f"--junit-xml-output={tmp_path / 'o.xml'}" in args


def test_batch_targets():
    targets = [f"src/file_{i:03d}.py" for i in range(100)]
    batches = hook.batch_targets(targets, base_len=100, limit=600)
    assert sum(batches, []) == targets
    assert len(batches) > 1
    assert all(sum(len(t) + 3 for t in b) <= 500 for b in batches)
    assert hook.batch_targets(targets, base_len=10) == [targets]


# ------------------------------------------------------------------ config


def test_sast_config_excludes_and_expiry(tmp_path):
    write_cfg(
        tmp_path,
        "sast:\n  exclude_rules:\n"
        "    - {id: keep-me, reason: accepted risk, expires: 2099-01-01}\n"
        "    - {id: old-one, reason: was noisy, expires: 2020-01-01}\n",
    )
    cfg = load_config(tmp_path, env={})
    assert [s.id for s in cfg.sast_excludes] == ["keep-me"]
    assert [s.id for s in cfg.sast_expired] == ["old-one"]


def test_sast_config_requires_reason(tmp_path):
    write_cfg(tmp_path, "sast:\n  exclude_rules:\n    - {id: x}\n")
    with pytest.raises(ConfigError, match="reason"):
        load_config(tmp_path, env={})


def test_sast_config_defaults(tmp_path):
    cfg = load_config(tmp_path, env={})
    assert cfg.sast_excludes == [] and cfg.sast_expired == [] and cfg.sast_engine == "opengrep"


# ------------------------------------------------------------------ hook behaviour (stub engine)


def test_warn_mode_findings_exit_zero(stub, capsys):
    assert hook.run(["app.py", "app.js", "README.md"]) == 0
    (call,) = stub()
    assert call[-2:] == ["app.js", "app.py"]
    assert "mode=warn" in capsys.readouterr().out


def test_block_mode_findings_fail(stub, repo, capsys):
    write_cfg(repo, "mode: block\n")
    assert hook.run(["app.py"]) == 1
    assert "commit blocked" in capsys.readouterr().err


def test_mode_overrides(stub, repo, monkeypatch):
    write_cfg(repo, "mode: warn\n")
    assert hook.run(["app.py", "--mode", "block"]) == 1
    monkeypatch.setenv("SLSEC_MODE", "block")
    assert hook.run(["app.py"]) == 1


def test_clean_scan(stub, repo, monkeypatch):
    write_cfg(repo, "mode: block\n")
    monkeypatch.setenv("STUB_RC", "0")
    assert hook.run(["app.py"]) == 0


def test_no_source_files_is_noop(stub):
    assert hook.run(["README.md", "main.tf"]) == 0
    assert stub() == []


def test_engine_none_is_noop(stub, repo):
    write_cfg(repo, "providers:\n  sast_engine: none\n")
    assert hook.run(["app.py"]) == 0
    assert stub() == []


def test_invalid_config_fails_closed(stub, repo):
    write_cfg(repo, "sast: [oops]\n")
    assert hook.run(["app.py"]) == 2


def test_scanner_error_warns_unless_strict(stub, repo, monkeypatch, capsys):
    monkeypatch.setenv("STUB_RC", "7")
    write_cfg(repo, "mode: block\n")
    assert hook.run(["app.py"]) == 0
    assert "WARNING" in capsys.readouterr().err
    write_cfg(repo, "mode: block\nstrict: true\n")
    assert hook.run(["app.py"]) == 2


def test_excludes_honoured_and_expired_ignored(stub, repo, capsys):
    write_cfg(
        repo,
        "sast:\n  exclude_rules:\n"
        "    - {id: slsec-test-js-eval, reason: test, expires: 2099-01-01}\n"
        "    - {id: slsec-test-python-eval, reason: was noisy, expires: 2020-01-01}\n",
    )
    hook.run(["app.py", "app.js"])
    (call,) = stub()
    excluded = [call[i + 1] for i, a in enumerate(call) if a == "--exclude-rule"]
    assert excluded == ["slsec-test-js-eval"]
    out = capsys.readouterr().out
    assert "slsec-test-python-eval expired on 2020-01-01" in out


def test_reports_written_with_exact_names(stub, repo, monkeypatch):
    reports = repo / "reports"
    monkeypatch.setenv("SLSEC_REPORT_DIR", str(reports))
    hook.run(["app.py", "app.js"])
    assert sorted(p.name for p in reports.iterdir()) == ["slsec-sast.sarif", "slsec-sast.xml"]
    sarif = json.loads((reports / "slsec-sast.sarif").read_text())
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in sarif["runs"][0]["results"]]
    assert uris == ["app.js", "app.py"]  # forward slashes even on Windows
    root = ET.parse(str(reports / "slsec-sast.xml")).getroot()
    assert root.tag == "testsuites" and root.get("failures") == "2"


def test_report_dir_flag(stub, repo):
    hook.run(["app.py", "--report-dir", "out"])
    assert (repo / "out" / "slsec-sast.sarif").is_file()


def test_batches_are_merged_into_one_report(stub, repo, monkeypatch):
    (repo / "pkg").mkdir()
    names = []
    for i in range(12):
        name = f"pkg/module_{i:02d}.py"
        shutil.copy(TARGETS / "insecure.py", repo / name)
        names.append(name)
    monkeypatch.setattr(hook, "CMDLINE_LIMIT", hook._cmd_len([sys.executable, str(STUB)] + hook.build_args(
        "opengrep", [("python", RULES / "python")], load_config(repo, env={}), repo / "r" / "x.sarif", repo / "r" / "x.xml"
    )) + 70)
    monkeypatch.setenv("SLSEC_REPORT_DIR", str(repo / "r"))
    write_cfg(repo, "mode: block\n")
    assert hook.run(names) == 1
    calls = stub()
    assert len(calls) > 1
    sarif = json.loads((repo / "r" / "slsec-sast.sarif").read_text())
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 12
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert ET.parse(str(repo / "r" / "slsec-sast.xml")).getroot().get("tests") == "12"
    assert sorted(p.name for p in (repo / "r").iterdir()) == ["slsec-sast.sarif", "slsec-sast.xml"]


# ------------------------------------------------------------------ engine availability


def test_opengrep_unavailable_warns(repo, monkeypatch, capsys):
    def no_tool(name, env=None, key=None):
        raise tools.ToolError("could not download opengrep: offline")

    monkeypatch.setattr(tools, "ensure_tool", no_tool)
    assert hook.run(["app.py"]) == 0
    err = capsys.readouterr().err
    assert "opengrep is unavailable" in err and "offline" in err


def test_opengrep_unavailable_strict_fails(repo, monkeypatch):
    monkeypatch.setattr(tools, "ensure_tool", lambda *a, **k: (_ for _ in ()).throw(tools.ToolError("offline")))
    write_cfg(repo, "strict: true\n")
    assert hook.run(["app.py"]) == 2


def test_semgrep_unavailable_warns(repo, monkeypatch, capsys):
    monkeypatch.setattr(hook, "find_semgrep", lambda env=None: None)
    write_cfg(repo, "providers:\n  sast_engine: semgrep\n")
    assert hook.run(["app.py"]) == 0
    assert "semgrep is not installed" in capsys.readouterr().err
    write_cfg(repo, "strict: true\nproviders:\n  sast_engine: semgrep\n")
    assert hook.run(["app.py"]) == 2


def test_resolve_semgrep_puts_its_dir_on_path(monkeypatch, tmp_path):
    exe = tmp_path / "venv" / "Scripts" / "semgrep.exe"
    monkeypatch.setattr(hook, "find_semgrep", lambda env=None: str(exe))
    prefix, env = hook.resolve_engine("semgrep", {"PATH": "orig"})
    assert prefix == [str(exe)]
    assert env["PATH"].startswith(str(exe.parent)) and env["PATH"].endswith("orig")
    assert env["SEMGREP_SEND_METRICS"] == "off"


def test_resolve_opengrep_uses_tools(monkeypatch, tmp_path):
    fake = tmp_path / "opengrep.exe"
    monkeypatch.setattr(tools, "ensure_tool", lambda name, env=None, key=None: fake)
    prefix, _ = hook.resolve_engine("opengrep", {})
    assert prefix == [str(fake)]


def test_engine_fails_to_start(repo, monkeypatch, tmp_path):
    monkeypatch.setattr(hook, "resolve_engine", lambda name, env=None: ([str(tmp_path / "missing.exe")], {}))
    assert hook.run(["app.py"]) == 0


# ------------------------------------------------------------------ real engines


def _real_scan(repo, monkeypatch, engine):
    write_cfg(repo, f"mode: block\nproviders:\n  sast_engine: {engine}\n")
    monkeypatch.setenv("SLSEC_REPORT_DIR", str(repo / "reports"))
    rc = hook.run(["app.py", "app.js"])
    sarif = json.loads((repo / "reports" / "slsec-sast.sarif").read_text(encoding="utf-8"))
    found = sorted(
        (r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]) for r in sarif["runs"][0]["results"]
    )
    return rc, found


EXPECTED = [("slsec-test-js-eval", "app.js"), ("slsec-test-python-eval", "app.py")]


@pytest.mark.integration
def test_real_opengrep_scan(repo, monkeypatch):
    try:
        tools.ensure_tool("opengrep")
    except tools.ToolError as exc:
        pytest.skip(f"opengrep unavailable (offline?): {exc}")

    rc, found = _real_scan(repo, monkeypatch, "opengrep")
    assert rc == 1
    assert found == EXPECTED
    assert (repo / "reports" / "slsec-sast.xml").is_file()

    # warn mode: same findings, exit 0
    write_cfg(repo, "providers:\n  sast_engine: opengrep\n")
    assert hook.run(["app.py", "app.js"]) == 0

    # exclusions are honoured by the real engine
    write_cfg(
        repo,
        "mode: block\nsast:\n  exclude_rules:\n"
        "    - {id: slsec-test-python-eval, reason: test}\n    - {id: slsec-test-js-eval, reason: test}\n",
    )
    assert hook.run(["app.py", "app.js"]) == 0

    # clean file in block mode
    shutil.copy(TARGETS / "secure.py", repo / "ok.py")
    write_cfg(repo, "mode: block\n")
    assert hook.run(["ok.py"]) == 0


@pytest.mark.integration
def test_real_semgrep_scan_matches_opengrep(repo, monkeypatch):
    if hook.find_semgrep() is None:
        pytest.skip("semgrep not installed (pip install 'slsec[semgrep]')")
    rc, found = _real_scan(repo, monkeypatch, "semgrep")
    assert rc == 1
    assert found == EXPECTED
