"""Tests for slsec-sca. Everything runs against stub CLIs, so no tokens or network are needed.

The stubs are one small Python script (below) exposed on PATH as `osv-scanner`, `snyk` and `jf`
(a `.cmd` wrapper on Windows, a `sh` script elsewhere). Behaviour is selected by env vars:

  STUB_EXIT        exit code of the scan command (default 0)
  STUB_SARIF       SARIF text the scan writes (to the sarif flag's path, or stdout for jf)
  STUB_SLEEP       seconds to sleep in the scan command (timeout tests)
  STUB_JF_CONFIG   "1" if `jf c show` should list a server
  STUB_SNYK_API    value printed by `snyk config get api` (empty = not logged in)
  STUB_LOG         file that gets one JSON line (argv + cwd) per invocation
"""

import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest

from slsec import tools
from slsec.hooks import sca_hook as sca

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "sca"

STUB = r'''
import json, os, sys, time
name, args = sys.argv[1], sys.argv[2:]
log = os.environ.get("STUB_LOG")
if log:
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"tool": name, "args": args, "cwd": os.getcwd()}) + "\n")
sarif = os.environ.get("STUB_SARIF", '{"version": "2.1.0", "runs": [{"results": [{"ruleId": "X"}]}]}')
code = int(os.environ.get("STUB_EXIT", "0"))
if name == "snyk" and args[:3] == ["config", "get", "api"]:
    print(os.environ.get("STUB_SNYK_API", ""))
    sys.exit(0)
if name == "jf" and args[:2] == ["c", "show"]:
    if os.environ.get("STUB_JF_CONFIG") == "1":
        print("Server ID: test\nJFrog Platform URL: https://example.invalid/")
    sys.exit(0)
time.sleep(float(os.environ.get("STUB_SLEEP", "0")))
for i, a in enumerate(args):
    if a == "--output-file":
        Path = __import__("pathlib").Path
        Path(args[i + 1]).write_text(sarif, encoding="utf-8")
    if a.startswith("--sarif-file-output="):
        __import__("pathlib").Path(a.split("=", 1)[1]).write_text(sarif, encoding="utf-8")
if name == "jf" and "sarif" in args:
    print(sarif)
else:
    print("stub scan output")
sys.exit(code)
'''

# provider -> (stub CLI name, extra env that makes it "logged in")
PROVIDER_SPECS = {
    "osv": ("osv-scanner", {}),
    "snyk": ("snyk", {"SNYK_TOKEN": "stub-not-a-real-token"}),
    "jfrog": ("jf", {"STUB_JF_CONFIG": "1"}),
}
# provider -> (exit code for findings, exit code for tool error, exit codes meaning "nothing to scan")
EXIT_CODES = {
    "osv": (1, 127, [128]),
    "snyk": (1, 2, [3]),
    "jfrog": (3, 1, []),
}
SARIF_ONE = '{"version": "2.1.0", "runs": [{"results": [{"ruleId": "CVE-2020-1"}]}]}'


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    for var in ("SNYK_TOKEN", "SNYK_OAUTH_TOKEN", "SLSEC_CI", "CI", "SLSEC_STRICT", "SLSEC_SCA_TIMEOUT", "STUB_EXIT",
                "STUB_SARIF", "STUB_SLEEP", "STUB_JF_CONFIG", "STUB_SNYK_API", "STUB_LOG"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))  # no snyk configstore
    def _no_download(name, *a, **k):
        raise tools.ToolError("downloads are disabled in tests")

    monkeypatch.setattr(sca.tools, "ensure_tool", _no_download)  # never download osv-scanner in tests


@pytest.fixture
def stubs(tmp_path, monkeypatch):
    """Put stub osv-scanner / snyk / jf on PATH; returns the call-log path."""
    bindir = tmp_path / "stubbin"
    bindir.mkdir()
    script = bindir / "stub_cli.py"
    script.write_text(STUB, encoding="utf-8")
    for name, short in (("osv-scanner", "osv-scanner"), ("snyk", "snyk"), ("jf", "jf")):
        if os.name == "nt":
            (bindir / f"{name}.cmd").write_text(
                f'@"{sys.executable}" "{script}" {short} %*\r\n', encoding="utf-8"
            )
        else:
            wrapper = bindir / name
            wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" {short} "$@"\n', encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv("STUB_LOG", str(log))
    return log


def calls(log: Path):
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def scans(log: Path):
    """Calls that are actual scans (not auth probes)."""
    return [c for c in calls(log) if c["args"][:1] != ["config"] and c["args"][:1] != ["c"]]


def login(monkeypatch, provider):
    for k, v in PROVIDER_SPECS[provider][1].items():
        monkeypatch.setenv(k, v)


def write_cfg(repo: Path, text: str):
    (repo / ".slsec.yaml").write_text(text, encoding="utf-8")


def hook(provider, *files, extra=()):
    return sca.run(["--provider", provider, *extra, *files])


# ------------------------------------------------------------ target mapping


@pytest.mark.parametrize(
    "path",
    [
        "package.json", "a/package-lock.json", "npm-shrinkwrap.json", "x/yarn.lock", "pnpm-lock.yaml",
        "pom.xml", "svc/build.gradle", "build.gradle.kts", "gradle.lockfile", "gradle/libs.versions.toml",
        "requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock", "uv.lock",
        "go.mod", "go.sum", "App/App.csproj", "packages.lock.json", "Directory.Packages.props", "packages.config",
    ],
)
def test_is_manifest_true(path):
    assert sca.is_manifest(path)


@pytest.mark.parametrize("path", ["README.md", "main.py", "package.json.bak", "src/requirements.py", "Dockerfile"])
def test_is_manifest_false(path):
    assert not sca.is_manifest(path)


def test_scan_dirs_maps_and_dedupes():
    files = [
        "package.json", "package-lock.json",
        "svc/api/pom.xml", "svc\\api\\build.gradle",
        "svc/web/requirements.txt", "svc/web/requirements-dev.txt", "README.md",
        "node_modules/left-pad/package.json",
    ]
    assert sca.scan_dirs(files) == [".", "svc/api", "svc/web"]


def test_scan_dirs_empty_when_no_manifests():
    assert sca.scan_dirs(["a.py", "docs/readme.md"]) == []


def test_hook_manifest_regex_matches_python_classifier():
    import re
    import yaml

    root = Path(__file__).resolve().parents[1]
    hooks = {h["id"]: h for h in yaml.safe_load((root / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))}
    for pid in ("slsec-osv", "slsec-snyk", "slsec-jfrog"):
        h = hooks[pid]
        assert h["entry"].startswith("slsec-sca --provider ")
        assert "pre-push" in h["stages"] and h["verbose"] and h["require_serial"]
        rx = re.compile(h["files"])
        for p in ("package.json", "deep/er/requirements-dev.txt", "a/b/Foo.csproj", "gradle/libs.versions.toml"):
            assert rx.search(p), (pid, p)
        for p in ("main.py", "xpackage.json", "a/requirements.py"):
            assert not rx.search(p), (pid, p)


# ------------------------------------------------------------- per provider


@pytest.mark.parametrize("provider", sorted(PROVIDER_SPECS))
class TestProvider:
    def test_no_relevant_files_skips_cli(self, provider, git_repo, stubs, monkeypatch):
        login(monkeypatch, provider)
        assert hook(provider, "main.py", "README.md") == 0
        assert hook(provider) == 0
        assert calls(stubs) == []

    def test_cli_missing_warns_then_strict_fails(self, provider, git_repo, monkeypatch, capsys):
        monkeypatch.setattr(sca.shutil, "which", lambda *a, **k: None)
        assert hook(provider, "package.json") == 0
        err = capsys.readouterr().err
        assert "CLI was not found" in err and "CI will still enforce" in err
        write_cfg(git_repo, "strict: true\n")
        assert hook(provider, "package.json") == 1
        assert "strict mode is on" in capsys.readouterr().err

    def test_unauthenticated_warns(self, provider, git_repo, stubs, monkeypatch, capsys):
        if provider == "osv":
            pytest.skip("osv-scanner needs no login")
        assert hook(provider, "package.json") == 0
        assert scans(stubs) == []
        err = capsys.readouterr().err
        assert "skipped" in err and "CI will still enforce" in err

    def test_unauthenticated_strict_fails_in_ci_too(self, provider, git_repo, stubs, monkeypatch):
        if provider == "osv":
            pytest.skip("osv-scanner needs no login")
        write_cfg(git_repo, "strict: true\n")
        assert hook(provider, "package.json") == 1
        # no CI exemption: an expired token must not silently turn the scan off
        monkeypatch.setenv("CI", "true")
        monkeypatch.setenv("SLSEC_CI", "1")
        assert hook(provider, "package.json") == 1

    def test_slsec_strict_env_overrides_file(self, provider, git_repo, stubs, monkeypatch):
        if provider == "osv":
            pytest.skip("osv-scanner needs no login")
        monkeypatch.setenv("SLSEC_STRICT", "1")  # what the CI templates set
        assert hook(provider, "package.json") == 1
        write_cfg(git_repo, "strict: true\n")
        monkeypatch.setenv("SLSEC_STRICT", "0")
        assert hook(provider, "package.json") == 0

    def test_clean(self, provider, git_repo, stubs, monkeypatch):
        login(monkeypatch, provider)
        assert hook(provider, "package.json") == 0
        assert len(scans(stubs)) == 1

    def test_no_supported_projects_is_clean(self, provider, git_repo, stubs, monkeypatch):
        codes = EXIT_CODES[provider][2]
        if not codes:
            pytest.skip("no such exit code for this provider")
        login(monkeypatch, provider)
        monkeypatch.setenv("STUB_EXIT", str(codes[0]))
        write_cfg(git_repo, "mode: block\nstrict: true\n")
        assert hook(provider, "package.json") == 0

    def test_findings_warn_mode_exit_0(self, provider, git_repo, stubs, monkeypatch, capsys):
        login(monkeypatch, provider)
        monkeypatch.setenv("STUB_EXIT", str(EXIT_CODES[provider][0]))
        assert hook(provider, "package.json") == 0
        assert "mode=warn" in capsys.readouterr().out

    def test_findings_block_mode_exit_1(self, provider, git_repo, stubs, monkeypatch, capsys):
        login(monkeypatch, provider)
        monkeypatch.setenv("STUB_EXIT", str(EXIT_CODES[provider][0]))
        write_cfg(git_repo, "mode: block\n")
        assert hook(provider, "package.json") == 1
        assert "push blocked" in capsys.readouterr().err

    def test_tool_error_is_unavailable_not_findings(self, provider, git_repo, stubs, monkeypatch, capsys):
        login(monkeypatch, provider)
        monkeypatch.setenv("STUB_EXIT", str(EXIT_CODES[provider][1]))
        write_cfg(git_repo, "mode: block\n")  # block mode must NOT fail on a tool error
        assert hook(provider, "package.json") == 0
        assert "skipped" in capsys.readouterr().err
        write_cfg(git_repo, "mode: block\nstrict: true\n")
        assert hook(provider, "package.json") == 1

    def test_timeout_warns(self, provider, git_repo, stubs, monkeypatch, capsys):
        login(monkeypatch, provider)
        monkeypatch.setenv("STUB_SLEEP", "4")
        monkeypatch.setenv("SLSEC_SCA_TIMEOUT", "1")
        write_cfg(git_repo, "mode: block\n")
        t0 = time.time()
        assert hook(provider, "package.json") == 0
        assert "timed out after 1s" in capsys.readouterr().err
        assert time.time() - t0 < 30

    def test_sarif_report_written(self, provider, git_repo, stubs, monkeypatch, tmp_path):
        login(monkeypatch, provider)
        monkeypatch.setenv("STUB_EXIT", str(EXIT_CODES[provider][0]))
        monkeypatch.setenv("STUB_SARIF", SARIF_ONE)
        out = tmp_path / "reports" / "nested"
        monkeypatch.setenv("SLSEC_REPORT_DIR", str(out))
        assert hook(provider, "package.json") == 0
        report = out / f"slsec-{provider}.sarif"
        doc = json.loads(report.read_text(encoding="utf-8"))
        assert doc["runs"][0]["results"][0]["ruleId"] == "CVE-2020-1"

    def test_no_report_without_report_dir(self, provider, git_repo, stubs, monkeypatch, tmp_path):
        login(monkeypatch, provider)
        assert hook(provider, "package.json") == 0
        assert not list(tmp_path.rglob("slsec-*.sarif"))


# -------------------------------------------------- provider-specific details


def test_osv_command_shape(git_repo, stubs, monkeypatch):
    assert hook("osv", "svc/a/package.json", "svc/b/requirements.txt", "svc/b/requirements-dev.txt") == 0
    (call,) = scans(stubs)
    assert call["args"] == ["scan", "source", "svc/a", "svc/b"]


def test_snyk_runs_once_per_dir_in_that_dir_and_merges_sarif(git_repo, stubs, monkeypatch, tmp_path):
    login(monkeypatch, "snyk")
    (git_repo / "a").mkdir()
    (git_repo / "b").mkdir()
    monkeypatch.setenv("STUB_EXIT", "1")
    monkeypatch.setenv("STUB_SARIF", SARIF_ONE)
    monkeypatch.setenv("SLSEC_REPORT_DIR", str(tmp_path / "rep"))
    assert hook("snyk", "a/package.json", "b/package.json", "b/package-lock.json") == 0
    got = scans(stubs)
    assert [Path(c["cwd"]).name for c in got] == ["a", "b"]
    assert all(c["args"][:2] == ["test", "--all-projects"] for c in got)
    doc = json.loads((tmp_path / "rep" / "slsec-snyk.sarif").read_text(encoding="utf-8"))
    assert len(doc["runs"]) == 2


def test_snyk_auth_via_cli_config_get(git_repo, stubs, monkeypatch):
    monkeypatch.setenv("STUB_SNYK_API", "stub-not-a-real-token")
    assert hook("snyk", "package.json") == 0
    assert len(scans(stubs)) == 1  # auth probe passed, scan ran


def test_snyk_auth_via_configstore_file(git_repo, stubs, tmp_path):
    store = tmp_path / "xdg" / "configstore"
    store.mkdir(parents=True)
    (store / "snyk.json").write_text('{"api": "stub-not-a-real-token"}', encoding="utf-8")
    assert hook("snyk", "package.json") == 0
    assert [c["args"][0] for c in calls(stubs)] == ["test"]  # no subprocess needed for auth


def test_jfrog_audit_uses_working_dirs(git_repo, stubs, monkeypatch):
    login(monkeypatch, "jfrog")
    assert hook("jfrog", "a/pom.xml", "b/go.mod") == 0
    (call,) = scans(stubs)
    assert call["args"] == ["audit", "--working-dirs", "a,b"]


def test_jfrog_sarif_flag_only_with_report_dir(git_repo, stubs, monkeypatch, tmp_path):
    login(monkeypatch, "jfrog")
    monkeypatch.setenv("SLSEC_REPORT_DIR", str(tmp_path / "r"))
    hook("jfrog", "pom.xml")
    assert scans(stubs)[0]["args"][-2:] == ["--format", "sarif"]


def test_mode_override_flag(git_repo, stubs, monkeypatch):
    login(monkeypatch, "osv")
    monkeypatch.setenv("STUB_EXIT", "1")
    assert hook("osv", "go.mod", extra=["--mode", "block"]) == 1


def test_timeout_env_parsing(monkeypatch):
    assert sca.get_timeout({}) == sca.DEFAULT_TIMEOUT
    assert sca.get_timeout({"SLSEC_SCA_TIMEOUT": "42"}) == 42
    assert sca.get_timeout({"SLSEC_SCA_TIMEOUT": "junk"}) == sca.DEFAULT_TIMEOUT
    assert sca.get_timeout({"SLSEC_SCA_TIMEOUT": "-5"}) == sca.DEFAULT_TIMEOUT


def test_osv_falls_back_to_tools_fetcher(git_repo, stubs, monkeypatch, tmp_path):
    """No osv-scanner on PATH -> use the pinned binary from slsec.tools.ensure_tool."""
    real_which = sca.shutil.which
    monkeypatch.setattr(sca.shutil, "which", lambda n, *a, **k: None if n == "osv-scanner" else real_which(n, *a, **k))
    stub = tmp_path / "stubbin" / ("osv-scanner.cmd" if os.name == "nt" else "osv-scanner")
    monkeypatch.setattr(sca.tools, "ensure_tool", lambda name, *a, **k: stub)
    assert hook("osv", "go.mod") == 0
    assert len(scans(stubs)) == 1

    def boom(name, *a, **k):
        raise tools.ToolError("sha256 mismatch")

    monkeypatch.setattr(sca.tools, "ensure_tool", boom)
    assert hook("osv", "go.mod") == 0  # warns, does not crash


def test_fixtures_are_recognised():
    files = [str(p.relative_to(FIXTURES)).replace("\\", "/") for p in FIXTURES.rglob("*") if p.is_file()]
    assert sca.scan_dirs(files) == ["node", "python"]


@pytest.mark.integration
def test_real_osv_scanner_on_fixtures(git_repo, monkeypatch):
    import shutil

    if not shutil.which("osv-scanner"):
        pytest.skip("osv-scanner not installed")
    write_cfg(git_repo, "mode: block\n")
    rc = sca.run(["--provider", "osv", str(FIXTURES / "python" / "requirements.txt")])
    assert rc in (0, 1)
