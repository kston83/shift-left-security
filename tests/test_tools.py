"""Tests for slsec.tools: pinned binary fetch, SHA-256 verification and cache.

No network: downloads are served from file:// URLs, or urlopen is patched.
"""

import hashlib
import os
import re
import threading
import urllib.error
from pathlib import Path

import pytest

from slsec import tools

FAKE = "fake-tool"
KEY = "linux-x86_64"  # fixed platform key so tests behave the same on every OS


@pytest.fixture
def payload(tmp_path: Path) -> Path:
    src = tmp_path / "release" / "fake-tool-linux"
    src.parent.mkdir()
    src.write_bytes(b"#!/bin/sh\necho fake-tool 9.9.9\n" + os.urandom(64))
    return src


@pytest.fixture
def fake_registry(monkeypatch, tmp_path: Path, payload: Path):
    """Register FAKE with its asset served from a local file:// URL."""
    spec = {
        "version": "9.9.9",
        "repo": "example/fake-tool",
        "url": payload.parent.as_uri() + "/{asset}",
        "assets": {KEY: {"asset": payload.name, "sha256": hashlib.sha256(payload.read_bytes()).hexdigest()}},
    }
    monkeypatch.setitem(tools.TOOLS, FAKE, spec)
    cache = tmp_path / "cache"
    env = {"SLSEC_CACHE_DIR": str(cache), "PATH": str(tmp_path / "empty-path")}
    return spec, env, cache


def _cache_files(cache: Path):
    return sorted(p.relative_to(cache).as_posix() for p in cache.rglob("*") if p.is_file()) if cache.exists() else []


# ------------------------------------------------------------------ registry


def test_registry_is_well_formed():
    for name, spec in tools.TOOLS.items():
        assert re.fullmatch(r"\d+\.\d+\.\d+", spec["version"]), name
        assert "{asset}" in spec["url"] and "{version}" in spec["url"], name
        assert spec["assets"], name
        for key, asset in spec["assets"].items():
            assert re.fullmatch(r"(windows|linux|linux-musl|macos)-(x86_64|arm64)", key), (name, key)
            assert re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]), (name, key)
            assert asset["asset"], (name, key)


def test_opengrep_registered_for_required_platforms():
    assets = tools.TOOLS["opengrep"]["assets"]
    for key in ("windows-x86_64", "linux-x86_64", "linux-arm64", "macos-x86_64", "macos-arm64"):
        assert key in assets


# ------------------------------------------------------------------ platform mapping


@pytest.mark.parametrize(
    "system,machine,musl,key",
    [
        ("Windows", "AMD64", None, "windows-x86_64"),
        ("Windows", "ARM64", None, "windows-arm64"),
        ("Linux", "x86_64", False, "linux-x86_64"),
        ("Linux", "aarch64", False, "linux-arm64"),
        ("Linux", "x86_64", True, "linux-musl-x86_64"),
        ("Darwin", "x86_64", None, "macos-x86_64"),
        ("Darwin", "arm64", None, "macos-arm64"),
    ],
)
def test_platform_key(system, machine, musl, key):
    assert tools.platform_key(system, machine, musl=musl) == key


@pytest.mark.parametrize(
    "tool,key,asset",
    [
        ("opengrep", "windows-x86_64", "opengrep_windows_x86.exe"),
        ("opengrep", "windows-arm64", "opengrep_windows_x86.exe"),  # x64 emulation fallback
        ("opengrep", "linux-x86_64", "opengrep_manylinux_x86"),
        ("opengrep", "linux-arm64", "opengrep_manylinux_aarch64"),
        ("opengrep", "linux-musl-x86_64", "opengrep_musllinux_x86"),
        ("opengrep", "macos-x86_64", "opengrep_osx_x86"),
        ("opengrep", "macos-arm64", "opengrep_osx_arm64"),
        ("osv-scanner", "windows-arm64", "osv-scanner_windows_arm64.exe"),
        ("osv-scanner", "linux-musl-arm64", "osv-scanner_linux_arm64"),  # static Go binary
        ("osv-scanner", "macos-arm64", "osv-scanner_darwin_arm64"),
    ],
)
def test_select_asset(tool, key, asset):
    assert tools.select_asset(tool, key)["asset"] == asset


def test_unsupported_platform_is_a_tool_error():
    with pytest.raises(tools.ToolError, match="SLSEC_OPENGREP_PATH"):
        tools.select_asset("opengrep", "freebsd-x86_64")


def test_unknown_tool():
    with pytest.raises(tools.ToolError, match="unknown tool"):
        tools.ensure_tool("nope", env={})


def test_binary_name_and_override_var():
    assert tools.binary_name("opengrep", "windows-x86_64") == "opengrep.exe"
    assert tools.binary_name("opengrep", "macos-arm64") == "opengrep"
    assert tools.override_env_var("osv-scanner") == "SLSEC_OSV_SCANNER_PATH"


# ------------------------------------------------------------------ cache dir


def test_cache_dir_env_override(tmp_path):
    assert tools.cache_dir({"SLSEC_CACHE_DIR": str(tmp_path)}, "Linux") == tmp_path


def test_cache_dir_windows(tmp_path):
    assert tools.cache_dir({"LOCALAPPDATA": str(tmp_path)}, "Windows") == tmp_path / "slsec" / "Cache"
    assert tools.cache_dir({}, "Windows") == Path.home() / "AppData" / "Local" / "slsec" / "Cache"


def test_cache_dir_macos():
    assert tools.cache_dir({}, "Darwin") == Path.home() / "Library" / "Caches" / "slsec"


def test_cache_dir_linux(tmp_path):
    assert tools.cache_dir({"XDG_CACHE_HOME": str(tmp_path)}, "Linux") == tmp_path / "slsec"
    assert tools.cache_dir({}, "Linux") == Path.home() / ".cache" / "slsec"


def test_tool_path_layout(tmp_path):
    env = {"SLSEC_CACHE_DIR": str(tmp_path)}
    version = tools.TOOLS["opengrep"]["version"]
    assert tools.tool_path("opengrep", env, "windows-x86_64") == tmp_path / "opengrep" / version / "opengrep.exe"


# ------------------------------------------------------------------ ensure_tool


def test_download_verify_and_cache(fake_registry, payload, monkeypatch):
    spec, env, cache = fake_registry
    path = tools.ensure_tool(FAKE, env=env, key=KEY)
    assert path == cache / FAKE / "9.9.9" / FAKE
    assert path.read_bytes() == payload.read_bytes()
    if os.name != "nt":
        assert os.access(path, os.X_OK)
    assert _cache_files(cache) == [f"{FAKE}/9.9.9/{FAKE}"]  # no temp files left behind

    # Second use is served from the cache: no network at all.
    def boom(*a, **k):
        raise AssertionError("should not download again")

    monkeypatch.setattr(tools.urllib.request, "urlopen", boom)
    assert tools.ensure_tool(FAKE, env=env, key=KEY) == path


def test_tampered_cache_is_refused(fake_registry):
    spec, env, cache = fake_registry
    path = tools.ensure_tool(FAKE, env=env, key=KEY)
    path.write_bytes(path.read_bytes() + b"\n# injected\n")
    with pytest.raises(tools.ToolError, match="refusing to run"):
        tools.ensure_tool(FAKE, env=env, key=KEY)
    assert tools.tool_status(FAKE, env=env, key=KEY)["state"] == "tampered"


def test_download_hash_mismatch_is_refused_and_leaves_nothing(fake_registry, monkeypatch):
    spec, env, cache = fake_registry
    monkeypatch.setitem(spec["assets"][KEY], "sha256", "0" * 64)
    with pytest.raises(tools.ToolError, match="SHA-256 mismatch"):
        tools.ensure_tool(FAKE, env=env, key=KEY)
    assert _cache_files(cache) == []


def test_offline_is_a_tool_error(fake_registry, monkeypatch):
    spec, env, cache = fake_registry

    def offline(*a, **k):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(tools.urllib.request, "urlopen", offline)
    with pytest.raises(tools.ToolError, match="could not download"):
        tools.ensure_tool(FAKE, env=env, key=KEY)
    assert _cache_files(cache) == []


def test_override_env_var_used_as_is(fake_registry, tmp_path, capsys):
    spec, env, cache = fake_registry
    custom = tmp_path / "mirror" / "my-fake-tool"
    custom.parent.mkdir()
    custom.write_bytes(b"anything")
    env = dict(env, SLSEC_FAKE_TOOL_PATH=str(custom))
    assert tools.ensure_tool(FAKE, env=env, key=KEY) == custom
    assert "SLSEC_FAKE_TOOL_PATH" in capsys.readouterr().err
    assert _cache_files(cache) == []
    assert tools.tool_status(FAKE, env=env, key=KEY)["state"] == "override"


def test_override_env_var_missing_file(fake_registry, tmp_path):
    spec, env, cache = fake_registry
    env = dict(env, SLSEC_FAKE_TOOL_PATH=str(tmp_path / "missing"))
    with pytest.raises(tools.ToolError, match="isn't a file"):
        tools.ensure_tool(FAKE, env=env, key=KEY)


def test_path_binary_used_only_if_hash_matches(fake_registry, payload, tmp_path, monkeypatch):
    spec, env, cache = fake_registry
    bindir = tmp_path / "bin"
    bindir.mkdir()
    on_path = bindir / tools.binary_name(FAKE, KEY)
    on_path.write_bytes(payload.read_bytes())
    if os.name != "nt":
        on_path.chmod(0o755)
    monkeypatch.setattr(tools.shutil, "which", lambda name, path=None: str(on_path))
    env = dict(env, PATH=str(bindir))
    assert tools.ensure_tool(FAKE, env=env, key=KEY) == on_path
    assert tools.tool_status(FAKE, env=env, key=KEY)["state"] == "path"
    assert _cache_files(cache) == []

    # A same-named binary with different bytes is ignored; the pinned one is downloaded.
    on_path.write_bytes(b"something else")
    assert tools.ensure_tool(FAKE, env=env, key=KEY) == cache / FAKE / "9.9.9" / FAKE


def test_concurrent_fetches_do_not_corrupt_cache(fake_registry, payload):
    spec, env, cache = fake_registry
    results, errors = [], []

    def worker():
        try:
            results.append(tools.ensure_tool(FAKE, env=env, key=KEY))
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(set(results)) == 1
    assert results[0].read_bytes() == payload.read_bytes()
    assert _cache_files(cache) == [f"{FAKE}/9.9.9/{FAKE}"]


def test_tool_status_missing_and_cached(fake_registry):
    spec, env, cache = fake_registry
    assert tools.tool_status(FAKE, env=env, key=KEY)["state"] == "missing"
    tools.ensure_tool(FAKE, env=env, key=KEY)
    status = tools.tool_status(FAKE, env=env, key=KEY)
    assert status["state"] == "cached" and status["version"] == "9.9.9"
    assert tools.tool_status("opengrep", env=env, key="freebsd-x86_64")["state"] == "unsupported"


def test_platform_for_asset_names():
    assert tools._platform_for_asset("opengrep_manylinux_aarch64") == "linux-arm64"
    assert tools._platform_for_asset("opengrep_musllinux_x86") == "linux-musl-x86_64"
    assert tools._platform_for_asset("opengrep_windows_x86.exe") == "windows-x86_64"
    assert tools._platform_for_asset("osv-scanner_darwin_arm64") == "macos-arm64"
    assert tools._platform_for_asset("opengrep_osx_x86.sig") is None
    assert tools._platform_for_asset("opengrep-core_linux_x86.tar.gz") is None
    assert tools._platform_for_asset("osv-scanner_SHA256SUMS") is None
