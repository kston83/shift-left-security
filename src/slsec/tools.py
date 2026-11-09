"""Fetch pinned scanner binaries, verify their SHA-256, and cache them.

Some scanners (opengrep, osv-scanner) aren't on PyPI. slsec downloads the
release binary pinned in `TOOLS` for the current OS/arch, checks it against
the SHA-256 baked into this file, and caches it at:

    <cache>/<tool>/<version>/<binary>

The cache root is `SLSEC_CACHE_DIR` if set, otherwise
`%LOCALAPPDATA%\\slsec\\Cache` (Windows), `~/Library/Caches/slsec` (macOS) or
`${XDG_CACHE_HOME:-~/.cache}/slsec` (Linux).

How the binary is chosen, in order:

1. `SLSEC_<TOOL>_PATH` (for example SLSEC_OPENGREP_PATH): used as-is, with a
   one-line note. This is for air-gapped orgs that mirror binaries
   themselves; the user takes responsibility for that binary.
2. The cached binary, re-hashed before every use. A mismatch is refused.
3. A binary of the same name on PATH, but only if it is byte-identical to the
   pinned release asset (same SHA-256). A `--version` check would prove
   nothing (any binary can print a version string) and costs a process start
   (about 3 s for opengrep on Windows), so the hash is the test.
4. Download from the pinned URL (urllib, honours HTTPS_PROXY/HTTP_PROXY/
   NO_PROXY), verify, and atomically move into the cache.

Concurrency: downloads go to a uniquely named temp file in the destination
directory and are verified before `os.replace` moves them into place. Two
hooks fetching at once may both download, but the cached file is only ever a
complete, verified binary. No lock files, so there's nothing stale to clean up.

Maintainers: see `python -m slsec.tools regen --help` to regenerate a
registry entry when bumping a version.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request
from glob import glob
from pathlib import Path
from typing import Dict, List, Mapping, Optional

DOWNLOAD_TIMEOUT = 60  # seconds per socket operation
_CHUNK = 1 << 20


class ToolError(RuntimeError):
    """The tool can't be provided: unsupported platform, download failed, hash mismatch..."""


# --------------------------------------------------------------------------- registry
# One block per tool. Bump `version` and every `sha256` together; Renovate
# matches the `# renovate:` comment to propose the version bump, then
# regenerate the asset block with:
#
#     python -m slsec.tools regen opengrep v1.33.0
#     python -m slsec.tools regen osv-scanner v2.8.0 --download   # also hash locally
#
# `regen` reads the release's per-asset SHA-256 digests from the GitHub API
# (and with --download, downloads each asset and hashes it). Never hand-edit
# a hash you haven't verified. Repo standard: pin releases >= 2 weeks old.
#
# Platform keys are "<os>-<arch>": os in windows/linux/linux-musl/macos,
# arch in x86_64/arm64 (aarch64 is normalised to arm64).
TOOLS: Dict[str, dict] = {
    "opengrep": {
        # renovate: datasource=github-releases depName=opengrep/opengrep
        "version": "1.32.0",  # released 2026-10-22
        "repo": "opengrep/opengrep",
        "url": "https://github.com/opengrep/opengrep/releases/download/v{version}/{asset}",
        "assets": {
            "windows-x86_64": {"asset": "opengrep_windows_x86.exe", "sha256": "ae7152809ec71340213e8f4de3701c83edbdb33f4ac05eca2987b96ec6826a5e"},
            "linux-x86_64": {"asset": "opengrep_manylinux_x86", "sha256": "7360d60174880bd9214f2dfbe439b7bce82b7a3d44cfe945ba833c85cc8bda75"},
            "linux-arm64": {"asset": "opengrep_manylinux_aarch64", "sha256": "dc6229319c0d68948733053786a5614873947e5ec1d4669cc0e94ae9038cb99d"},
            "linux-musl-x86_64": {"asset": "opengrep_musllinux_x86", "sha256": "ad8732262e87aea94750cb06df8423c9cb4b640c1bb3b3b01a377fcf6f08d2ba"},
            "linux-musl-arm64": {"asset": "opengrep_musllinux_aarch64", "sha256": "918fead4e82e3d779fef04aeb4e85b3d30c7a3bb73cd7895bca4401257471b65"},
            "macos-x86_64": {"asset": "opengrep_osx_x86", "sha256": "7dfb68184b7da2895a56e86bc88192fe2b9414993026f5100bacccb4764d19f4"},
            "macos-arm64": {"asset": "opengrep_osx_arm64", "sha256": "e161746226bccef5b85c57611946fa21dc3b00a2dc2591343d6160af99397e2f"},
        },
    },
    "osv-scanner": {
        # renovate: datasource=github-releases depName=google/osv-scanner
        "version": "2.7.0",  # released 2026-10-12
        "repo": "google/osv-scanner",
        "url": "https://github.com/google/osv-scanner/releases/download/v{version}/{asset}",
        "assets": {
            "windows-x86_64": {"asset": "osv-scanner_windows_amd64.exe", "sha256": "9964ed64ec9a387391eb4cc006ad5c531154821aef29b793e02c448de4686438"},
            "windows-arm64": {"asset": "osv-scanner_windows_arm64.exe", "sha256": "3e630381c1f1fd3c9c4d447e6ff2ef6c737083371722773db8337eead0f97962"},
            "linux-x86_64": {"asset": "osv-scanner_linux_amd64", "sha256": "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"},
            "linux-arm64": {"asset": "osv-scanner_linux_arm64", "sha256": "4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7"},
            "macos-x86_64": {"asset": "osv-scanner_darwin_amd64", "sha256": "e82c5df7ab0a42dff29a1cd0660711447b56b4c0483ff66ad8634df10fd81a45"},
            "macos-arm64": {"asset": "osv-scanner_darwin_arm64", "sha256": "d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b"},
        },
    },
}
# ------------------------------------------------------------------------ end registry

# Fallbacks when a platform has no native asset (Windows 11 on ARM runs x64
# binaries under emulation; static Go binaries run on musl).
_FALLBACKS = {
    "windows-arm64": ["windows-x86_64"],
    "linux-musl-x86_64": ["linux-x86_64"],
    "linux-musl-arm64": ["linux-arm64"],
}


def _note(msg: str) -> None:
    print(f"[slsec] {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- platform
def _norm_arch(machine: str) -> str:
    m = machine.strip().lower()
    if m in ("x86_64", "amd64", "x64", "x86-64"):
        return "x86_64"
    if m in ("arm64", "aarch64", "armv8", "armv8l", "aarch64_be"):
        return "arm64"
    return m or "unknown"


def _is_musl() -> bool:
    try:
        if platform.libc_ver()[0] == "glibc":
            return False
    except Exception:  # pragma: no cover - libc_ver can fail on odd interpreters
        pass
    return bool(glob("/lib/ld-musl-*.so.1"))


def platform_key(system: Optional[str] = None, machine: Optional[str] = None, musl: Optional[bool] = None) -> str:
    """'<os>-<arch>' for this machine (or for the given values, for tests)."""
    system = (system or platform.system()).lower()
    arch = _norm_arch(machine if machine is not None else platform.machine())
    if system.startswith(("windows", "cygwin", "msys")):
        os_name = "windows"
    elif system == "darwin":
        os_name = "macos"
    elif system == "linux":
        os_name = "linux-musl" if (_is_musl() if musl is None else musl) else "linux"
    else:
        os_name = system
    return f"{os_name}-{arch}"


def select_asset(name: str, key: Optional[str] = None) -> dict:
    """The registry asset for `name` on platform `key`, applying fallbacks."""
    spec = _spec(name)
    key = key or platform_key()
    for candidate in [key, *_FALLBACKS.get(key, [])]:
        if candidate in spec["assets"]:
            return spec["assets"][candidate]
    raise ToolError(
        f"{name} {spec['version']} has no prebuilt binary for {key}. "
        f"Install it yourself and set {override_env_var(name)} to its path."
    )


def _spec(name: str) -> dict:
    try:
        return TOOLS[name]
    except KeyError:
        raise ToolError(f"unknown tool {name!r}; known: {', '.join(sorted(TOOLS))}") from None


def override_env_var(name: str) -> str:
    return "SLSEC_" + name.upper().replace("-", "_") + "_PATH"


def binary_name(name: str, key: Optional[str] = None) -> str:
    return name + ".exe" if (key or platform_key()).startswith("windows") else name


# --------------------------------------------------------------------------- cache
def cache_dir(env: Optional[Mapping[str, str]] = None, system: Optional[str] = None) -> Path:
    env = os.environ if env is None else env
    if env.get("SLSEC_CACHE_DIR"):
        return Path(env["SLSEC_CACHE_DIR"]).expanduser()
    system = system or platform.system()
    home = Path.home()
    if system == "Windows":
        base = env.get("LOCALAPPDATA")
        return (Path(base) if base else home / "AppData" / "Local") / "slsec" / "Cache"
    if system == "Darwin":
        return home / "Library" / "Caches" / "slsec"
    xdg = env.get("XDG_CACHE_HOME")
    return (Path(xdg) if xdg else home / ".cache") / "slsec"


def tool_path(name: str, env: Optional[Mapping[str, str]] = None, key: Optional[str] = None) -> Path:
    """Where the cached binary for `name` lives (whether or not it exists yet)."""
    spec = _spec(name)
    return cache_dir(env) / name / spec["version"] / binary_name(name, key)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_retrying(path: Path, attempts: int = 10) -> str:
    # On Windows a file being replaced by another process can briefly refuse
    # to open (sharing violation). Retry instead of failing the hook.
    for i in range(attempts):
        try:
            return sha256_file(path)
        except PermissionError:
            if i == attempts - 1:
                raise
            time.sleep(0.05 * (i + 1))
    raise AssertionError("unreachable")


def _make_executable(path: Path) -> None:
    if os.name != "nt":
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _download(url: str, dest: Path, expected: str, label: str) -> None:
    """Download `url`, verify it against `expected`, and atomically place it at `dest`."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(dest.parent), prefix=f".{dest.name}.", suffix=".part")
    tmp = Path(tmp_name)
    try:
        h = hashlib.sha256()
        req = urllib.request.Request(url, headers={"User-Agent": "slsec (+https://github.com/kston83/shift-left-security)"})
        try:
            with os.fdopen(fd, "wb") as out, urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
                size = resp.headers.get("Content-Length") if hasattr(resp, "headers") else None
                mb = f" ({int(size) / 1e6:.0f} MB)" if size and str(size).isdigit() else ""
                _note(f"downloading {label}{mb}; one-time, cached afterwards")
                for chunk in iter(lambda: resp.read(_CHUNK), b""):
                    h.update(chunk)
                    out.write(chunk)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ToolError(f"could not download {label} from {url}: {exc}") from exc
        actual = h.hexdigest()
        if actual != expected:
            raise ToolError(
                f"SHA-256 mismatch for {label} from {url}: expected {expected}, got {actual}. "
                f"Refusing to use it (possible tampering or a broken proxy/mirror)."
            )
        _make_executable(tmp)
        _replace(tmp, dest, expected)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _replace(tmp: Path, dest: Path, expected: str) -> None:
    # On Windows os.replace fails if another process is running or reading the
    # destination. If that file is already the verified binary, we're done.
    for attempt in range(5):
        try:
            os.replace(str(tmp), str(dest))
            return
        except PermissionError:
            if dest.is_file() and _hash_retrying(dest) == expected:
                return
            time.sleep(0.2 * (attempt + 1))
    raise ToolError(f"could not move the downloaded binary into {dest}")


def _verified(path: Path, expected: str) -> bool:
    try:
        return path.is_file() and _hash_retrying(path) == expected
    except OSError as exc:
        raise ToolError(f"could not read {path}: {exc}") from exc


def _matching_on_path(name: str, key: str, expected: str, env: Mapping[str, str]) -> Optional[Path]:
    """A same-named binary on PATH, only if it is byte-identical to the pinned asset."""
    found = shutil.which(binary_name(name, key), path=env.get("PATH"))
    if not found:
        return None
    try:
        return Path(found) if _verified(Path(found), expected) else None
    except ToolError:
        return None


def ensure_tool(name: str, env: Optional[Mapping[str, str]] = None, key: Optional[str] = None) -> Path:
    """Return the path of a verified `name` executable, downloading it if needed.

    Raises ToolError on any failure (unknown tool, unsupported platform,
    offline, hash mismatch). Callers should treat that as "scanner unavailable".
    """
    env = os.environ if env is None else env
    spec = _spec(name)
    label = f"{name} {spec['version']}"

    override = env.get(override_env_var(name))
    if override:
        path = Path(override).expanduser()
        if not path.is_file():
            raise ToolError(f"{override_env_var(name)} points to {path}, which isn't a file")
        _note(f"using {name} from {override_env_var(name)}={path} (not verified by slsec)")
        return path

    key = key or platform_key()
    asset = select_asset(name, key)
    expected = asset["sha256"].lower()
    dest = tool_path(name, env, key)

    if dest.exists():
        if _verified(dest, expected):
            return dest
        raise ToolError(
            f"cached {label} at {dest} does not match its pinned SHA-256; refusing to run it. "
            f"Delete that file to re-download, and investigate if you didn't modify it."
        )

    on_path = _matching_on_path(name, key, expected, env)
    if on_path:
        return on_path

    url = spec["url"].format(version=spec["version"], asset=asset["asset"])
    _download(url, dest, expected, label)
    return dest


def tool_status(name: str, env: Optional[Mapping[str, str]] = None, key: Optional[str] = None) -> dict:
    """Describe `name` without downloading anything (for `slsec doctor`).

    `state` is one of: override, cached, path, missing, tampered, unreadable, unsupported.
    """
    env = os.environ if env is None else env
    spec = _spec(name)
    key = key or platform_key()
    info = {"name": name, "version": spec["version"], "platform": key, "path": None, "state": "missing"}
    override = env.get(override_env_var(name))
    if override:
        info.update(state="override", path=str(Path(override).expanduser()))
        return info
    try:
        expected = select_asset(name, key)["sha256"].lower()
    except ToolError:
        info["state"] = "unsupported"
        return info
    dest = tool_path(name, env, key)
    info["path"] = str(dest)
    if dest.exists():
        try:
            info["state"] = "cached" if _verified(dest, expected) else "tampered"
        except ToolError:
            info["state"] = "unreadable"
        return info
    on_path = _matching_on_path(name, key, expected, env)
    if on_path:
        info.update(state="path", path=str(on_path))
    return info


# --------------------------------------------------------------------------- maintainer CLI
def _platform_for_asset(asset_name: str) -> Optional[str]:
    """Best-effort map from a release asset name to a registry platform key."""
    n = asset_name.lower()
    if n.endswith((".sig", ".cert", ".pem", ".sbom", ".json", ".jsonl", ".txt", ".zip", ".tar.gz")) or "sha256" in n:
        return None
    arch = "arm64" if ("arm64" in n or "aarch64" in n) else "x86_64" if ("amd64" in n or "x86" in n) else None
    if arch is None:
        return None
    if "windows" in n:
        return f"windows-{arch}"
    if "musllinux" in n:
        return f"linux-musl-{arch}"
    if "linux" in n:
        return f"linux-{arch}"
    if "osx" in n or "darwin" in n or "macos" in n:
        return f"macos-{arch}"
    return None


def regen(name: str, tag: str, download: bool = False) -> str:
    """Build a registry `assets` block for `name` at release `tag` (GitHub only)."""
    spec = _spec(name)
    api = f"https://api.github.com/repos/{spec['repo']}/releases/tags/{tag}"
    with urllib.request.urlopen(api, timeout=DOWNLOAD_TIMEOUT) as resp:
        release = json.load(resp)
    lines: List[str] = [f'        "version": "{tag.lstrip("v")}",  # released {release["published_at"][:10]}', '        "assets": {']
    for a in release["assets"]:
        key = _platform_for_asset(a["name"])
        if key is None or key not in spec["assets"]:
            continue
        digest = (a.get("digest") or "").split(":", 1)[-1]
        if download:
            tmp = Path(tempfile.mkdtemp()) / a["name"]
            urllib.request.urlretrieve(a["browser_download_url"], tmp)
            local = sha256_file(tmp)
            shutil.rmtree(tmp.parent, ignore_errors=True)
            if digest and local != digest:
                raise ToolError(f"{a['name']}: GitHub digest {digest} != downloaded {local}")
            digest = local
        if not digest:
            raise ToolError(f"{a['name']}: no digest published; rerun with --download")
        lines.append(f'            "{key}": {{"asset": "{a["name"]}", "sha256": "{digest}"}},')
    lines.append("        },")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m slsec.tools", description="Manage slsec's pinned scanner binaries.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_fetch = sub.add_parser("fetch", help="download + verify tools into the cache (e.g. to pre-warm CI images)")
    p_fetch.add_argument("names", nargs="*", default=sorted(TOOLS))
    p_status = sub.add_parser("status", help="show cache status without downloading")
    p_status.add_argument("names", nargs="*", default=sorted(TOOLS))
    p_regen = sub.add_parser("regen", help="print a registry block for a new release (maintainers)")
    p_regen.add_argument("name", choices=sorted(TOOLS))
    p_regen.add_argument("tag", help="release tag, e.g. v1.33.0")
    p_regen.add_argument("--download", action="store_true", help="also download each asset and hash it locally")
    args = parser.parse_args(argv)

    if args.cmd == "regen":
        print(regen(args.name, args.tag, args.download))
        return 0
    rc = 0
    for name in args.names:
        try:
            if args.cmd == "fetch":
                print(f"{name}: {ensure_tool(name)}")
            else:
                s = tool_status(name)
                print(f"{name} {s['version']} [{s['platform']}]: {s['state']} {s['path'] or ''}".rstrip())
        except ToolError as exc:
            print(f"{name}: {exc}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
