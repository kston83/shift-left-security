"""slsec-sca: dependency (SCA) scan on pre-push, when a manifest or lockfile changed.

    slsec-sca --provider {osv,snyk,jfrog} [changed files...]

pre-commit passes the changed manifest / lockfile paths. They are mapped to the
project directories to scan (deduplicated), then handed to one provider:

* osv   - `osv-scanner scan source` (OSS default, no account needed)
* snyk  - `snyk test` (needs SNYK_TOKEN or a prior `snyk auth`)
* jfrog - `jf audit` (needs a server configured with `jf c add`)

Policy (same as every commercial-tool hook in slsec):

* CLI missing, not authenticated, offline, timed out or crashed ("unavailable"):
  print one clear warning and exit 0; CI still enforces. With `strict: true` in
  .slsec.yaml, or SLSEC_STRICT=1 in the environment, the hook exits 1 instead.
  Strict applies the same way in CI: the slsec CI templates set SLSEC_STRICT=1 by
  default, so an expired token or a broken scanner fails the build instead of
  silently turning the scan off.
* Findings: exit 0 in `mode: warn` (default), exit 1 in `mode: block`.
* "No supported projects / no packages" counts as clean.

Environment:
* SLSEC_REPORT_DIR - also write `<dir>/slsec-<provider>.sarif`.
* SLSEC_SCA_TIMEOUT - per-scan timeout in seconds (default 300).
* SLSEC_MODE - see config.py.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from slsec import tools
from slsec.config import Config, ConfigError, load_config

TOOL = "slsec-sca"
DEFAULT_TIMEOUT = 300

CLEAN = "clean"
FINDINGS = "findings"
UNAVAILABLE = "unavailable"

# ---------------------------------------------------------------- targets

_MANIFEST_NAMES = {
    # npm
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    # Maven / Gradle
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    # Python
    "pyproject.toml", "poetry.lock", "pipfile.lock", "uv.lock",
    # Go
    "go.mod", "go.sum",
    # NuGet
    "packages.lock.json", "directory.packages.props", "packages.config",
}


def _posix(path: str) -> PurePosixPath:
    return PurePosixPath(path.replace("\\", "/"))


def is_manifest(path: str) -> bool:
    name = _posix(path).name.lower()
    if name in _MANIFEST_NAMES:
        return True
    if name.endswith((".versions.toml", ".csproj")):
        return True
    return name.startswith("requirements") and name.endswith(".txt")


def _ignored(path: str) -> bool:
    parts = _posix(path).parts
    return any(p in ("node_modules", ".venv", "venv", ".git", ".terraform") for p in parts)


def scan_dirs(files: Iterable[str]) -> List[str]:
    """Unique project directories (posix, relative; "." for the root) for the changed manifests."""
    dirs = {str(_posix(f).parent) for f in files if is_manifest(f) and not _ignored(f)}
    return sorted(dirs)


# --------------------------------------------------------------- plumbing


@dataclass
class Invocation:
    cmd: List[str]
    cwd: Optional[str] = None
    sarif_file: Optional[Path] = None  # tool writes SARIF here itself
    sarif_stdout: bool = False  # tool prints SARIF on stdout instead


@dataclass
class Outcome:
    status: str  # CLEAN | FINDINGS | UNAVAILABLE
    detail: str = ""


def get_timeout(env: Optional[Dict[str, str]] = None) -> int:
    env = os.environ if env is None else env
    try:
        value = int(env.get("SLSEC_SCA_TIMEOUT", ""))
        return value if value > 0 else DEFAULT_TIMEOUT
    except ValueError:
        return DEFAULT_TIMEOUT


class Provider:
    """Adapter: resolve CLI -> check auth -> build commands -> interpret result."""

    name = ""
    label = ""
    binaries: Tuple[str, ...] = ()
    install_hint = ""
    login_hint = ""

    def resolve(self) -> Optional[str]:
        # shutil.which honours PATHEXT, so Windows shims (snyk.cmd, jf.exe) resolve.
        for b in self.binaries:
            found = shutil.which(b)
            if found:
                return found
        return None

    def check_auth(self, exe: str, timeout: int) -> Optional[str]:
        """Return None when authenticated, else a short reason. Must not hit the network."""
        return None

    def invocations(self, exe: str, dirs: Sequence[str], sarif: Optional[Path]) -> List[Invocation]:
        raise NotImplementedError

    def interpret(self, returncode: int, output: str) -> Outcome:
        raise NotImplementedError


class OsvProvider(Provider):
    name = "osv"
    label = "osv-scanner"
    binaries = ("osv-scanner",)
    install_hint = "install osv-scanner (https://google.github.io/osv-scanner/installation/) and put it on PATH"

    def resolve(self) -> Optional[str]:
        found = super().resolve()
        if found:
            return found
        # Fall back to the pinned, checksum-verified binary from slsec.tools.
        try:
            return str(tools.ensure_tool("osv-scanner"))
        except tools.ToolError as exc:
            self._fetch_error = str(exc)
            return None
        except Exception as exc:  # network, disk: never crash a push hook
            self._fetch_error = str(exc)
            return None

    _fetch_error = ""

    def invocations(self, exe, dirs, sarif):
        # osv-scanner v2: `scan source [dirs...]`; non-recursive unless -r, which is what we
        # want since we already point at each changed project directory.
        cmd = [exe, "scan", "source"]
        if sarif:
            cmd += ["--format", "sarif", "--output-file", str(sarif)]
        cmd += list(dirs)
        return [Invocation(cmd, sarif_file=sarif)]

    def interpret(self, returncode, output):
        # Exit codes: https://google.github.io/osv-scanner/output/ (docs/output.md in the repo):
        #   0 = packages found, no vulns; 1 = vulns found (1-126 reserved for result-related);
        #   127 = general error; 128 = no packages found (nothing to scan); 129-255 other errors.
        if returncode == 0 or returncode == 128:
            return Outcome(CLEAN)
        if returncode == 1:
            return Outcome(FINDINGS)
        return Outcome(UNAVAILABLE, f"osv-scanner exited with {returncode}")


class SnykProvider(Provider):
    name = "snyk"
    label = "Snyk"
    binaries = ("snyk",)
    install_hint = "install the Snyk CLI (npm install -g snyk)"
    login_hint = "set SNYK_TOKEN or run `snyk auth`"

    def check_auth(self, exe, timeout):
        # Cheapest first, all offline: env var, then the configstore file `snyk auth` writes,
        # then `snyk config get api` (a local read; covers non-default config locations).
        if os.environ.get("SNYK_TOKEN") or os.environ.get("SNYK_OAUTH_TOKEN"):
            return None
        for path in self._configstore_paths():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict) and (data.get("api") or data.get("INTERNAL_OAUTH_TOKEN_STORAGE")):
                return None
        try:
            proc = subprocess.run(
                [exe, "config", "get", "api"], capture_output=True, text=True, timeout=min(timeout, 20)
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return None
        except (OSError, subprocess.SubprocessError):
            pass
        return "no Snyk credentials found"

    @staticmethod
    def _configstore_paths() -> List[Path]:
        # configstore (used by the Snyk CLI) stores under xdg-basedir's config dir:
        # $XDG_CONFIG_HOME or ~/.config, on Windows too.
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
        return [Path(base) / "configstore" / "snyk.json"]

    def invocations(self, exe, dirs, sarif):
        # One run per project dir (cwd = dir) so Snyk's own detection applies.
        # --sarif-file-output keeps human-readable stdout and writes SARIF to a file;
        # one file per run (runs overwrite), merged later.
        invs = []
        for i, d in enumerate(dirs):
            cmd = [exe, "test", "--all-projects"]
            part = None
            if sarif:
                part = sarif.with_name(f"{sarif.stem}.{i}.part")
                cmd.append(f"--sarif-file-output={part}")
            invs.append(Invocation(cmd, cwd=d, sarif_file=part))
        return invs

    def interpret(self, returncode, output):
        # https://docs.snyk.io/developer-tools/snyk-cli/commands/test : 0 = no vulns,
        # 1 = vulns found, 2 = failure (also auth/network errors), 3 = no supported projects.
        if returncode in (0, 3):
            return Outcome(CLEAN)
        if returncode == 1:
            return Outcome(FINDINGS)
        return Outcome(UNAVAILABLE, f"snyk exited with {returncode}")


class JfrogProvider(Provider):
    name = "jfrog"
    label = "JFrog"
    binaries = ("jf", "jfrog")
    install_hint = "install the JFrog CLI (https://jfrog.com/getcli/) and put `jf` on PATH"
    login_hint = "run `jf c add` to configure a server"

    def check_auth(self, exe, timeout):
        # `jf c show` prints the configured servers from ~/.jfrog/jfrog-cli.conf.v*; it is local.
        try:
            proc = subprocess.run([exe, "c", "show"], capture_output=True, text=True, timeout=min(timeout, 20))
        except (OSError, subprocess.SubprocessError):
            return "could not read the JFrog CLI configuration"
        text = (proc.stdout or "").lower()
        if proc.returncode == 0 and ("server id" in text or "url" in text):
            return None
        return "no JFrog server is configured"

    def invocations(self, exe, dirs, sarif):
        # `jf audit --working-dirs a,b` audits several projects in one call.
        # --format sarif prints SARIF on stdout (there is no file option), so only ask for it
        # when a report is wanted; otherwise keep the readable table.
        cmd = [exe, "audit", "--working-dirs", ",".join(dirs)]
        if sarif:
            cmd += ["--format", "sarif"]
        return [Invocation(cmd, sarif_stdout=bool(sarif))]

    def interpret(self, returncode, output):
        # https://docs.jfrog.com/security : `jf audit --fail` (default true) returns exit code 3
        # when a Fail Build policy rule matches; other non-zero codes are tool errors.
        if returncode == 0:
            return Outcome(CLEAN)
        if returncode == 3:
            return Outcome(FINDINGS)
        return Outcome(UNAVAILABLE, f"jf audit exited with {returncode}")


PROVIDERS: Dict[str, Provider] = {p.name: p for p in (OsvProvider(), SnykProvider(), JfrogProvider())}

# ---------------------------------------------------------------- running


def _run(inv: Invocation, timeout: int) -> Tuple[Optional[int], str, str]:
    """Returns (returncode or None on timeout/start failure, stdout, error text)."""
    try:
        proc = subprocess.run(
            inv.cmd,
            cwd=inv.cwd,
            capture_output=inv.sarif_stdout,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, "", f"timed out after {timeout}s"
    except OSError as exc:
        return None, "", f"could not start: {exc}"
    return proc.returncode, (proc.stdout or "") if inv.sarif_stdout else "", ""


def merge_sarif(parts: Sequence[str]) -> str:
    """Merge several SARIF documents into one by concatenating their `runs`."""
    merged: Optional[dict] = None
    for text in parts:
        try:
            doc = json.loads(text)
        except ValueError:
            continue
        if not isinstance(doc, dict):
            continue
        if merged is None:
            merged = doc
            merged.setdefault("runs", [])
        else:
            merged["runs"].extend(doc.get("runs") or [])
    if merged is None:
        merged = {"version": "2.1.0", "runs": []}
    return json.dumps(merged, indent=2)


def sarif_result_count(text: str) -> int:
    try:
        doc = json.loads(text)
        return sum(len(r.get("results") or []) for r in doc.get("runs") or [])
    except (ValueError, AttributeError, TypeError):
        return 0


def _warn_unavailable(provider: Provider, reason: str, fix: str, cfg: Config) -> int:
    strict = cfg.strict
    print(
        f"[{TOOL}] {provider.label} dependency scan skipped: {reason}. To fix: {fix}. "
        + (
            "strict mode is on (strict: true in .slsec.yaml or SLSEC_STRICT=1), so this fails."
            if strict
            else "The push is not blocked; CI will still enforce this check."
        ),
        file=sys.stderr,
        flush=True,
    )
    return 1 if strict else 0


def run(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog=TOOL, description=__doc__.splitlines()[0])
    parser.add_argument("--provider", required=True, choices=sorted(PROVIDERS))
    parser.add_argument("--mode", choices=("warn", "block"), help="override mode from .slsec.yaml")
    parser.add_argument("--report-dir", help="also write SARIF here (default: $SLSEC_REPORT_DIR)")
    parser.add_argument("filenames", nargs="*")
    args = parser.parse_args(argv)

    try:
        cfg = load_config()
    except ConfigError as exc:
        print(f"[{TOOL}] configuration error: {exc}", file=sys.stderr)
        return 2
    if args.mode:
        cfg.mode = args.mode

    dirs = scan_dirs(args.filenames)
    if not dirs:
        return 0

    provider = PROVIDERS[args.provider]
    timeout = get_timeout()

    exe = provider.resolve()
    if not exe:
        reason = f"the {provider.label} CLI was not found"
        fetch_err = getattr(provider, "_fetch_error", "")
        if fetch_err:
            reason += f" and downloading it failed ({fetch_err})"
        return _warn_unavailable(provider, reason, provider.install_hint, cfg)

    why = provider.check_auth(exe, timeout)
    if why:
        return _warn_unavailable(provider, why, provider.login_hint, cfg)

    report = args.report_dir or os.environ.get("SLSEC_REPORT_DIR")
    report_dir = Path(report) if report else None
    final_sarif: Optional[Path] = None
    if report_dir:
        report_dir.mkdir(parents=True, exist_ok=True)
        final_sarif = report_dir / f"slsec-{provider.name}.sarif"

    if not cfg.blocking:
        print(
            f"[{TOOL}] mode=warn: {provider.label} findings are reported but won't block this push. "
            f"Set `mode: block` in .slsec.yaml to enforce.",
            flush=True,
        )

    # Work in a temp dir for per-run SARIF parts, then publish one file at the final name.
    with tempfile.TemporaryDirectory(prefix="slsec-sca-") as tmp:
        work_sarif = Path(tmp) / f"slsec-{provider.name}.sarif" if final_sarif else None
        invs = provider.invocations(exe, dirs, work_sarif)
        statuses: List[Outcome] = []
        sarif_parts: List[str] = []
        for inv in invs:
            code, out, err = _run(inv, timeout)
            if code is None:
                statuses.append(Outcome(UNAVAILABLE, err))
                continue
            outcome = provider.interpret(code, out)
            statuses.append(outcome)
            if final_sarif and outcome.status != UNAVAILABLE:
                if inv.sarif_stdout and out.strip():
                    sarif_parts.append(out)
                elif inv.sarif_file and inv.sarif_file.is_file():
                    sarif_parts.append(inv.sarif_file.read_text(encoding="utf-8", errors="replace"))
        if final_sarif and sarif_parts:
            merged = merge_sarif(sarif_parts)
            final_sarif.write_text(merged, encoding="utf-8")
            if provider.name != "snyk":  # snyk already printed readable output
                n = sarif_result_count(merged)
                print(f"[{TOOL}] {provider.label}: {n} finding(s); SARIF written to {final_sarif}", flush=True)

    found = any(s.status == FINDINGS for s in statuses)
    broken = [s for s in statuses if s.status == UNAVAILABLE]

    if found:
        if broken:
            print(f"[{TOOL}] note: part of the {provider.label} scan failed ({broken[0].detail}).", file=sys.stderr)
        if cfg.blocking:
            print(
                f"\n[{TOOL}] push blocked by {provider.label} dependency findings. Upgrade the affected "
                f"packages, or record an exception in your {provider.label} policy.",
                file=sys.stderr,
            )
            return 1
        return 0
    if broken:
        return _warn_unavailable(
            provider,
            broken[0].detail or "the scan failed (offline?)",
            "check network access and credentials, then re-run `pre-commit run --hook-stage pre-push`",
            cfg,
        )
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
