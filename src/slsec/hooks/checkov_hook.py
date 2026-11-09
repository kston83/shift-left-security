"""slsec-checkov: run checkov on the IaC files in a commit, using the shared slsec policy.

pre-commit passes in the staged filenames. They're scanned like this:

* Terraform files are grouped by directory, and checkov scans each of those
  directories (`-d`), so variables, locals and local module calls resolve. A
  per-file scan can't, which leads to false positives and missed findings.
  The scan does not recurse: subdirectories are skipped unless they hold staged
  files themselves, and sibling files that the repo's pre-commit `exclude:`
  filters out are skipped too. Staging one root-level .tf file scans the root
  directory, not the whole repo.
* Dockerfiles / Containerfiles are scanned file by file (`-f`).
* OpenTofu `.tofu` files are reported but can't be scanned: checkov doesn't
  read them yet. The hook says so instead of passing silently (strict mode fails).

Inline suppressions (`# checkov:skip=CKV_X_N: <reason>`) in the staged files
must carry a real reason, the same rule as exceptions in `.slsec.yaml`.

`mode: warn` (the default) shows findings without blocking the commit.
`mode: block` fails the commit. Set the mode in `.slsec.yaml`, or override it
with `--mode` or the SLSEC_MODE environment variable.

If SLSEC_REPORT_DIR is set (CI does this), SARIF and JUnit reports are also
written to that directory. Runs that share SLSEC_RUN_ID add to one report.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

import yaml

from slsec import reports
from slsec.config import Config, ConfigError, load_config, weak_reason

TOOL = "slsec-checkov"
HOOK_ID = "slsec-checkov"
BASE_ARGS = [
    "--compact",
    "--quiet",
    "--skip-download",  # offline: no Prisma Cloud calls, no vendor telemetry
    "--download-external-modules",
    "false",
]
TERRAFORM_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json")
TOFU_SUFFIXES = (".tofu", ".tofu.json")
# Same as `files:` for slsec-checkov in .pre-commit-hooks.yaml (a test keeps them in step).
HOOK_FILES = (
    r"(\.tf|\.tf\.json|\.tfvars|\.tfvars\.json|\.tofu|\.tofu\.json)$"
    r"|(^|/)(Dockerfile|Containerfile)([.][^/]*)?$|\.[dD]ockerfile$"
)
IGNORED_DIRS = {".terraform", ".terragrunt-cache"}
# `checkov:skip=CKV_AWS_20` optionally followed by `:reason` (checkov's own syntax)
INLINE_SKIP = re.compile(r"checkov:skip=([A-Za-z0-9_\-]+)(?:\s*:(.*))?")


def _posix(path: str) -> PurePosixPath:
    return PurePosixPath(path.replace("\\", "/"))


def is_terraform(path: str) -> bool:
    return _posix(path).name.lower().endswith(TERRAFORM_SUFFIXES)


def is_tofu(path: str) -> bool:
    return _posix(path).name.lower().endswith(TOFU_SUFFIXES)


def is_dockerfile(path: str) -> bool:
    name = _posix(path).name
    lower = name.lower()
    return (
        lower in ("dockerfile", "containerfile")
        or lower.startswith(("dockerfile.", "containerfile."))
        or lower.endswith(".dockerfile")
    )


def _ignored(path: str) -> bool:
    return any(part in IGNORED_DIRS for part in _posix(path).parts)


def terraform_dirs(files: Iterable[str]) -> List[str]:
    """Unique directories holding staged Terraform files. Each is scanned without recursing into subdirectories."""
    return sorted({str(_posix(f).parent) for f in files if is_terraform(f) and not _ignored(f)})


def dockerfiles(files: Iterable[str]) -> List[str]:
    return sorted({str(_posix(f)) for f in files if is_dockerfile(f) and not _ignored(f)})


# --------------------------------------------------------------------------- pre-commit filters


def precommit_filter(root: Path) -> Callable[[str], bool]:
    """Would pre-commit pass this path to slsec-checkov? Mirrors `files:` / `exclude:` in the repo config.

    checkov's `-d` reads every file in a directory, including ones the repo told
    pre-commit to leave alone. The hook uses this to skip those siblings.
    """
    include = [re.compile(HOOK_FILES)]
    exclude: List["re.Pattern[str]"] = []
    try:
        config = yaml.safe_load((root / ".pre-commit-config.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        config = {}
    if not isinstance(config, dict):
        config = {}
    try:
        if config.get("files"):
            include.append(re.compile(str(config["files"])))
        if config.get("exclude"):
            exclude.append(re.compile(str(config["exclude"])))
        for repo in config.get("repos") or []:
            for hook in (repo or {}).get("hooks") or []:
                if (hook or {}).get("id") != HOOK_ID:
                    continue
                if hook.get("files"):
                    include[0] = re.compile(str(hook["files"]))
                if hook.get("exclude"):
                    exclude.append(re.compile(str(hook["exclude"])))
                break
    except re.error:
        pass  # pre-commit itself rejects a bad regex; don't second-guess it here

    def wanted(path: str) -> bool:
        p = str(_posix(path))
        return all(r.search(p) for r in include) and not any(r.search(p) for r in exclude)

    return wanted


def sibling_filter(passed: Sequence[str], root: Path) -> Callable[[str], bool]:
    """Which unstaged sibling files `-d` may read: the repo config's view, unless it isn't in effect.

    Files pre-commit passed in are always scanned. If the repo config would have
    excluded one of them, that config isn't what's running (`pre-commit try-repo`,
    `--config other.yaml`, a manual call), so it isn't applied to siblings either.
    """
    wanted = precommit_filter(root)
    given = {str(_posix(f)) for f in passed if is_terraform(f) and not _ignored(f)}
    if any(not wanted(f) for f in given):
        return lambda p: True
    return lambda p: str(_posix(p)) in given or wanted(p)


def _path_regex(path: Path) -> str:
    """checkov --skip-path regex matching exactly `path`.

    checkov matches skip patterns against absolute paths (os.path.abspath). The
    pattern avoids brackets and other regex syntax, because checkov's module
    finder builds its own regex by joining the pattern list character by
    character, so a `]` crashes it (checkov 3.4.3). Every character other than an
    ASCII letter, digit or `_` becomes `.`, which also matches either separator.
    """
    full = os.path.abspath(str(path))
    return "^" + "".join(c if (c.isascii() and c.isalnum()) or c == "_" else "." for c in full) + "$"


def scan_root(dirs: Sequence[str]) -> str:
    """The single `-d` root for a set of directories: their deepest common ancestor.

    checkov is run with exactly one `-d`: with several, it reports paths relative
    to the wrong root and can drop files.
    """
    parts = [_posix(d).parts if d not in (".", "") else () for d in dirs]
    common: List[str] = []
    for level in zip(*parts) if parts else ():
        if len(set(level)) != 1:
            break
        common.append(level[0])
    return "/".join(common) or "."


def skip_paths(dirs: Sequence[str], root: Path, wanted: Callable[[str], bool]) -> List[str]:
    """--skip-path entries that limit a `-d scan_root(dirs)` scan to `dirs` themselves.

    Each staged directory is scanned without recursing; directories on the way to
    it are walked but their own files skipped; everything else is skipped. Files
    the repo's pre-commit config excludes are skipped too.
    """
    staged = {str(_posix(d)) if d not in ("", ".") else "." for d in dirs}
    on_path = set(staged)
    for d in staged:
        p = _posix(d)
        while str(p) not in (".", ""):
            p = p.parent
            on_path.add(str(p) if str(p) else ".")
    skips: List[str] = []
    start = scan_root(sorted(staged))
    todo = [start]
    while todo:
        d = todo.pop()
        try:
            entries = sorted(os.scandir(root / d), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            rel = entry.name if d == "." else f"{d}/{entry.name}"
            if entry.is_dir():
                # checkov already ignores .terraform and hidden dirs
                if entry.name in IGNORED_DIRS or entry.name.startswith("."):
                    continue
                if rel in on_path:
                    todo.append(rel)
                else:
                    skips.append(_path_regex(root / rel))
            elif is_terraform(entry.name) and (d not in staged or not wanted(rel)):
                skips.append(_path_regex(root / rel))
    return skips


# --------------------------------------------------------------------------- inline skips


def inline_skip_problems(files: Iterable[str]) -> List[Tuple[str, int, str, str]]:
    """(file, line, check id, problem) for each `checkov:skip=` without an acceptable reason."""
    problems = []
    for f in files:
        try:
            text = Path(f).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for m in INLINE_SKIP.finditer(line):
                why = weak_reason(m.group(2))
                if why:
                    problems.append((str(_posix(f)), n, m.group(1), why))
    return problems


def _report_inline_skips(problems: Sequence[Tuple[str, int, str, str]], cfg: Config) -> None:
    stream = sys.stderr if cfg.blocking else sys.stdout
    print(f"[{TOOL}] inline suppressions need a reason a reviewer can evaluate:", file=stream)
    for f, n, check, why in problems:
        print(f"  {f}:{n}: checkov:skip={check}: {why}", file=stream)
    print(f"  Write it as:  # checkov:skip=CKV_XXX_N: <why this is acceptable>", file=stream)
    if not cfg.blocking:
        print(f"[{TOOL}] mode=warn: not blocking now; these fail once `mode: block` is set.", file=stream)
    stream.flush()


# --------------------------------------------------------------------------- checkov


def checkov_command() -> List[str]:
    return [sys.executable, "-m", "checkov.main"]


def build_args(
    framework: str,
    targets: Sequence[str],
    cfg: Config,
    report_dir: Optional[Path] = None,
    skips: Sequence[str] = (),
) -> List[str]:
    flag = "-d" if framework == "terraform" else "-f"
    args: List[str] = []
    for t in targets:
        args += [flag, t]
    args += ["--framework", framework, *BASE_ARGS, *cfg.checkov_extra_args]
    for s in skips:
        args += ["--skip-path", s]
    if cfg.checkov_skips:
        args += ["--skip-check", ",".join(s.id for s in cfg.checkov_skips)]
    if not cfg.blocking:
        args.append("--soft-fail")
    if report_dir is not None:
        stem = report_dir / f"checkov-{framework}"
        args += [
            "-o", "cli", "-o", "sarif", "-o", "junitxml",
            "--output-file-path", f"console,{stem}.sarif,{stem}.xml",
        ]
    return args


def _publish(work: Path, report_dir: Path, framework: str) -> None:
    """Move checkov's reports for this invocation into the report dir, merging with this run's earlier batches."""
    name = f"checkov-{framework}"
    sarif = work / f"{name}.sarif"
    if sarif.is_file():
        try:
            reports.publish_sarif(report_dir / sarif.name, json.loads(sarif.read_text(encoding="utf-8")))
        except ValueError:
            print(f"[{TOOL}] checkov wrote an unreadable SARIF report; not published", file=sys.stderr)
    junit = work / f"{name}.xml"
    if junit.is_file():
        reports.publish_junit(report_dir / junit.name, reports.read_junit_suites(junit))


def _print_expired(cfg: Config) -> None:
    for s in cfg.checkov_expired:
        print(
            f"[{TOOL}] exception for {s.id} expired on {s.expires} ({s.reason}); the check is enforced again. "
            f"Fix the finding, or renew the exception in {cfg.source.name if cfg.source else '.slsec.yaml'}.",
            flush=True,
        )


def _report_tofu(files: Sequence[str], cfg: Config) -> int:
    shown = ", ".join(files[:5]) + (f" (+{len(files) - 5} more)" if len(files) > 5 else "")
    msg = (
        f"[{TOOL}] {len(files)} OpenTofu .tofu file(s) were NOT scanned: checkov doesn't read the .tofu "
        f"extension yet. {shown}"
    )
    if cfg.strict:
        print(msg + f"\n[{TOOL}] strict mode is on, so this fails the hook.", file=sys.stderr, flush=True)
        return 2
    print(msg + "\n  Use .tf for resources you want policy-checked, or set strict: true to fail on this.", flush=True)
    return 0


def run(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog=TOOL, description=__doc__.splitlines()[0])
    parser.add_argument("filenames", nargs="*")
    parser.add_argument("--mode", choices=("warn", "block"), help="override mode from .slsec.yaml")
    parser.add_argument("--report-dir", help="also write SARIF + JUnit here (default: $SLSEC_REPORT_DIR)")
    args = parser.parse_args(argv)

    try:
        cfg = load_config()
    except ConfigError as exc:
        print(f"[{TOOL}] configuration error: {exc}", file=sys.stderr)
        return 2
    if args.mode:
        cfg.mode = args.mode

    report = args.report_dir or os.environ.get("SLSEC_REPORT_DIR")
    report_dir = Path(report) if report else None
    if report_dir:
        report_dir.mkdir(parents=True, exist_ok=True)

    tf_dirs = terraform_dirs(args.filenames)
    docker = dockerfiles(args.filenames)
    tofu = sorted({str(_posix(f)) for f in args.filenames if is_tofu(f) and not _ignored(f)})
    if not (tf_dirs or docker or tofu):
        return 0

    worst = 0
    if tofu:
        worst = max(worst, _report_tofu(tofu, cfg))

    staged = [f for f in args.filenames if (is_terraform(f) or is_dockerfile(f) or is_tofu(f)) and not _ignored(f)]
    problems = inline_skip_problems(staged)
    if problems:
        _report_inline_skips(problems, cfg)
        if cfg.blocking:
            worst = max(worst, 1)

    jobs: List[Tuple[str, List[str], List[str]]] = []
    if tf_dirs:
        skips = skip_paths(tf_dirs, Path.cwd(), sibling_filter(args.filenames, Path.cwd()))
        jobs.append(("terraform", [scan_root(tf_dirs)], skips))
    if docker:
        jobs.append(("dockerfile", docker, []))
    if not jobs:
        return worst

    _print_expired(cfg)
    if not cfg.blocking:
        print(
            f"[{TOOL}] mode=warn: findings are reported but won't block this commit. "
            f"Set `mode: block` in .slsec.yaml to enforce.",
            flush=True,
        )

    found = False
    with tempfile.TemporaryDirectory(prefix="slsec-checkov-") as tmp:
        work = Path(tmp) if report_dir else None
        for framework, targets, skips in jobs:
            cmd = checkov_command() + build_args(framework, targets, cfg, work, skips)
            try:
                proc = subprocess.run(cmd)
            except OSError as exc:
                print(f"[{TOOL}] could not start checkov: {exc}", file=sys.stderr)
                return 2
            if proc.returncode not in (0, 1):
                print(f"[{TOOL}] checkov exited with {proc.returncode} (scanner error)", file=sys.stderr)
            found = found or proc.returncode == 1
            worst = max(worst, proc.returncode)
            if report_dir and work:
                _publish(work, report_dir, framework)

    if found and cfg.blocking:
        print(
            f"\n[{TOOL}] commit blocked by IaC findings. Fix them, or suppress inline with a reason:\n"
            f"    # checkov:skip=CKV_XXX_N: <why this is acceptable>\n"
            f"  See docs/suppressions.md.",
            file=sys.stderr,
        )
    return worst


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
