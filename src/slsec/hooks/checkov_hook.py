"""slsec-checkov: run checkov on the IaC files in a commit, using the shared slsec policy.

pre-commit passes in the staged filenames. They're scanned like this:

* Terraform / OpenTofu files are grouped by directory, and checkov scans each
  directory (`-d`). A per-file scan can't resolve variables, locals or modules,
  which leads to false positives and missed findings.
* Dockerfiles / Containerfiles are scanned file by file (`-f`).

`mode: warn` (the default) shows findings without blocking the commit.
`mode: block` fails the commit. Set the mode in `.slsec.yaml`, or override it
with `--mode` or the SLSEC_MODE environment variable.

If SLSEC_REPORT_DIR is set (CI does this), SARIF and JUnit reports are also
written to that directory.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Iterable, List, Optional, Sequence

from slsec.config import Config, ConfigError, load_config

TOOL = "slsec-checkov"
BASE_ARGS = [
    "--compact",
    "--quiet",
    "--skip-download",  # offline: no Prisma Cloud calls, no vendor telemetry
    "--download-external-modules",
    "false",
]


def _posix(path: str) -> PurePosixPath:
    return PurePosixPath(path.replace("\\", "/"))


def is_terraform(path: str) -> bool:
    name = _posix(path).name.lower()
    return name.endswith((".tf", ".tf.json", ".tfvars", ".tfvars.json"))


def is_dockerfile(path: str) -> bool:
    name = _posix(path).name
    lower = name.lower()
    return (
        lower in ("dockerfile", "containerfile")
        or lower.startswith(("dockerfile.", "containerfile."))
        or lower.endswith(".dockerfile")
    )


def _ignored(path: str) -> bool:
    parts = _posix(path).parts
    return ".terraform" in parts or ".terragrunt-cache" in parts


def terraform_dirs(files: Iterable[str]) -> List[str]:
    """Unique directories holding the Terraform files, with nested ones dropped.

    `checkov -d` is recursive, so if a parent directory is already being
    scanned, its children don't need their own entry.
    """
    dirs = sorted({str(_posix(f).parent) for f in files if is_terraform(f) and not _ignored(f)})
    kept: List[str] = []
    for d in dirs:
        p = PurePosixPath(d)
        if any(k == "." or p == PurePosixPath(k) or PurePosixPath(k) in p.parents for k in kept):
            continue
        kept.append(d)
    return kept


def dockerfiles(files: Iterable[str]) -> List[str]:
    return sorted({str(_posix(f)) for f in files if is_dockerfile(f) and not _ignored(f)})


def checkov_command() -> List[str]:
    return [sys.executable, "-m", "checkov.main"]


def build_args(
    framework: str,
    targets: Sequence[str],
    cfg: Config,
    report_dir: Optional[Path] = None,
) -> List[str]:
    flag = "-d" if framework == "terraform" else "-f"
    args: List[str] = []
    for t in targets:
        args += [flag, t]
    args += ["--framework", framework, *BASE_ARGS, *cfg.checkov_extra_args]
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


def _print_expired(cfg: Config) -> None:
    for s in cfg.checkov_expired:
        print(
            f"[{TOOL}] exception for {s.id} expired on {s.expires} ({s.reason}); the check is enforced again. "
            f"Fix the finding, or renew the exception in {cfg.source.name if cfg.source else '.slsec.yaml'}.",
            flush=True,
        )


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

    jobs = [
        ("terraform", terraform_dirs(args.filenames)),
        ("dockerfile", dockerfiles(args.filenames)),
    ]
    jobs = [(fw, targets) for fw, targets in jobs if targets]
    if not jobs:
        return 0

    _print_expired(cfg)
    if not cfg.blocking:
        print(
            f"[{TOOL}] mode=warn: findings are reported but won't block this commit. "
            f"Set `mode: block` in .slsec.yaml to enforce.",
            flush=True,
        )

    worst = 0
    for framework, targets in jobs:
        cmd = checkov_command() + build_args(framework, targets, cfg, report_dir)
        try:
            proc = subprocess.run(cmd)
        except OSError as exc:
            print(f"[{TOOL}] could not start checkov: {exc}", file=sys.stderr)
            return 2
        if proc.returncode != 0 and proc.returncode != 1:
            print(f"[{TOOL}] checkov exited with {proc.returncode} (scanner error)", file=sys.stderr)
        worst = max(worst, proc.returncode)

    if worst == 1 and cfg.blocking:
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
