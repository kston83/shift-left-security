"""slsec-sast: scan staged source files with opengrep (default) or Semgrep CE.

pre-commit passes in the staged filenames. The hook picks the bundled rule
packs that match their extensions (java, kotlin, javascript, python, go,
csharp), and runs the engine once over all of them, with one `--config` per
pack. Packs that are missing or empty are skipped.

Engine (`providers.sast_engine` in .slsec.yaml):

* `opengrep` (default): the pinned release binary, fetched and SHA-256
  verified by `slsec.tools` and cached; offline after the first run.
* `semgrep`: Semgrep CE from the `slsec[semgrep]` extra, or a `semgrep` on PATH.
* `none`: the hook does nothing.

`mode: warn` (the default) shows findings without blocking the commit.
`mode: block` fails the commit. Override with `--mode` or SLSEC_MODE. If the
engine is unavailable (offline on first run, not installed) or errors out,
the hook warns and exits 0, unless `.slsec.yaml` sets `strict: true`.

Rules listed under `sast.exclude_rules` in .slsec.yaml are excluded (each
needs a reason; expired entries stop applying). Rule ids are used exactly as
written in the rule files (`--no-rewrite-rule-ids`).

If SLSEC_REPORT_DIR (or --report-dir) is set, `slsec-sast.sarif` and
`slsec-sast.xml` (JUnit) are also written there.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from slsec import tools
from slsec.config import Config, ConfigError, bundled_path, load_config

TOOL = "slsec-sast"
SARIF_NAME = "slsec-sast.sarif"
JUNIT_NAME = "slsec-sast.xml"

# Rule pack -> file extensions it covers. Keep in step with `types_or` in
# .pre-commit-hooks.yaml.
PACK_EXTENSIONS: Dict[str, Tuple[str, ...]] = {
    "java": (".java",),
    "kotlin": (".kt", ".kts"),
    "javascript": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"),
    "python": (".py", ".pyi"),
    "go": (".go",),
    "csharp": (".cs",),
}

# CreateProcess caps a command line at 32,767 chars; stay well under it.
# POSIX ARG_MAX is far larger, but each engine start costs seconds, so fewer
# bigger batches are better anyway.
CMDLINE_LIMIT = 30_000 if os.name == "nt" else 120_000

# Engine exit codes (verified against opengrep 1.32.0 and semgrep 1.136.0):
# 0 = clean, 1 = findings (with --error), >=2 = scanner/config error.
RC_FINDINGS = 1


def _posix(path: str) -> str:
    return str(PurePosixPath(path.replace("\\", "/")))


def pack_for(path: str) -> Optional[str]:
    lower = path.lower()
    for pack, exts in PACK_EXTENSIONS.items():
        if lower.endswith(exts):
            return pack
    return None


def rules_root(env: Optional[Mapping[str, str]] = None) -> Path:
    env = os.environ if env is None else env
    override = env.get("SLSEC_SAST_RULES_DIR")
    return Path(override) if override else bundled_path("configs", "sast-rules")


def _has_rules(directory: Path) -> bool:
    return directory.is_dir() and any(
        p.is_file() for pattern in ("*.yaml", "*.yml") for p in directory.rglob(pattern)
    )


def select_packs(files: Sequence[str], root: Path) -> Tuple[List[Tuple[str, Path]], List[str]]:
    """(pack name, pack dir) for each pack with rules, plus the targets they cover.

    Files with no matching pack, whose pack is missing/empty, or that no longer
    exist on disk are dropped.
    """
    wanted: Dict[str, List[str]] = {}
    for f in files:
        pack = pack_for(f)
        if pack and os.path.isfile(f):
            wanted.setdefault(pack, []).append(_posix(f))
    packs: List[Tuple[str, Path]] = []
    targets: List[str] = []
    for pack in PACK_EXTENSIONS:  # stable order
        if pack not in wanted:
            continue
        config = pack_config(root, pack)
        if config is not None:
            packs.append((pack, config))
            targets += wanted[pack]
    return packs, sorted(set(targets))


def pack_config(root: Path, pack: str) -> Optional[Path]:
    """The --config target for a pack: the generated single-file bundle if there is one, else the pack dir.

    Bundles (bundles/<pack>.yaml, written by scripts/refresh-sast-rules.py) load about 2x faster on
    Windows than a directory of rule files, and their rule ids are path-qualified, so they stay
    unique under --no-rewrite-rule-ids (short upstream ids such as `ecb-cipher` collide across packs).
    """
    bundle = root / "bundles" / f"{pack}.yaml"
    if bundle.is_file():
        return bundle
    if _has_rules(root / pack):
        return root / pack
    return None


# --------------------------------------------------------------------------- engines
class EngineUnavailable(Exception):
    pass


def find_semgrep(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """semgrep from this interpreter's scripts dir (the slsec[semgrep] extra) or PATH."""
    env = os.environ if env is None else env
    scripts = Path(sys.executable).parent
    for name in ("semgrep.exe", "semgrep") if os.name == "nt" else ("semgrep",):
        candidate = scripts / name
        if candidate.is_file():
            return str(candidate)
    return shutil.which("semgrep", path=env.get("PATH"))


def resolve_engine(name: str, env: Optional[Mapping[str, str]] = None) -> Tuple[List[str], Dict[str, str]]:
    """Return (command prefix, environment) for the engine, or raise EngineUnavailable."""
    env = dict(os.environ if env is None else env)
    if name == "opengrep":
        try:
            return [str(tools.ensure_tool("opengrep", env=env))], env
        except tools.ToolError as exc:
            raise EngineUnavailable(f"opengrep is unavailable: {exc}") from exc
    if name == "semgrep":
        exe = find_semgrep(env)
        if not exe:
            raise EngineUnavailable(
                "semgrep is not installed. Add it to the hook with "
                "`additional_dependencies: ['semgrep>=1.120,<2']`, or `pip install \"slsec[semgrep]\"`, "
                "or switch to `providers: {sast_engine: opengrep}`. "
                "(Semgrep >= 1.137 needs Python 3.10+; native Windows wheels exist from 1.120.)"
            )
        # semgrep's OCaml core re-executes `pysemgrep` for some options, so its
        # directory has to be on PATH even when the venv isn't activated.
        env["PATH"] = str(Path(exe).parent) + os.pathsep + env.get("PATH", "")
        env.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")
        env.setdefault("SEMGREP_SEND_METRICS", "off")
        env.setdefault("PYTHONUTF8", "1")
        return [exe], env
    raise EngineUnavailable(f"unknown SAST engine {name!r}")


def build_args(
    engine: str,
    packs: Sequence[Tuple[str, Path]],
    cfg: Config,
    sarif: Optional[Path] = None,
    junit: Optional[Path] = None,
) -> List[str]:
    """Engine arguments, without the executable or the targets.

    `--error` is always passed so the exit code tells findings (1) apart from
    a clean scan (0) in both modes; warn mode then maps 1 to 0.
    """
    args = ["scan", "--disable-version-check", "--no-rewrite-rule-ids", "--error"]
    if engine == "semgrep":
        args.append("--metrics=off")  # opengrep has no telemetry and rejects --metrics
    for _, path in packs:
        args += ["--config", str(path)]
    for s in cfg.sast_excludes:
        args += ["--exclude-rule", s.id]
    if sarif is not None:
        args.append(f"--sarif-output={sarif}")
    if junit is not None:
        args.append(f"--junit-xml-output={junit}")
    return args


def batch_targets(targets: Sequence[str], base_len: int, limit: int = CMDLINE_LIMIT) -> List[List[str]]:
    """Split targets so each command line stays under `limit` characters."""
    budget = max(limit - base_len, 1)
    batches: List[List[str]] = []
    current: List[str] = []
    used = 0
    for t in targets:
        cost = len(t) + 3  # quotes + separator
        if current and used + cost > budget:
            batches.append(current)
            current, used = [], 0
        current.append(t)
        used += cost
    if current:
        batches.append(current)
    return batches


def _cmd_len(args: Sequence[str]) -> int:
    return sum(len(a) + 3 for a in args)


# --------------------------------------------------------------------------- reports
def _fix_uri(uri: str) -> str:
    return uri.replace("\\", "/")


def merge_sarif(parts: Sequence[Path], dest: Path) -> None:
    """Merge per-batch SARIF files into one run (code scanning rejects duplicate runs)."""
    merged: Optional[dict] = None
    rule_ids = set()
    for part in parts:
        if not part.is_file():
            continue
        doc = json.loads(part.read_text(encoding="utf-8"))
        if not doc.get("runs"):
            continue
        run = doc["runs"][0]
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                art = loc.get("physicalLocation", {}).get("artifactLocation", {})
                if "uri" in art:
                    art["uri"] = _fix_uri(art["uri"])
        if merged is None:
            merged = doc
            rule_ids = {r.get("id") for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
            continue
        target = merged["runs"][0]
        target.setdefault("results", []).extend(run.get("results", []))
        rules = target.setdefault("tool", {}).setdefault("driver", {}).setdefault("rules", [])
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            if rule.get("id") not in rule_ids:
                rule_ids.add(rule.get("id"))
                rules.append(rule)
        target.setdefault("invocations", []).extend(run.get("invocations", []))
    if merged is not None:
        dest.write_text(json.dumps(merged, indent=2), encoding="utf-8")


def merge_junit(parts: Sequence[Path], dest: Path) -> None:
    root = ET.Element("testsuites")
    totals = {"tests": 0, "failures": 0, "errors": 0}
    found = False
    for part in parts:
        if not part.is_file():
            continue
        found = True
        tree = ET.parse(str(part))
        suites = [tree.getroot()] if tree.getroot().tag == "testsuite" else list(tree.getroot().iter("testsuite"))
        for suite in suites:
            suite.set("name", "slsec-sast")
            for case in suite.iter("testcase"):
                for attr in ("classname", "file"):
                    if attr in case.attrib:
                        case.set(attr, _fix_uri(case.get(attr, "")))
            for k in totals:
                totals[k] += int(suite.get(k, "0") or 0)
            root.append(suite)
    if not found:
        return
    for k, v in totals.items():
        root.set(k, str(v))
    ET.ElementTree(root).write(str(dest), encoding="utf-8", xml_declaration=True)


# --------------------------------------------------------------------------- hook
def _print_expired(cfg: Config) -> None:
    for s in cfg.sast_expired:
        print(
            f"[{TOOL}] exclusion for rule {s.id} expired on {s.expires} ({s.reason}); the rule is enforced again. "
            f"Fix the finding, or renew the exclusion in {cfg.source.name if cfg.source else '.slsec.yaml'}.",
            flush=True,
        )


def _unavailable(cfg: Config, message: str) -> int:
    if cfg.strict:
        print(f"[{TOOL}] {message}\n[{TOOL}] strict: true is set, so this fails the hook.", file=sys.stderr, flush=True)
        return 2
    print(
        f"[{TOOL}] WARNING: {message}\n[{TOOL}] SAST was skipped for this commit; CI still runs it. "
        f"Set `strict: true` in .slsec.yaml to fail instead.",
        file=sys.stderr,
        flush=True,
    )
    return 0


def run(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog=TOOL, description=__doc__.splitlines()[0])
    parser.add_argument("filenames", nargs="*")
    parser.add_argument("--mode", choices=("warn", "block"), help="override mode from .slsec.yaml")
    parser.add_argument("--report-dir", help="also write SARIF + JUnit here (default: $SLSEC_REPORT_DIR)")
    parser.add_argument("--rules-dir", help="rule pack root (default: $SLSEC_SAST_RULES_DIR or the bundled packs)")
    args = parser.parse_args(argv)

    try:
        cfg = load_config()
    except ConfigError as exc:
        print(f"[{TOOL}] configuration error: {exc}", file=sys.stderr)
        return 2
    if args.mode:
        cfg.mode = args.mode
    if cfg.sast_engine == "none":
        return 0

    root = Path(args.rules_dir) if args.rules_dir else rules_root()
    packs, targets = select_packs(args.filenames, root)
    if not targets:
        return 0

    _print_expired(cfg)
    try:
        prefix, env = resolve_engine(cfg.sast_engine)
    except EngineUnavailable as exc:
        return _unavailable(cfg, str(exc))

    report = args.report_dir or os.environ.get("SLSEC_REPORT_DIR")
    report_dir = Path(report) if report else None
    if report_dir:
        report_dir.mkdir(parents=True, exist_ok=True)

    base = build_args(cfg.sast_engine, packs, cfg, report_dir and report_dir / "x.sarif", report_dir and report_dir / "x.xml")
    batches = batch_targets(targets, _cmd_len([*prefix, *base]), CMDLINE_LIMIT)

    print(
        f"[{TOOL}] {cfg.sast_engine}: {len(targets)} file(s), packs: {', '.join(p for p, _ in packs)}"
        + ("" if cfg.blocking else " (mode=warn: findings won't block this commit; set `mode: block` to enforce)"),
        flush=True,
    )

    worst = 0
    sarif_parts: List[Path] = []
    junit_parts: List[Path] = []
    for i, batch in enumerate(batches):
        sarif = junit = None
        if report_dir:
            sarif = report_dir / f".{SARIF_NAME}.part{i}"
            junit = report_dir / f".{JUNIT_NAME}.part{i}"
            sarif_parts.append(sarif)
            junit_parts.append(junit)
        cmd = [*prefix, *build_args(cfg.sast_engine, packs, cfg, sarif, junit), *batch]
        try:
            proc = subprocess.run(cmd, env=env)
        except OSError as exc:
            return _unavailable(cfg, f"could not start {cfg.sast_engine}: {exc}")
        worst = max(worst, proc.returncode)

    if report_dir:
        merge_sarif(sarif_parts, report_dir / SARIF_NAME)
        merge_junit(junit_parts, report_dir / JUNIT_NAME)
        for part in sarif_parts + junit_parts:
            try:
                part.unlink()
            except OSError:
                pass

    if worst > RC_FINDINGS:
        return _unavailable(cfg, f"{cfg.sast_engine} exited with {worst} (scanner or rule error; see output above)")
    if worst == RC_FINDINGS:
        if cfg.blocking:
            print(
                f"\n[{TOOL}] commit blocked by SAST findings. Fix them, or suppress one inline with a reason:\n"
                f"    # nosemgrep: <rule-id>  -- <why this is acceptable>\n"
                f"  or exclude a rule repo-wide under `sast.exclude_rules` in .slsec.yaml (needs a reason).",
                file=sys.stderr,
            )
            return 1
        print(f"[{TOOL}] findings above are warnings only (mode=warn).", flush=True)
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
