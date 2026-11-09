#!/usr/bin/env python3
"""Refresh the vendored SAST rule packs from opengrep-rules.

Python 3.9+, stdlib + PyYAML only. Works on Windows, macOS and Linux.

The source of truth for the curation is
``src/slsec/configs/sast-rules/allowlist.yaml``. This script:

  1. fetches upstream at ``--ref`` (git clone/fetch when git exists, else a
     GitHub zip download) into a temp dir, or uses ``--source <dir>``;
  2. re-copies ONLY the rule files listed in the allowlist (verbatim, byte for
     byte; no upstream test targets are copied);
  3. regenerates NOTICE, SOURCE, MANIFEST.txt and the upstream LICENSE;
  4. reports (a) allowlisted rules that disappeared or changed id upstream and
     (b) NEW upstream rules that meet the curation criteria but are not in the
     allowlist, so a human can decide whether to add them.

Upstream content is treated as untrusted data: it is only parsed (yaml.safe_load)
and copied, never executed.

Examples:
  python scripts/refresh-sast-rules.py --ref f1d2b562b414783763fd02a6ed2736eaed622efa
  python scripts/refresh-sast-rules.py --ref main --dry-run
  python scripts/refresh-sast-rules.py --source D:/scratch/opengrep-rules --init-allowlist
"""
from __future__ import annotations

import argparse
import io
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

import yaml

UPSTREAM_URL = "https://github.com/opengrep/opengrep-rules"
REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "src" / "slsec" / "configs" / "sast-rules"
ALLOWLIST = RULES_DIR / "allowlist.yaml"

# Pack name -> upstream top-level language dirs feeding it. Anything under a
# dir other than the first listed one keeps that dir as a path prefix inside the
# pack (so TypeScript rules land in javascript/typescript/...).
PACKS = {
    "java": ["java"],
    "kotlin": ["kotlin"],
    "javascript": ["javascript", "typescript"],
    "python": ["python"],
    "go": ["go"],
    "csharp": ["csharp"],
}

# --- curation criteria -------------------------------------------------------
# OWASP Top 10 oriented CWE ids: injection, XSS, deserialization, XXE, weak
# crypto/hashing, hardcoded credentials, SSRF, path traversal, TLS validation,
# dangerous eval/exec, open redirect, SSTI, debug mode.
CWE_OK = {
    22, 23, 73, 78, 79, 89, 90, 94, 95, 116, 287, 295, 297, 323, 326, 327, 328,
    329, 338, 347, 489, 502, 601, 611, 643, 780, 798, 918, 1336,
}
# CWE-522 is only accepted for the hardcoded-JWT-secret rules (extra_paths).
EXTRA_PATHS = {"python/jwt/security/jwt-hardcode.yaml"}

# Niche frameworks / non-code contexts: skipped wholesale (path prefix match).
EXCLUDE_DIR_PARTS = (
    "/aws-lambda/", "/angular/", "/chrome-remote-interface/", "/deno/",
    "/argon2/", "/pyramid/", "/twilio/", "/pymongo/", "/distributed/",
    "/aws-cdk/", "/android/", "/jboss/", "/gradle/", "/bokeh/", "/spring/security/audit/spring-actuator",
    "/express/security/express-phantom", "/express/security/express-puppeteer",
    "/express/security/express-sandbox", "/express/security/express-vm2",
    "/express/security/express-xml2json", "/express/security/audit/express-xml2json",
    "/express/security/express-expat", "/express/security/require-request",
)
# Individually noisy rule ids.
EXCLUDE_IDS = {"math-random-used", "wip-xss-using-responsewriter-and-printf"}
MAX_RULE_SIZE = 10000  # chars of JSON excluding metadata/message: expensive-pattern guard


def _w(path: Path, text: str) -> None:
    """Write UTF-8 text with LF endings on every platform (Path.write_text has no newline arg on 3.9)."""
    path.write_bytes(text.encode("utf-8"))


def top_dir_to_pack(top: str) -> str | None:
    for pack, tops in PACKS.items():
        if top in tops:
            return pack
    return None


def pack_relpath(upstream_rel: str) -> tuple[str, str]:
    """upstream path -> (pack, path inside pack dir)."""
    top, _, rest = upstream_rel.partition("/")
    pack = top_dir_to_pack(top)
    if pack is None:
        raise ValueError(upstream_rel)
    inside = rest if top == PACKS[pack][0] else f"{top}/{rest}"
    return pack, inside


def rule_ok(rule: dict, upstream_rel: str) -> bool:
    import json

    meta = rule.get("metadata") or {}
    if meta.get("category") != "security":
        return False
    if rule.get("severity") not in ("ERROR", "WARNING"):
        return False
    if meta.get("confidence") not in ("MEDIUM", "HIGH"):
        return False
    if rule.get("id") in EXCLUDE_IDS:
        return False
    opts = rule.get("options") or {}
    if opts.get("interfile") or meta.get("interfile"):
        return False  # needs cross-file context
    slim = {k: v for k, v in rule.items() if k not in ("metadata", "message")}
    if len(json.dumps(slim)) > MAX_RULE_SIZE:
        return False
    marker = "/" + upstream_rel
    if any(part in marker for part in EXCLUDE_DIR_PARTS):
        return False
    if upstream_rel in EXTRA_PATHS:
        return True
    cwe = meta.get("cwe")
    cwes = cwe if isinstance(cwe, list) else [cwe]
    nums = {int(m) for c in cwes for m in re.findall(r"CWE-(\d+)", str(c))}
    return bool(nums & CWE_OK)


def scan_upstream(src: Path):
    """Yield (upstream_rel, [rule dicts]) for every parseable rule file."""
    for top in sorted({t for tops in PACKS.values() for t in tops}):
        base = src / top
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if p.suffix not in (".yaml", ".yml") or ".test." in p.name:
                continue
            try:
                doc = yaml.safe_load(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(doc, dict) and isinstance(doc.get("rules"), list):
                yield p.relative_to(src).as_posix(), doc["rules"]


def candidate_files(src: Path) -> dict[str, list[str]]:
    """Files where ALL rules meet the criteria (files are copied verbatim, so a
    file is only a candidate if nothing in it fails the criteria)."""
    out = {}
    for rel, rules in scan_upstream(src):
        if rules and all(rule_ok(r, rel) for r in rules):
            out[rel] = [r["id"] for r in rules]
    return out


# --- fetching -----------------------------------------------------------------
def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def fetch(ref: str, dest: Path) -> str:
    """Fetch upstream at ref into dest; return the full commit SHA."""
    if shutil.which("git"):
        run(["git", "init", "-q", str(dest)])
        run(["git", "remote", "add", "origin", UPSTREAM_URL], cwd=dest)
        run(["git", "fetch", "-q", "--depth", "1", "origin", ref], cwd=dest)
        run(["git", "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"], cwd=dest)
        return run(["git", "rev-parse", "HEAD"], cwd=dest)
    # No git: resolve the sha through the API and download the zip archive.
    req = urllib.request.Request(
        f"https://api.github.com/repos/opengrep/opengrep-rules/commits/{ref}",
        headers={"Accept": "application/vnd.github.sha"},
    )
    sha = urllib.request.urlopen(req, timeout=60).read().decode().strip()
    data = urllib.request.urlopen(f"{UPSTREAM_URL}/archive/{sha}.zip", timeout=300).read()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            parts = name.split("/", 1)
            if len(parts) == 2 and parts[1] and not name.endswith("/"):
                target = (dest / parts[1]).resolve()
                if dest.resolve() not in target.parents:  # zip-slip guard
                    raise RuntimeError(f"unsafe path in archive: {name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(name))
    return sha


# --- allowlist ----------------------------------------------------------------
def load_allowlist() -> dict:
    with ALLOWLIST.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def write_allowlist(commit: str, files: dict[str, list[str]]) -> None:
    packs: dict[str, dict[str, list[str]]] = {p: {} for p in PACKS}
    for rel, ids in sorted(files.items()):
        pack, _ = pack_relpath(rel)
        packs[pack][rel] = ids
    lines = [
        "# Source of truth for the vendored SAST rule curation.",
        "# Each entry is an upstream path (relative to the opengrep-rules repo root)",
        "# plus the rule ids that file defines. Files are copied verbatim by",
        "# scripts/refresh-sast-rules.py. Edit this file to add/remove rules, then",
        "# run the script. See README.md for the selection criteria.",
        f"upstream: {UPSTREAM_URL}",
        f"commit: {commit}",
        "packs:",
    ]
    for pack, entries in packs.items():
        lines.append(f"  {pack}:")
        if not entries:
            lines[-1] += " {}"
        for rel, ids in entries.items():
            lines.append(f"    {rel}: [{', '.join(ids)}]")
    _w(ALLOWLIST, "\n".join(lines) + "\n")


# --- generated files ----------------------------------------------------------
NOTICE = """\
slsec vendored SAST rules
=========================

The files under src/slsec/configs/sast-rules/<pack>/ are third-party
Semgrep-syntax rules vendored from opengrep-rules. They are NOT covered by this
repository's Apache-2.0 license.

  Source:   {url}
  Commit:   {commit}
  License:  LGPL-2.1 with the Commons Clause License Condition v1.0, exactly as
            stated in the upstream LICENSE file (copied verbatim next to this
            NOTICE as LICENSE; the full LGPL-2.1 text is in COPYING.LGPL-2.1).
  Licensor: Semgrep, Inc. (upstream rules originate from semgrep-rules)

Modifications: none to the rule files. Every file under <pack>/ is a
byte-for-byte copy of the upstream file at the commit above. Only a curated
subset of files is included, and the upstream test target files are not
included. MANIFEST.txt lists every included rule id and its upstream path;
allowlist.yaml is the curation source of truth.

Derived files: bundles/<pack>.yaml concatenate the rules of one pack into a
single file (faster to load). They are generated by
scripts/refresh-sast-rules.py. The only change to any rule is that its `id` is
rewritten to the path-qualified form the engine itself assigns in directory
mode (<pack>.<dotted.dirs.in.pack>.<original-id>). The rule bodies are otherwise
semantically unchanged (re-serialised YAML).

License boundary: only this directory (src/slsec/configs/sast-rules/) is
LGPL-2.1 + Commons Clause. Everything else in the repository, including the
scripts, the Python package and tests, is Apache-2.0. The rules are data files
read by the SAST engine at run time; slsec does not link against them.

The Commons Clause condition restricts selling the Software (including
selling support or hosting whose value derives substantially from it). Review it
with legal counsel before redistributing these rules commercially.
"""


def qualified_id(upstream_rel: str, rule_id: str) -> str:
    """Id the engine assigns in directory mode: <pack>.<dotted DIRECTORY path in pack>.<id>.

    (The file name is not part of the id; verified against opengrep 1.33.1.)
    """
    pack, inside = pack_relpath(upstream_rel)
    dirs = inside.rsplit("/", 1)[0].replace("/", ".") if "/" in inside else ""
    return ".".join(x for x in (pack, dirs, rule_id) if x)


def write_bundles(files: dict[str, list[str]]) -> None:
    """Write bundles/<pack>.yaml: every rule of a pack in ONE file.

    Loading ~100 separate rule files is the dominant cost of a scan on Windows
    (measured: 84 python rules, 11.8s as a directory vs 5.3s as one file), so
    the hook should prefer these. The ONLY change to a rule is its `id`, which
    becomes the path-qualified id the engine would assign in directory mode, so
    findings are identical either way. The per-rule files stay the source of
    truth; bundles are derived and verified by tests/test_sast_rules.py.
    """
    out_dir = RULES_DIR / "bundles"
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    for pack in PACKS:
        rules = []
        for rel in sorted(files):
            if pack_relpath(rel)[0] != pack:
                continue
            doc = yaml.safe_load((RULES_DIR / pack / pack_relpath(rel)[1]).read_text(encoding="utf-8"))
            for r in doc["rules"]:
                r["id"] = qualified_id(rel, r["id"])
                rules.append(r)
        header = (
            f"# GENERATED by scripts/refresh-sast-rules.py - do not edit.\n"
            f"# All '{pack}' rules from opengrep-rules in one file (rule ids are path-qualified).\n"
            f"# License: LGPL-2.1 with Commons Clause; see ../NOTICE and ../LICENSE.\n"
        )
        body = yaml.safe_dump({"rules": rules}, sort_keys=False, allow_unicode=True, width=100000)
        _w(out_dir / f"{pack}.yaml", header + body)


def write_generated(commit: str, files: dict[str, list[str]], src: Path) -> None:
    write_bundles(files)
    _w(RULES_DIR / "NOTICE", NOTICE.format(url=UPSTREAM_URL, commit=commit))
    _w(RULES_DIR / "SOURCE", f"repo: {UPSTREAM_URL}\ncommit: {commit}\n")
    shutil.copyfile(src / "LICENSE", RULES_DIR / "LICENSE")
    rows = ["# pack<TAB>rule id<TAB>upstream path (commit " + commit + ")"]
    for rel, ids in sorted(files.items()):
        pack, _ = pack_relpath(rel)
        for rid in ids:
            rows.append(f"{pack}\t{rid}\t{rel}")
    _w(RULES_DIR / "MANIFEST.txt", "\n".join(rows) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ref", help="upstream commit SHA or tag (default: commit in allowlist.yaml)")
    ap.add_argument("--source", type=Path, help="use an existing local checkout instead of fetching")
    ap.add_argument("--dry-run", action="store_true", help="report only; do not modify the repo")
    ap.add_argument("--init-allowlist", action="store_true",
                    help="write a DRAFT allowlist from the built-in criteria (then prune it by hand)")
    args = ap.parse_args()

    tmp = None
    try:
        if args.source:
            src = args.source.resolve()
            commit = run(["git", "rev-parse", "HEAD"], cwd=src) if (src / ".git").exists() else (args.ref or "unknown")
        else:
            ref = args.ref or load_allowlist()["commit"]
            tmp = Path(tempfile.mkdtemp(prefix="slsec-rules-"))
            src = tmp / "up"
            src.mkdir()
            commit = fetch(ref, src)
        print(f"upstream commit: {commit}")

        cands = candidate_files(src)
        if args.init_allowlist:
            write_allowlist(commit, cands)
            print(f"draft allowlist written: {sum(len(v) for v in cands.values())} rules in {len(cands)} files")
            return 0

        allow = load_allowlist()
        rejected = set(allow.get("rejected") or [])
        wanted: dict[str, list[str]] = {}
        for entries in allow["packs"].values():
            wanted.update(entries or {})

        # Removed / changed upstream.
        problems = 0
        upstream_ids = {rel: [r["id"] for r in rules] for rel, rules in scan_upstream(src)}
        for rel, ids in sorted(wanted.items()):
            if rel not in upstream_ids:
                print(f"REMOVED upstream: {rel}")
                problems += 1
            elif upstream_ids[rel] != ids:
                print(f"CHANGED ids upstream: {rel}: {ids} -> {upstream_ids[rel]}")
                problems += 1
        # Added upstream (meets criteria, not allowlisted).
        for rel, ids in sorted(cands.items()):
            if rel not in wanted and rel not in rejected:
                print(f"NEW candidate: {rel} ({', '.join(ids)})")

        if args.dry_run:
            print("dry run: no files written")
            return 1 if problems else 0
        if problems:
            print("refusing to copy: fix allowlist.yaml for removed/changed rules first", file=sys.stderr)
            return 1

        for pack in PACKS:
            shutil.rmtree(RULES_DIR / pack, ignore_errors=True)
        for rel in sorted(wanted):
            pack, inside = pack_relpath(rel)
            dest = RULES_DIR / pack / inside
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src / rel, dest)
        write_generated(commit, wanted, src)
        print(f"copied {len(wanted)} files / {sum(len(v) for v in wanted.values())} rules")
        return 0
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
