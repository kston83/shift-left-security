"""Write SARIF / JUnit reports so that every hook run in one CI job adds up.

pre-commit splits a long file list into several invocations of the same hook (on
Linux the command line is capped at 128 KiB, so ~12,000 files means 3 runs). If
each run simply wrote `checkov-terraform.sarif`, the last one would win, code
scanning would get a partial upload, and alerts from the earlier batches would be
closed as "fixed".

So reports are tagged with a run id, taken from SLSEC_RUN_ID (the CI templates
and `slsec ci` set it). When a report with the same run id is already on disk,
the new results are merged into it. A report from an earlier run (a reused
Jenkins workspace, a developer's local report dir) is replaced instead.

Without SLSEC_RUN_ID, the report is written fresh each time (local use).
"""

from __future__ import annotations

import copy
import json
import os
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, List, Mapping, Optional

RUN_ID_ENV = "SLSEC_RUN_ID"
SARIF_RUN_ID_KEY = "slsecRunId"  # in each run's property bag
JUNIT_RUN_ID_ATTR = "slsec-run-id"  # on the <testsuites> root


def run_id(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    env = os.environ if env is None else env
    value = str(env.get(RUN_ID_ENV) or "").strip()
    return value or None


def new_run_id() -> str:
    return uuid.uuid4().hex


def fix_uri(uri: str) -> str:
    # Engines write Windows-style paths on Windows; SARIF consumers want "/".
    return uri.replace("\\", "/") if os.name == "nt" else uri


def _artifact_locations(result: dict) -> Iterable[dict]:
    for key in ("locations", "relatedLocations"):
        for loc in result.get(key) or []:
            art = (loc.get("physicalLocation") or {}).get("artifactLocation")
            if isinstance(art, dict):
                yield art


def _driver_name(run: dict) -> str:
    return str(((run.get("tool") or {}).get("driver") or {}).get("name") or "")


def merge_sarif(docs: Iterable[dict]) -> dict:
    """Merge SARIF logs into one, with a single run per tool.

    Code scanning rejects (or silently collapses) several runs from the same tool
    in one upload, so runs with the same driver name are folded together: results
    are appended, rules de-duplicated by id, and `ruleIndex` / artifact indexes
    renumbered to match the merged lists.
    """
    merged: Optional[dict] = None
    by_tool: dict = {}
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        doc = copy.deepcopy(doc)
        if merged is None:
            merged = {k: v for k, v in doc.items() if k != "runs"}
            merged.setdefault("version", "2.1.0")
            merged["runs"] = []
        for run in doc.get("runs") or []:
            if not isinstance(run, dict):
                continue
            for result in run.get("results") or []:
                for art in _artifact_locations(result):
                    if "uri" in art:
                        art["uri"] = fix_uri(str(art["uri"]))
            name = _driver_name(run)
            target = by_tool.get(name)
            if target is None:
                by_tool[name] = run
                merged["runs"].append(run)
                continue
            _fold_run(target, run)
    if merged is None:
        merged = {"version": "2.1.0", "runs": []}
    for run in merged["runs"]:
        _reindex_rules(run)
    return merged


def _fold_run(target: dict, run: dict) -> None:
    offset = len(target.get("artifacts") or [])
    if run.get("artifacts"):
        target.setdefault("artifacts", []).extend(run["artifacts"])
    for result in run.get("results") or []:
        if offset:
            for art in _artifact_locations(result):
                if isinstance(art.get("index"), int):
                    art["index"] += offset
        target.setdefault("results", []).append(result)
    driver = target.setdefault("tool", {}).setdefault("driver", {})
    rules = driver.setdefault("rules", [])
    known = {r.get("id") for r in rules}
    for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
        if rule.get("id") not in known:
            known.add(rule.get("id"))
            rules.append(rule)
    if run.get("invocations"):
        target.setdefault("invocations", []).extend(run["invocations"])


def _reindex_rules(run: dict) -> None:
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    index = {}
    for i, rule in enumerate(rules):
        index.setdefault(rule.get("id"), i)
    for result in run.get("results") or []:
        rid = result.get("ruleId") or (result.get("rule") or {}).get("id")
        if rid not in index:
            continue
        if "ruleIndex" in result:
            result["ruleIndex"] = index[rid]
        if isinstance(result.get("rule"), dict) and "index" in result["rule"]:
            result["rule"]["index"] = index[rid]


def result_count(doc: dict) -> int:
    try:
        return sum(len(r.get("results") or []) for r in doc.get("runs") or [])
    except (AttributeError, TypeError):
        return 0


def _sarif_run_id(doc: dict) -> Optional[str]:
    for run in doc.get("runs") or []:
        rid = (run.get("properties") or {}).get(SARIF_RUN_ID_KEY)
        if rid:
            return str(rid)
    return None


def _atomic_write(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, dest)


def publish_sarif(dest: Path, doc: dict, env: Optional[Mapping[str, str]] = None) -> dict:
    """Write `doc` to `dest`, merging with a report from the same run if one is there."""
    rid = run_id(env)
    docs: List[dict] = []
    if rid and dest.is_file():
        try:
            previous = json.loads(dest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = None
        if isinstance(previous, dict) and _sarif_run_id(previous) == rid:
            docs.append(previous)
    docs.append(doc)
    merged = merge_sarif(docs)
    if rid:
        for run in merged["runs"]:
            run.setdefault("properties", {})[SARIF_RUN_ID_KEY] = rid
    _atomic_write(dest, json.dumps(merged, indent=2).encode("utf-8"))
    return merged


def _suites(root: ET.Element) -> List[ET.Element]:
    return [root] if root.tag == "testsuite" else list(root.iter("testsuite"))


def publish_junit(dest: Path, suites: Iterable[ET.Element], env: Optional[Mapping[str, str]] = None) -> None:
    """Write `<testsuites>` holding `suites`, after any suites from the same run already in `dest`."""
    rid = run_id(env)
    out = ET.Element("testsuites")
    collected: List[ET.Element] = []
    if rid and dest.is_file():
        try:
            prev_root = ET.parse(str(dest)).getroot()
        except (OSError, ET.ParseError):
            prev_root = None
        if prev_root is not None and prev_root.get(JUNIT_RUN_ID_ATTR) == rid:
            collected.extend(_suites(prev_root))
    collected.extend(suites)
    totals = {"tests": 0, "failures": 0, "errors": 0}
    for suite in collected:
        for k in totals:
            try:
                totals[k] += int(suite.get(k, "0") or 0)
            except ValueError:
                pass
        out.append(suite)
    for k, v in totals.items():
        out.set(k, str(v))
    if rid:
        out.set(JUNIT_RUN_ID_ATTR, rid)
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}.tmp")
    dest.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(out).write(str(tmp), encoding="utf-8", xml_declaration=True)
    os.replace(tmp, dest)


def read_junit_suites(path: Path) -> List[ET.Element]:
    try:
        return _suites(ET.parse(str(path)).getroot())
    except (OSError, ET.ParseError):
        return []
