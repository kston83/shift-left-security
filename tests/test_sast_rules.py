"""Tests for the vendored SAST rule packs. The non-integration tests need no network."""
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES = REPO_ROOT / "src" / "slsec" / "configs" / "sast-rules"
FIXTURES = REPO_ROOT / "tests" / "fixtures"
PACKS = ["java", "kotlin", "javascript", "python", "go", "csharp"]


def _load_refresh():
    spec = importlib.util.spec_from_file_location("refresh_sast_rules", REPO_ROOT / "scripts" / "refresh-sast-rules.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


refresh = _load_refresh()


def _rule_files(pack):
    return sorted(p for p in (RULES / pack).rglob("*") if p.suffix in (".yaml", ".yml"))


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _allowlist():
    return yaml.safe_load((RULES / "allowlist.yaml").read_text(encoding="utf-8"))


def _qualified_ids():
    """Every qualified rule id, from the per-rule files."""
    out = []
    for pack in PACKS:
        for f in _rule_files(pack):
            inside = f.relative_to(RULES / pack).as_posix()
            dirs = inside.rsplit("/", 1)[0].replace("/", ".") if "/" in inside else ""
            for r in _load(f)["rules"]:
                out.append(".".join(x for x in (pack, dirs, r["id"]) if x))
    return out


@pytest.mark.parametrize("pack", PACKS)
def test_pack_dir_exists_and_parses(pack):
    files = _rule_files(pack)
    assert files, f"pack {pack} is empty"
    for f in files:
        doc = _load(f)
        assert isinstance(doc, dict) and isinstance(doc.get("rules"), list) and doc["rules"], f


@pytest.mark.parametrize("pack", PACKS)
def test_rules_have_required_fields(pack):
    for f in _rule_files(pack):
        for r in _load(f)["rules"]:
            for key in ("id", "languages", "severity", "message"):
                assert r.get(key), f"{f}: rule {r.get('id')} missing {key}"
            assert r["severity"] in ("ERROR", "WARNING"), f"{f}: {r['id']} severity {r['severity']}"


def test_qualified_rule_ids_are_unique_across_packs():
    # Short ids repeat upstream (e.g. 'ecb-cipher' in java and kotlin); the id the
    # engine reports is path-qualified, and that is what must be unique.
    ids = _qualified_ids()
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})


def test_allowlist_matches_files_present():
    allow = _allowlist()
    assert set(allow["packs"]) == set(PACKS)
    present = set()
    for pack in PACKS:
        for upstream_rel, ids in (allow["packs"][pack] or {}).items():
            got_pack, inside = refresh.pack_relpath(upstream_rel)
            assert got_pack == pack, upstream_rel
            f = RULES / pack / inside
            assert f.is_file(), f"allowlisted but missing: {upstream_rel}"
            assert [r["id"] for r in _load(f)["rules"]] == ids, upstream_rel
            present.add(f.resolve())
    on_disk = {f.resolve() for pack in PACKS for f in _rule_files(pack)}
    assert on_disk == present, f"files not in allowlist: {sorted(map(str, on_disk - present))}"


def test_manifest_matches_allowlist():
    rows = [
        line.split("\t")
        for line in (RULES / "MANIFEST.txt").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    expected = [
        [pack, rid, rel]
        for pack in PACKS
        for rel, ids in (_allowlist()["packs"][pack] or {}).items()
        for rid in ids
    ]
    assert sorted(rows) == sorted(expected)


def test_bundles_match_pack_files():
    for pack in PACKS:
        bundle = _load(RULES / "bundles" / f"{pack}.yaml")["rules"]
        files = {}
        for f in _rule_files(pack):
            inside = f.relative_to(RULES / pack).as_posix()
            dirs = inside.rsplit("/", 1)[0].replace("/", ".") if "/" in inside else ""
            for r in _load(f)["rules"]:
                files[".".join(x for x in (pack, dirs, r["id"]) if x)] = r
        assert sorted(r["id"] for r in bundle) == sorted(files), pack
        for r in bundle:  # identical apart from id
            orig = dict(files[r["id"]])
            assert {k: v for k, v in r.items() if k != "id"} == {k: v for k, v in orig.items() if k != "id"}, r["id"]


def test_provenance_files_present():
    for name in ("LICENSE", "COPYING.LGPL-2.1", "NOTICE", "SOURCE", "README.md", "MANIFEST.txt"):
        assert (RULES / name).is_file(), name
    commit = _allowlist()["commit"]
    assert len(commit) == 40
    assert commit in (RULES / "NOTICE").read_text(encoding="utf-8")
    assert commit in (RULES / "SOURCE").read_text(encoding="utf-8")


def test_expected_file_references_real_rules_and_fixtures():
    expected = yaml.safe_load((FIXTURES / "sast-expected.yaml").read_text(encoding="utf-8"))["fixtures"]
    ids = set(_qualified_ids())
    assert set(v["pack"] for v in expected.values()) <= set(PACKS)
    for path, spec in expected.items():
        assert (FIXTURES / path).is_file(), path
        assert (FIXTURES / spec["secure"]).is_file(), spec["secure"]
        assert spec["rules"]
        for rid in spec["rules"]:
            assert rid in ids, f"{path}: unknown rule {rid}"


# ---------------------------------------------------------------------------
@pytest.mark.integration
@pytest.mark.parametrize("config_kind", ["bundle", "directory"])
def test_fixtures_trigger_expected_rules(config_kind):
    exe = os.environ.get("SLSEC_OPENGREP_PATH")
    if not exe or not Path(exe).is_file():
        pytest.skip("SLSEC_OPENGREP_PATH not set to an opengrep binary")
    expected = yaml.safe_load((FIXTURES / "sast-expected.yaml").read_text(encoding="utf-8"))["fixtures"]
    for path, spec in expected.items():
        pack = spec["pack"]
        config = RULES / "bundles" / f"{pack}.yaml" if config_kind == "bundle" else RULES / pack
        files = [str(FIXTURES / path), str(FIXTURES / spec["secure"])]  # explicit files bypass .semgrepignore
        proc = subprocess.run(
            [exe, "scan", "--disable-version-check", "--quiet", "--json", "--config", str(config), *files],
            capture_output=True, text=True, timeout=300,
        )
        data = json.loads(proc.stdout)
        assert not data["errors"], data["errors"]
        found = {}
        for r in data["results"]:
            found.setdefault(Path(r["path"]).name, set()).add(r["check_id"])

        def matches(check_id, rule_id):
            return check_id == rule_id or check_id.endswith("." + rule_id)

        hit = found.get(Path(path).name, set())
        for rid in spec["rules"]:
            assert any(matches(c, rid) for c in hit), f"{path}: expected {rid}; got {sorted(hit)}"
        assert Path(spec["secure"]).name not in found, f"{spec['secure']} must be clean: {found.get(Path(spec['secure']).name)}"
