import json
import xml.etree.ElementTree as ET

from slsec import reports


def sarif(tool, *results, rules=None):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool, "rules": [{"id": r} for r in (rules or [])]}},
                "results": [
                    {"ruleId": rid, "ruleIndex": (rules or []).index(rid) if rid in (rules or []) else 0,
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]}
                    for rid, uri in results
                ],
            }
        ],
    }


def uris(doc):
    return sorted(
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for run in doc["runs"] for r in run["results"]
    )


def test_merge_folds_same_tool_into_one_run_and_reindexes_rules():
    a = sarif("checkov", ("CKV_1", "a.tf"), rules=["CKV_1"])
    b = sarif("checkov", ("CKV_2", "b.tf"), ("CKV_1", "b.tf"), rules=["CKV_2", "CKV_1"])
    merged = reports.merge_sarif([a, b])
    assert len(merged["runs"]) == 1
    run = merged["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["CKV_1", "CKV_2"]
    assert [(r["ruleId"], r["ruleIndex"]) for r in run["results"]] == [("CKV_1", 0), ("CKV_2", 1), ("CKV_1", 0)]


def test_merge_keeps_different_tools_apart():
    merged = reports.merge_sarif([sarif("snyk", ("X", "a")), sarif("osv", ("Y", "b"))])
    assert [r["tool"]["driver"]["name"] for r in merged["runs"]] == ["snyk", "osv"]


def test_merge_offsets_artifact_indexes():
    a = sarif("t", ("R", "a"))
    a["runs"][0]["artifacts"] = [{"location": {"uri": "a"}}]
    a["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["index"] = 0
    b = json.loads(json.dumps(a))
    b["runs"][0]["artifacts"] = [{"location": {"uri": "b"}}]
    merged = reports.merge_sarif([a, b])
    idx = [r["locations"][0]["physicalLocation"]["artifactLocation"]["index"] for r in merged["runs"][0]["results"]]
    assert idx == [0, 1]
    assert len(merged["runs"][0]["artifacts"]) == 2


def test_publish_without_run_id_overwrites(tmp_path):
    dest = tmp_path / "r.sarif"
    reports.publish_sarif(dest, sarif("t", ("R", "a")), env={})
    reports.publish_sarif(dest, sarif("t", ("R", "b")), env={})
    assert uris(json.loads(dest.read_text())) == ["b"]


def test_publish_same_run_id_accumulates(tmp_path):
    dest = tmp_path / "r.sarif"
    env = {"SLSEC_RUN_ID": "42-1"}
    for uri in ("a", "b", "c"):  # e.g. pre-commit's three batches of 12,000 files
        reports.publish_sarif(dest, sarif("t", ("R", uri)), env=env)
    doc = json.loads(dest.read_text())
    assert uris(doc) == ["a", "b", "c"]
    assert len(doc["runs"]) == 1


def test_publish_new_run_id_replaces_stale_report(tmp_path):
    dest = tmp_path / "r.sarif"
    reports.publish_sarif(dest, sarif("t", ("R", "old")), env={"SLSEC_RUN_ID": "1"})
    reports.publish_sarif(dest, sarif("t", ("R", "new")), env={"SLSEC_RUN_ID": "2"})
    assert uris(json.loads(dest.read_text())) == ["new"]


def test_publish_ignores_unreadable_previous_report(tmp_path):
    dest = tmp_path / "r.sarif"
    dest.write_text("{not json")
    reports.publish_sarif(dest, sarif("t", ("R", "a")), env={"SLSEC_RUN_ID": "1"})
    assert uris(json.loads(dest.read_text())) == ["a"]


def _suite(name, tests, failures):
    s = ET.Element("testsuite", name=name, tests=str(tests), failures=str(failures), errors="0")
    for i in range(tests):
        ET.SubElement(s, "testcase", name=f"{name}-{i}")
    return s


def test_junit_accumulates_within_a_run_and_resets_across_runs(tmp_path):
    dest = tmp_path / "r.xml"
    env = {"SLSEC_RUN_ID": "1"}
    reports.publish_junit(dest, [_suite("a", 2, 1)], env=env)
    reports.publish_junit(dest, [_suite("b", 3, 0)], env=env)
    root = ET.parse(dest).getroot()
    assert (root.get("tests"), root.get("failures")) == ("5", "1")
    assert [s.get("name") for s in root.iter("testsuite")] == ["a", "b"]
    reports.publish_junit(dest, [_suite("c", 1, 1)], env={"SLSEC_RUN_ID": "2"})
    root = ET.parse(dest).getroot()
    assert [s.get("name") for s in root.iter("testsuite")] == ["c"]
