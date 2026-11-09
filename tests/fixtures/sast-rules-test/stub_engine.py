"""Stand-in for opengrep/semgrep in the slsec-sast unit tests.

Appends its argv to $STUB_LOG (one JSON list per line), writes SARIF/JUnit
files when asked (with Windows-style URIs, like the real engine on Windows),
and exits with $STUB_RC (default 1: "findings").
"""

import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(args) + "\n")

targets = [a for a in args if not a.startswith("-") and a != "scan" and args[args.index(a) - 1] not in ("--config", "--exclude-rule")]
for a in args:
    if a.startswith("--sarif-output="):
        results = [
            {
                "ruleId": "slsec-test-python-eval",
                "message": {"text": "eval"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": t.replace("/", "\\")}, "region": {"startLine": 1}}}],
            }
            for t in targets
        ]
        doc = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Stub", "rules": [{"id": "slsec-test-python-eval"}]}}, "results": results, "invocations": [{"executionSuccessful": True}]}],
        }
        with open(a.split("=", 1)[1], "w", encoding="utf-8") as f:
            json.dump(doc, f)
    if a.startswith("--junit-xml-output="):
        cases = "".join(f'<testcase name="slsec-test-python-eval" classname="{t.replace("/", chr(92))}" file="{t.replace("/", chr(92))}"><failure/></testcase>' for t in targets)
        with open(a.split("=", 1)[1], "w", encoding="utf-8") as f:
            f.write(f'<?xml version="1.0"?><testsuites><testsuite name="semgrep results" tests="{len(targets)}" failures="{len(targets)}" errors="0">{cases}</testsuite></testsuites>')

sys.exit(int(os.environ.get("STUB_RC", "1")))
