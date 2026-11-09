"""The slsec gitleaks rules (src/slsec/configs/gitleaks/gitleaks.toml).

The unit tests apply each rule the way gitleaks does: path regex, then the rule
regex, then the secret group's allowlists, then the entropy floor. Python's `re`
accepts the RE2 syntax the rules use. When a `gitleaks` binary is on PATH, the
integration test runs the real thing over the same cases.
"""

import json
import math
import shutil
import subprocess
import tomllib
from collections import Counter

import re

import pytest

from slsec.config import bundled_text

CONFIG = tomllib.loads(bundled_text("configs", "gitleaks", "gitleaks.toml"))
RULES = {r["id"]: r for r in CONFIG["rules"]}
SECRET = "slsec-mcp-config-secret"
AUTH = "slsec-mcp-config-auth-header"

# realistic-looking but fake values with enough entropy to pass the 3.0 floor
FAKE = "q7Ft2LmZp9Xc4Rv8Kd1Wn6Hs3Jb5Ye0A"  # gitleaks:allow (synthetic)


def _entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def findings(rule_id: str, path: str, text: str):
    rule = RULES[rule_id]
    if not re.search(rule["path"], path):
        return []
    out = []
    for m in re.finditer(rule["regex"], text):
        secret = m.group(rule.get("secretGroup", 0))
        allowed = False
        for allow in rule.get("allowlists", []):
            if allow.get("regexTarget") == "secret" and any(re.search(rx, secret) for rx in allow.get("regexes", [])):
                allowed = True
        if allowed or _entropy(secret) < rule.get("entropy", 0):
            continue
        out.append(secret)
    return out


def env_line(key: str, value: str) -> str:
    return json.dumps({key: value})


@pytest.mark.parametrize(
    "key",
    [
        "API_KEY", "BRAVE_API_KEY", "GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_PAT", "SLACK_BOT_TOKEN",
        "client_secret", "client-secret", "DB_PASSWORD", "token", "PAT", "apiKey", "githubToken",
        "ApiKey", "clientSecret", "apikey", "accesstoken", "AUTHTOKEN", "credentials", "GOOGLE_CREDENTIALS",
        "npm.token",
    ],
)
def test_secret_keys_are_flagged(key):
    assert findings(SECRET, ".mcp.json", env_line(key, FAKE)) == [FAKE]


@pytest.mark.parametrize(
    "key",
    [
        "PATH", "path", "Path", "PYTHONPATH", "TOKEN_FILE", "KEY_ID", "monkey", "keyboard", "TOKENIZER",
        "SECRET_NAME", "PASSWORD_FILE", "patch", "pattern", "compat", "keys", "tokens_url", "spatial",
    ],
)
def test_non_secret_keys_are_not_flagged(key):
    assert findings(SECRET, ".mcp.json", env_line(key, FAKE)) == []


@pytest.mark.parametrize(
    "key,value",
    [
        # the false positives from the review
        ("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"),
        ("TOKEN_FILE", "~/secrets/mytoken.txt"),
        # path-like values under secret-looking keys are references, not secrets
        ("GITHUB_TOKEN", "~/secrets/mytoken.txt"),
        ("API_KEY", "/run/secrets/api_key"),
        ("SERVICE_ACCOUNT_CREDENTIALS", "./config/sa-key.json"),
        ("SERVICE_ACCOUNT_CREDENTIALS", "sa-prod-key.json"),
        ("CLIENT_SECRET", "C:\\Users\\dev\\secrets\\client.txt"),
        ("CLIENT_SECRET", "%USERPROFILE%\\secrets\\client.txt"),
        # env references and placeholders
        ("API_KEY", "${BRAVE_API_KEY}"),
        ("API_KEY", "your-api-key-here"),
        ("API_KEY", "<paste key>"),
        ("API_KEY", "changeme"),
    ],
)
def test_paths_references_and_placeholders_are_allowed(key, value):
    # json.dumps writes Windows paths with escaped backslashes, as they appear in the file
    assert findings(SECRET, ".mcp.json", env_line(key, value)) == []


def test_real_secret_in_a_path_like_key_value_pair_still_flags():
    # a value that merely starts with "/" but is a token (contains + and =) is not a path
    value = "/q7Ft2L+mZp9Xc4Rv8Kd1Wn6Hs3Jb5Ye0A=="  # gitleaks:allow (synthetic)
    assert findings(SECRET, ".mcp.json", env_line("API_KEY", value)) == [value]


@pytest.mark.parametrize(
    "path,hit",
    [
        (".mcp.json", True),
        ("tools/.cursor/mcp.json", True),
        (".claude/settings.local.json", True),
        ("claude_desktop_config.json", True),
        ("package.json", False),
        ("docs/mcp.json.md", False),
    ],
)
def test_rule_only_applies_to_agent_configs(path, hit):
    assert bool(findings(SECRET, path, env_line("API_KEY", FAKE))) is hit


def test_full_mcp_config_flags_only_the_secret():
    text = json.dumps(
        {
            "mcpServers": {
                "github": {
                    "command": "docker",
                    "env": {
                        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
                        "TOKEN_FILE": "~/secrets/mytoken.txt",
                        "GITHUB_PERSONAL_ACCESS_TOKEN": FAKE,
                        "LOG_LEVEL": "debugverbose",
                    },
                }
            }
        },
        indent=2,
    )
    assert findings(SECRET, ".mcp.json", text) == [FAKE]


@pytest.mark.parametrize(
    "value,hit",
    [
        ("Bearer " + FAKE, True),
        ("token " + FAKE, True),
        ("Bearer ${GITHUB_TOKEN}", False),
        ("Bearer short", False),
    ],
)
def test_authorization_header(value, hit):
    assert bool(findings(AUTH, ".vscode/mcp.json", json.dumps({"Authorization": value}))) is hit


@pytest.mark.integration
@pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks not on PATH")
def test_real_gitleaks_agrees(tmp_path):
    cfg = tmp_path / "gitleaks.toml"
    cfg.write_text(bundled_text("configs", "gitleaks", "gitleaks.toml"), encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / ".mcp.json").write_text(
        json.dumps(
            {
                "env": {
                    "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
                    "TOKEN_FILE": "~/secrets/mytoken.txt",
                    "MY_SERVICE_PAT": FAKE,
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    report = tmp_path / "report.json"
    proc = subprocess.run(
        ["gitleaks", "dir", str(src), "--config", str(cfg), "--no-banner",
         "--report-format", "json", "--report-path", str(report), "--exit-code", "0"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    found = json.loads(report.read_text(encoding="utf-8"))
    ours = [f for f in found if f["RuleID"] == SECRET]
    assert [f["Secret"] for f in ours] == [FAKE]
