import datetime as dt

import pytest

from slsec.config import ConfigError, load_config

TODAY = dt.date(2026, 11, 8)


def write(root, text):
    (root / ".slsec.yaml").write_text(text, encoding="utf-8")


def test_defaults_without_repo_file(tmp_path):
    cfg = load_config(tmp_path, env={})
    assert cfg.mode == "warn"
    assert not cfg.blocking
    assert cfg.source is None
    ids = {s.id for s in cfg.checkov_skips}
    assert "CKV_DOCKER_2" in ids  # from the bundled baseline
    assert all(s.source == "baseline" for s in cfg.checkov_skips)


def test_repo_file_adds_exceptions_and_mode(tmp_path):
    write(
        tmp_path,
        """
mode: block
checkov:
  skip_checks:
    - id: CKV_AWS_18
      reason: central logging
""",
    )
    cfg = load_config(tmp_path, env={}, today=TODAY)
    assert cfg.blocking
    assert "CKV_AWS_18" in {s.id for s in cfg.checkov_skips}


def test_env_overrides_mode(tmp_path):
    write(tmp_path, "mode: warn\n")
    assert load_config(tmp_path, env={"SLSEC_MODE": "block"}).mode == "block"


def test_enable_checks_removes_baseline_skip(tmp_path):
    write(tmp_path, "checkov:\n  enable_checks: [CKV_DOCKER_2]\n")
    cfg = load_config(tmp_path, env={})
    assert "CKV_DOCKER_2" not in {s.id for s in cfg.checkov_skips}


def test_exception_requires_reason(tmp_path):
    write(tmp_path, "checkov:\n  skip_checks:\n    - id: CKV_AWS_18\n")
    with pytest.raises(ConfigError, match="reason"):
        load_config(tmp_path, env={})


def test_bare_string_exception_rejected(tmp_path):
    write(tmp_path, "checkov:\n  skip_checks: [CKV_AWS_18]\n")
    with pytest.raises(ConfigError, match="id and a reason"):
        load_config(tmp_path, env={})


def test_expired_exception_is_not_applied(tmp_path):
    write(
        tmp_path,
        """
checkov:
  skip_checks:
    - id: CKV_AWS_18
      reason: temporary
      expires: 2026-01-31
    - id: CKV_AWS_21
      reason: still valid
      expires: 2027-01-31
""",
    )
    cfg = load_config(tmp_path, env={}, today=TODAY)
    active = {s.id for s in cfg.checkov_skips}
    assert "CKV_AWS_18" not in active
    assert "CKV_AWS_21" in active
    assert [s.id for s in cfg.checkov_expired] == ["CKV_AWS_18"]


def test_bad_expiry_format(tmp_path):
    write(tmp_path, "checkov:\n  skip_checks:\n    - {id: X, reason: y, expires: 'next week'}\n")
    with pytest.raises(ConfigError, match="YYYY-MM-DD"):
        load_config(tmp_path, env={})


@pytest.mark.parametrize("text", ["mode: maybe\n", "providers:\n  sca: blackduck\n", "- not a mapping\n"])
def test_invalid_values(tmp_path, text):
    write(tmp_path, text)
    with pytest.raises(ConfigError):
        load_config(tmp_path, env={})


@pytest.mark.parametrize(
    "file_text,env,expected",
    [
        ("", {}, False),
        ("strict: true\n", {}, True),
        ("", {"SLSEC_STRICT": "1"}, True),  # CI templates set this
        ("", {"SLSEC_STRICT": "true"}, True),
        ("strict: true\n", {"SLSEC_STRICT": "0"}, False),  # env wins in both directions
        ("strict: true\n", {"SLSEC_STRICT": ""}, True),  # empty = unset
    ],
)
def test_strict_from_file_and_env(tmp_path, file_text, env, expected):
    write(tmp_path, file_text)
    assert load_config(tmp_path, env=env).strict is expected


def test_strict_rejects_bad_values(tmp_path):
    with pytest.raises(ConfigError, match="SLSEC_STRICT"):
        load_config(tmp_path, env={"SLSEC_STRICT": "maybe"})
    write(tmp_path, 'strict: "false"\n')  # a quoted string must not be read as truthy
    with pytest.raises(ConfigError, match="strict must be true or false"):
        load_config(tmp_path, env={})
