"""Load the shared slsec policy and merge it with a repo's local `.slsec.yaml`.

The policy that ships in this package is the baseline. A consuming repo can add
to it in `.slsec.yaml`, but every exception has to carry a reason, and it can
also carry an expiry date. Once an exception expires it stops applying, so the
check runs again.
"""

from __future__ import annotations

import datetime as _dt
import os
import subprocess
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Mapping, Optional

import yaml

CONFIG_FILENAMES = (".slsec.yaml", ".slsec.yml")
MODES = ("warn", "block")
SCA_PROVIDERS = ("osv", "snyk", "jfrog", "none")
SAST_ENGINES = ("opengrep", "semgrep", "none")


class ConfigError(ValueError):
    """Raised when `.slsec.yaml` or the bundled policy is invalid."""


@dataclass(frozen=True)
class Suppression:
    id: str
    reason: str
    expires: Optional[_dt.date] = None
    source: str = "repo"  # "baseline" or "repo"

    def is_expired(self, today: Optional[_dt.date] = None) -> bool:
        return self.expires is not None and self.expires < (today or _dt.date.today())


@dataclass
class Config:
    root: Path
    source: Optional[Path]
    mode: str = "warn"
    strict: bool = False
    profiles: list = field(default_factory=list)
    sast_engine: str = "opengrep"
    sca: str = "none"
    checkov_skips: list = field(default_factory=list)  # active Suppressions
    checkov_expired: list = field(default_factory=list)  # expired Suppressions
    checkov_extra_args: list = field(default_factory=list)

    @property
    def blocking(self) -> bool:
        return self.mode == "block"


def bundled_path(*parts: str) -> Path:
    """Path to a file bundled under `slsec/configs` or `slsec/templates`."""
    ref = resources.files("slsec").joinpath(*parts)
    return Path(str(ref))


def bundled_text(*parts: str) -> str:
    return resources.files("slsec").joinpath(*parts).read_text(encoding="utf-8")


def find_repo_root(start: Optional[Path] = None) -> Path:
    start = Path(start or Path.cwd())
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if out:
            return Path(out)
    except (OSError, subprocess.CalledProcessError):
        pass
    return start


def _parse_date(value: Any, where: str) -> Optional[_dt.date]:
    if value is None or value == "":
        return None
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    try:
        return _dt.date.fromisoformat(str(value))
    except ValueError as exc:
        raise ConfigError(f"{where}: 'expires' must be YYYY-MM-DD, got {value!r}") from exc


def _parse_suppressions(items: Any, where: str, source: str) -> list:
    if items is None:
        return []
    if not isinstance(items, list):
        raise ConfigError(f"{where} must be a list")
    result = []
    for i, item in enumerate(items):
        loc = f"{where}[{i}]"
        if not isinstance(item, Mapping):
            raise ConfigError(
                f"{loc}: each exception needs an id and a reason, for example "
                f"{{id: CKV_AWS_18, reason: 'logging handled centrally'}}"
            )
        check_id = str(item.get("id") or "").strip()
        reason = str(item.get("reason") or "").strip()
        if not check_id:
            raise ConfigError(f"{loc}: missing 'id'")
        if not reason:
            raise ConfigError(f"{loc} ({check_id}): missing 'reason'; every exception must be justified")
        result.append(
            Suppression(
                id=check_id,
                reason=reason,
                expires=_parse_date(item.get("expires"), loc),
                source=source,
            )
        )
    return result


def _choice(value: Any, allowed: tuple, where: str) -> str:
    value = str(value).strip().lower()
    if value not in allowed:
        raise ConfigError(f"{where} must be one of {', '.join(allowed)}; got {value!r}")
    return value


def load_baseline() -> dict:
    data = yaml.safe_load(bundled_text("configs", "checkov", "baseline.yaml")) or {}
    if not isinstance(data, Mapping):
        raise ConfigError("bundled checkov baseline is malformed")
    return dict(data)


def load_repo_file(root: Path) -> tuple:
    for name in CONFIG_FILENAMES:
        path = root / name
        if path.is_file():
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
            if not isinstance(data, Mapping):
                raise ConfigError(f"{path}: top level must be a mapping")
            return path, dict(data)
    return None, {}


def load_config(
    root: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
    today: Optional[_dt.date] = None,
) -> Config:
    env = os.environ if env is None else env
    root = Path(root) if root else find_repo_root()
    source, data = load_repo_file(root)
    where = source.name if source else ".slsec.yaml"

    mode = _choice(env.get("SLSEC_MODE") or data.get("mode", "warn"), MODES, f"{where}: mode")
    providers = data.get("providers") or {}
    if not isinstance(providers, Mapping):
        raise ConfigError(f"{where}: providers must be a mapping")

    baseline = load_baseline()
    checkov_repo = data.get("checkov") or {}
    if not isinstance(checkov_repo, Mapping):
        raise ConfigError(f"{where}: checkov must be a mapping")

    enable = {str(x).strip() for x in (checkov_repo.get("enable_checks") or [])}
    skips = [
        s
        for s in _parse_suppressions(baseline.get("skip_checks"), "baseline skip_checks", "baseline")
        if s.id not in enable
    ]
    skips += _parse_suppressions(checkov_repo.get("skip_checks"), f"{where}: checkov.skip_checks", "repo")

    active, expired, seen = [], [], set()
    for s in skips:
        if s.is_expired(today):
            expired.append(s)
        elif s.id not in seen:
            seen.add(s.id)
            active.append(s)

    profiles = data.get("profiles") or []
    if not isinstance(profiles, list):
        raise ConfigError(f"{where}: profiles must be a list")

    return Config(
        root=root,
        source=source,
        mode=mode,
        strict=bool(data.get("strict", False)),
        profiles=[str(p) for p in profiles],
        sast_engine=_choice(providers.get("sast_engine", "opengrep"), SAST_ENGINES, f"{where}: providers.sast_engine"),
        sca=_choice(providers.get("sca", "none"), SCA_PROVIDERS, f"{where}: providers.sca"),
        checkov_skips=active,
        checkov_expired=expired,
        checkov_extra_args=[str(a) for a in (baseline.get("extra_args") or [])],
    )
