import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures"


@pytest.fixture
def git_repo(tmp_path: Path, monkeypatch) -> Path:
    """An empty git repo as the current directory."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "slsec test"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "commit.gpgsign", "false"], check=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SLSEC_MODE", raising=False)
    monkeypatch.delenv("SLSEC_STRICT", raising=False)
    monkeypatch.delenv("SLSEC_REPORT_DIR", raising=False)
    return tmp_path


def checkov_available() -> bool:
    try:
        import checkov  # noqa: F401
    except ImportError:
        return False
    return True
