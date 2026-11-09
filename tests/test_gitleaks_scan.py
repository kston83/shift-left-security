"""resources/slsec/gitleaks-scan.sh (the Jenkins full-history scan) only trusts a gitleaks on
PATH that reports the pinned version; anything else falls through to the verified download."""

import os
import shutil
import stat
import subprocess

import pytest

from conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "resources" / "slsec" / "gitleaks-scan.sh"

pytestmark = pytest.mark.skipif(not shutil.which("sh"), reason="needs a POSIX sh (Git Bash on Windows)")


def _fake_gitleaks(bin_dir, version):
    """A `gitleaks` that prints `version` and records that it was asked to scan."""
    path = bin_dir / "gitleaks"
    path.write_text(
        "#!/bin/sh\n"
        f'if [ "$1" = version ]; then echo "{version}"; exit 0; fi\n'
        'echo scanned > "$SLSEC_REPORT_DIR/fake-ran"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _run(tmp_path, version_on_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _fake_gitleaks(bin_dir, version_on_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    env = dict(
        os.environ,
        PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        SLSEC_GITLEAKS_VERSION="8.30.1",
        # nothing listens here: a download attempt fails fast instead of reaching GitHub
        SLSEC_GITLEAKS_BASE_URL="http://127.0.0.1:9/nope",
        SLSEC_REPORT_DIR=str(reports),
    )
    proc = subprocess.run(["sh", str(SCRIPT)], cwd=repo, env=env, capture_output=True, text=True, timeout=60)
    return proc, (reports / "fake-ran").exists()


@pytest.mark.parametrize("reported", ["8.30.1", "v8.30.1"])
def test_pinned_gitleaks_on_path_is_used(tmp_path, reported):
    proc, ran = _run(tmp_path, reported)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert ran


def test_other_gitleaks_on_path_is_not_trusted(tmp_path):
    proc, ran = _run(tmp_path, "8.0.0")
    assert not ran
    assert "reports version '8.0.0', not the pinned 8.30.1" in proc.stdout
    assert proc.returncode == 3  # the verified download was attempted (and can't reach the test URL)
