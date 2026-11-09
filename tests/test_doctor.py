from types import SimpleNamespace

import pytest

from slsec import cli

from test_init import init


def run_doctor(path, capsys, ci=True):
    cli.cmd_doctor(SimpleNamespace(path=str(path), ci=ci))
    return capsys.readouterr().out


def fake_run(stdout="", rc=0):
    real = cli.subprocess.run

    def _run(cmd, *a, **k):
        if cmd[0] == "git":
            return real(cmd, *a, **k)
        return SimpleNamespace(returncode=rc, stdout=stdout, stderr="")

    return _run


def test_snyk_missing(git_repo, capsys, monkeypatch):
    init(git_repo, profile="base", sca="snyk")
    monkeypatch.setattr(cli.shutil, "which", lambda n: None)
    assert "[warn] sca=snyk but `snyk` is not on PATH" in run_doctor(git_repo, capsys)


def test_snyk_token_ok(git_repo, capsys, monkeypatch):
    init(git_repo, profile="base", sca="snyk")
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/x/snyk")
    monkeypatch.setenv("SNYK_TOKEN", "t")
    assert "snyk found and credentials" in run_doctor(git_repo, capsys)


def test_snyk_unauthenticated(git_repo, capsys, monkeypatch):
    init(git_repo, profile="base", sca="snyk")
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/x/snyk")
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    monkeypatch.setattr(cli.subprocess, "run", fake_run(""))
    assert "snyk is not authenticated" in run_doctor(git_repo, capsys)


@pytest.mark.parametrize("out,expect", [("Server ID: a", "configured server"), ("", "no JFrog server")])
def test_jfrog(git_repo, capsys, monkeypatch, out, expect):
    init(git_repo, profile="base", sca="jfrog")
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/x/jf")
    monkeypatch.setattr(cli.subprocess, "run", fake_run(out))
    assert expect in run_doctor(git_repo, capsys)


def test_jfrog_missing(git_repo, capsys, monkeypatch):
    init(git_repo, profile="base", sca="jfrog")
    monkeypatch.setattr(cli.shutil, "which", lambda n: None)
    assert "`jf`" in run_doctor(git_repo, capsys)


def test_osv_note(git_repo, capsys, monkeypatch):
    init(git_repo, profile="base", sca="osv")
    monkeypatch.setattr(cli.shutil, "which", lambda n: None)
    assert "downloads a pinned copy" in run_doctor(git_repo, capsys)


def test_sonarlint_info_for_language_profile(git_repo, capsys):
    init(git_repo, profile="python")
    (git_repo / "a.py").write_text("")
    assert "SonarQube for IDE" in run_doctor(git_repo, capsys)


def test_pre_push_hook_reported(git_repo, capsys, monkeypatch):
    init(git_repo, profile="base", sca="osv")
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/x/" + n)
    assert "pre-push hook missing" in run_doctor(git_repo, capsys, ci=False)
    (git_repo / ".git" / "hooks" / "pre-push").write_text("#!/bin/sh\n# pre-commit\n")
    assert "pre-push hook installed" in run_doctor(git_repo, capsys, ci=False)


def test_doctor_never_fails_on_provider_gaps(git_repo, monkeypatch):
    init(git_repo, profile="base", sca="snyk")
    monkeypatch.setattr(cli.shutil, "which", lambda n: None)
    assert cli.cmd_doctor(SimpleNamespace(path=str(git_repo), ci=True)) == 0
