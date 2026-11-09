from types import SimpleNamespace

import pytest
import yaml

from slsec import __version__, cli

SOURCE = "https://git.example.invalid/security/slsec"


def init(path, **kw):
    args = SimpleNamespace(
        path=str(path),
        profile=kw.get("profile"),
        mode=kw.get("mode", "warn"),
        sca=kw.get("sca", "none"),
        update=kw.get("update", False),
        force=kw.get("force", False),
        no_install=True,
        source_url=SOURCE,
        rev=kw.get("rev"),
    )
    return cli.cmd_init(args)


def load(path):
    return yaml.safe_load((path / ".pre-commit-config.yaml").read_text())


def repo_by_url(cfg, url):
    return next(r for r in cfg["repos"] if r["repo"] == url)


def test_profiles_share_consistent_pins():
    """The same upstream repo must have the same rev in every profile."""
    revs = {}
    for name in cli.PROFILES:
        for repo in cli.load_profile(name).get("repos", []):
            url = repo["repo"]
            if url in ("local", cli.SLSEC_PLACEHOLDER):
                continue
            assert "rev" in repo, f"{name}: {url} missing rev"
            assert revs.setdefault(url, repo["rev"]) == repo["rev"], f"inconsistent rev for {url}"


def test_detect_profiles(git_repo):
    (git_repo / "infra").mkdir()
    (git_repo / "infra" / "main.tf").write_text("")
    (git_repo / "Dockerfile").write_text("FROM scratch\n")
    (git_repo / ".github" / "workflows").mkdir(parents=True)
    (git_repo / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    (git_repo / "Jenkinsfile").write_text("pipeline {}\n")
    (git_repo / "node_modules" / "x").mkdir(parents=True)
    assert cli.detect_profiles(git_repo) == ["base", "terraform", "docker", "github-actions", "jenkins"]


def test_detect_ignores_vendored_terraform(git_repo):
    (git_repo / ".terraform" / "modules").mkdir(parents=True)
    (git_repo / ".terraform" / "modules" / "main.tf").write_text("")
    assert cli.detect_profiles(git_repo) == ["base"]


def test_init_writes_config_and_files(git_repo):
    assert init(git_repo, profile="terraform,docker") == 0
    cfg = load(git_repo)
    assert cfg["default_stages"] == ["pre-commit"]
    slsec = repo_by_url(cfg, SOURCE)
    assert slsec["rev"] == f"v{__version__}"
    assert [h["id"] for h in slsec["hooks"]] == ["slsec-checkov"]  # deduped across profiles
    urls = [r["repo"] for r in cfg["repos"]]
    assert "https://github.com/gitleaks/gitleaks" in urls
    assert "https://github.com/AleksaC/hadolint-py" in urls
    for f in (".gitleaks.toml", ".tflint.hcl", ".hadolint.yaml", ".slsec.yaml"):
        assert (git_repo / f).exists(), f
    assert not (git_repo / "zizmor.yml").exists()
    settings = yaml.safe_load((git_repo / ".slsec.yaml").read_text())
    assert settings["mode"] == "warn"
    assert settings["profiles"] == ["base", "terraform", "docker"]


def test_init_preserves_existing_hooks_and_updates_pins(git_repo):
    (git_repo / ".pre-commit-config.yaml").write_text(
        yaml.safe_dump(
            {
                "repos": [
                    {"repo": "https://github.com/psf/black", "rev": "24.1.0", "hooks": [{"id": "black"}]},
                    {"repo": "https://github.com/gitleaks/gitleaks", "rev": "v8.0.0", "hooks": [{"id": "gitleaks"}]},
                ]
            }
        )
    )
    assert init(git_repo, profile="base") == 0
    cfg = load(git_repo)
    assert repo_by_url(cfg, "https://github.com/psf/black")["rev"] == "24.1.0"
    gitleaks = repo_by_url(cfg, "https://github.com/gitleaks/gitleaks")
    assert gitleaks["rev"] != "v8.0.0"
    assert [h["id"] for h in gitleaks["hooks"]] == ["gitleaks"]
    assert (git_repo / ".pre-commit-config.yaml.bak").exists()


def test_init_keeps_local_tool_config_unless_forced(git_repo):
    (git_repo / ".gitleaks.toml").write_text("# my rules\n")
    init(git_repo, profile="base")
    assert (git_repo / ".gitleaks.toml").read_text() == "# my rules\n"
    init(git_repo, profile="base", force=True)
    assert "useDefault = true" in (git_repo / ".gitleaks.toml").read_text()
    assert (git_repo / ".gitleaks.toml.bak").read_text() == "# my rules\n"


def test_update_uses_recorded_profiles(git_repo):
    init(git_repo, profile="docker", rev="v0.0.1")
    assert repo_by_url(load(git_repo), SOURCE)["rev"] == "v0.0.1"
    init(git_repo, update=True)
    cfg = load(git_repo)
    assert repo_by_url(cfg, SOURCE)["rev"] == f"v{__version__}"
    assert "https://github.com/AleksaC/hadolint-py" in [r["repo"] for r in cfg["repos"]]


def test_update_refreshes_local_pin_but_keeps_customisation(git_repo):
    init(git_repo, profile="terraform")
    cfg = load(git_repo)
    local = repo_by_url(cfg, "local")
    tflint = next(h for h in local["hooks"] if h["id"] == "tflint")
    tflint["additional_dependencies"] = ["github.com/terraform-linters/tflint@v0.1.0"]
    tflint["args"] = ["--format=compact"]
    (git_repo / ".pre-commit-config.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False))
    init(git_repo, update=True)
    tflint = next(h for h in repo_by_url(load(git_repo), "local")["hooks"] if h["id"] == "tflint")
    assert tflint["additional_dependencies"] != ["github.com/terraform-linters/tflint@v0.1.0"]
    assert tflint["args"] == ["--format=compact"]


def test_init_is_idempotent(git_repo):
    init(git_repo, profile="terraform,github-actions,jenkins")
    first = (git_repo / ".pre-commit-config.yaml").read_text()
    init(git_repo, update=True)
    assert (git_repo / ".pre-commit-config.yaml").read_text() == first
    assert not (git_repo / ".pre-commit-config.yaml.bak").exists()


def test_unknown_profile(git_repo):
    assert init(git_repo, profile="cobol") == 2


def test_not_a_git_repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert init(tmp_path, profile="base") == 2


def test_doctor_ci_mode(git_repo, capsys):
    init(git_repo, profile="terraform")
    rc = cli.cmd_doctor(SimpleNamespace(path=str(git_repo), ci=True))
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "gitleaks" in out


def test_doctor_flags_missing_config(git_repo, capsys):
    assert cli.cmd_doctor(SimpleNamespace(path=str(git_repo), ci=True)) == 1


@pytest.mark.parametrize("rev,expected", [("v0.0.9", "warn"), (f"v{__version__}", "ok")])
def test_doctor_rev_drift(git_repo, capsys, rev, expected):
    init(git_repo, profile="terraform", rev=rev)
    cli.cmd_doctor(SimpleNamespace(path=str(git_repo), ci=True))
    out = capsys.readouterr().out
    line = next(l for l in out.splitlines() if "slsec" in l and "pinned" in l)
    assert f"[{expected}" in line
