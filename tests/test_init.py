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
        sca=kw.get("sca"),
        sast_engine=kw.get("sast_engine"),
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
    assert [h["id"] for h in slsec["hooks"]] == ["slsec-checkov", "slsec-osv"]  # deduped; osv is the default SCA
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


# ------------------------------------------------------------------ phase 2

LANGS = ["java", "node", "python", "go", "dotnet"]


def slsec_hooks(cfg):
    return repo_by_url(cfg, SOURCE)["hooks"]


@pytest.mark.parametrize("lang", LANGS)
def test_language_profile_composes(git_repo, lang):
    assert init(git_repo, profile=lang, sca="none") == 0
    assert [h["id"] for h in slsec_hooks(load(git_repo))] == ["slsec-sast"]


def test_sast_deduped_across_language_profiles(git_repo):
    init(git_repo, profile=",".join(LANGS + ["docker"]))
    ids = [h["id"] for h in slsec_hooks(load(git_repo))]
    assert ids.count("slsec-sast") == 1
    assert ids.count("slsec-checkov") == 1


def test_detect_languages(git_repo):
    (git_repo / "pom.xml").write_text("")
    (git_repo / "web").mkdir()
    (git_repo / "web" / "package.json").write_text("{}")
    (git_repo / "requirements-dev.txt").write_text("")
    (git_repo / "go.mod").write_text("")
    (git_repo / "App.csproj").write_text("")
    assert cli.detect_profiles(git_repo) == ["base", "java", "node", "python", "go", "dotnet"]


@pytest.mark.parametrize("d", ["node_modules", "target", "bin", "obj", ".gradle", "__pycache__", "venv"])
def test_detect_skips_build_dirs(git_repo, d):
    (git_repo / d / "x").mkdir(parents=True)
    for f in ("package.json", "a.java", "b.py", "c.cs", "go.mod"):
        (git_repo / d / "x" / f).write_text("")
    assert cli.detect_profiles(git_repo) == ["base"]


def test_sca_adds_hook_and_install_types(git_repo):
    init(git_repo, profile="python", sca="snyk")
    cfg = load(git_repo)
    assert [h["id"] for h in slsec_hooks(cfg)] == ["slsec-sast", "slsec-snyk"]
    assert cfg["default_install_hook_types"] == ["pre-commit", "pre-push"]
    assert yaml.safe_load((git_repo / ".slsec.yaml").read_text())["providers"]["sca"] == "snyk"


def test_fresh_init_defaults_to_osv(git_repo, capsys):
    assert init(git_repo, profile="python") == 0
    assert "Dependency scan: osv-scanner on pre-push" in capsys.readouterr().out
    cfg = load(git_repo)
    assert [h["id"] for h in slsec_hooks(cfg)] == ["slsec-sast", "slsec-osv"]
    assert cfg["default_install_hook_types"] == ["pre-commit", "pre-push"]
    providers = yaml.safe_load((git_repo / ".slsec.yaml").read_text())["providers"]
    assert providers == {"sast_engine": "opengrep", "sca": "osv"}
    assert cli.cmd_doctor(SimpleNamespace(path=str(git_repo), ci=True)) == 0


def test_no_sca_means_no_pre_push_types(git_repo, capsys):
    init(git_repo, profile="python", sca="none")
    assert "Dependency scan" not in capsys.readouterr().out
    cfg = load(git_repo)
    assert "default_install_hook_types" not in cfg
    assert "slsec-osv" not in [h["id"] for h in slsec_hooks(cfg)]
    assert yaml.safe_load((git_repo / ".slsec.yaml").read_text())["providers"]["sca"] == "none"
    init(git_repo, profile="python")  # the recorded `none` sticks on a re-run
    assert "default_install_hook_types" not in load(git_repo)


@pytest.mark.parametrize("update", [False, True])
def test_reinit_keeps_providers_from_slsec_yaml(git_repo, capsys, update):
    init(git_repo, profile="python", sca="snyk", sast_engine="semgrep")
    init(git_repo, profile=None if update else "python", update=update)
    hooks = slsec_hooks(load(git_repo))
    assert [h["id"] for h in hooks] == ["slsec-sast", "slsec-snyk"]
    assert hooks[0]["additional_dependencies"] == [cli.SEMGREP_DEPENDENCY]
    providers = yaml.safe_load((git_repo / ".slsec.yaml").read_text())["providers"]
    assert providers == {"sast_engine": "semgrep", "sca": "snyk"}
    capsys.readouterr()
    assert cli.cmd_doctor(SimpleNamespace(path=str(git_repo), ci=True)) == 0, capsys.readouterr().out


@pytest.mark.parametrize("update", [False, True])
@pytest.mark.parametrize(
    "settings, sast_engine",
    [("mode: warn\nprofiles: [python]\n", "opengrep"), ("profiles: [python]\nproviders:\n  sast_engine: semgrep\n", "semgrep")],
)
def test_existing_slsec_yaml_without_sca_stays_none(git_repo, update, settings, sast_engine):
    (git_repo / ".slsec.yaml").write_text(settings)
    assert init(git_repo, profile=None if update else "python", update=update) == 0
    cfg = load(git_repo)
    assert "default_install_hook_types" not in cfg
    hooks = slsec_hooks(cfg)
    assert [h["id"] for h in hooks] == ["slsec-sast"]
    assert ("additional_dependencies" in hooks[0]) is (sast_engine == "semgrep")
    assert (git_repo / ".slsec.yaml").read_text() == settings


def test_update_reads_and_switches_sca(git_repo):
    init(git_repo, profile="python", sca="osv")
    cfg = load(git_repo)
    cfg["repos"].append({"repo": "https://github.com/psf/black", "rev": "24.1.0", "hooks": [{"id": "black"}]})
    slsec_hooks(cfg).append({"id": "my-own-hook"})
    (git_repo / ".pre-commit-config.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False))
    init(git_repo, update=True)  # reads sca from .slsec.yaml
    assert "slsec-osv" in [h["id"] for h in slsec_hooks(load(git_repo))]
    init(git_repo, update=True, sca="jfrog")
    cfg = load(git_repo)
    ids = [h["id"] for h in slsec_hooks(cfg)]
    assert "slsec-jfrog" in ids and "slsec-osv" not in ids and "my-own-hook" in ids
    assert repo_by_url(cfg, "https://github.com/psf/black")
    assert yaml.safe_load((git_repo / ".slsec.yaml").read_text())["providers"]["sca"] == "jfrog"
    init(git_repo, update=True)
    assert "slsec-jfrog" in [h["id"] for h in slsec_hooks(load(git_repo))]


def test_sast_engine_semgrep_adds_dependency(git_repo):
    init(git_repo, profile="python", sast_engine="semgrep")
    assert slsec_hooks(load(git_repo))[0]["additional_dependencies"] == [cli.SEMGREP_DEPENDENCY]
    assert yaml.safe_load((git_repo / ".slsec.yaml").read_text())["providers"]["sast_engine"] == "semgrep"
    init(git_repo, update=True)
    assert "additional_dependencies" in slsec_hooks(load(git_repo))[0]
    init(git_repo, update=True, sast_engine="opengrep")
    assert "additional_dependencies" not in slsec_hooks(load(git_repo))[0]


def test_sast_engine_none_keeps_hook(git_repo):
    init(git_repo, profile="python", sast_engine="none")
    assert slsec_hooks(load(git_repo))[0]["id"] == "slsec-sast"
    assert yaml.safe_load((git_repo / ".slsec.yaml").read_text())["providers"]["sast_engine"] == "none"


@pytest.mark.parametrize(
    "version, profile, expected",
    [((3, 15, 0), "terraform", True), ((3, 15, 0), "java", False), ((3, 14, 0), "docker", False)],
)
def test_init_notes_checkov_on_python_315(git_repo, capsys, monkeypatch, version, profile, expected):
    monkeypatch.setattr(cli.sys, "version_info", version)
    assert init(git_repo, profile=profile) == 0
    assert ("doesn't install on Python 3.15" in capsys.readouterr().out) is expected
