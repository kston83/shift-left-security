"""`slsec init --update` pin handling and the `slsec doctor --ci` setup gate."""

import re
from types import SimpleNamespace

import pytest
import yaml

from conftest import REPO_ROOT
from slsec import __version__, cli

from test_init import SOURCE, init, load, repo_by_url

GITLEAKS = "https://github.com/gitleaks/gitleaks"


def pcc(repo):
    return repo / ".pre-commit-config.yaml"


# ------------------------------------------------------------------ versions


@pytest.mark.parametrize(
    "new,cur,expected",
    [
        ("v8.31.0", "v8.30.1", True),
        ("v8.30.1", "v8.31.0", False),
        ("v8.30.1", "v8.30.1", False),
        ("v1.10.0", "v1.9.9", True),
        ("v1.2.3", "v1.2.3-rc1", True),
        ("v1.2", "v1.2.0", False),
        ("v9.0.0", "0123456789abcdef0123456789abcdef01234567", False),  # unknown current: keep it
        ("v8.30.1", "3d3c42e5aac5d1f0e3b8c9a7d6e5f4a3b2c1d0e9", False),  # a SHA starting with digits
        ("v8.30.1", "3d3c42e", False),  # an abbreviated SHA
        ("main", "v1.0.0", False),
    ],
)
def test_is_newer(new, cur, expected):
    assert cli.is_newer(new, cur) is expected


def test_bump_dependencies_never_downgrades():
    cur = ["github.com/terraform-linters/tflint@v0.70.0", "extra==1.0"]
    assert cli.bump_dependencies(cur, ["github.com/terraform-linters/tflint@v0.66.0"]) == cur
    assert cli.bump_dependencies(cur, ["github.com/terraform-linters/tflint@v0.71.0"])[0].endswith("@v0.71.0")
    assert cli.bump_dependencies(["npm-groovy-lint@19.0.1"], ["npm-groovy-lint@19.1.0", "new@1"]) == [
        "npm-groovy-lint@19.1.0",
        "new@1",
    ]


# ------------------------------------------------------------------ init --update


def test_update_keeps_newer_pin_and_comments(git_repo):
    """The review case: Renovate bumped gitleaks past slsec's pin, and the team commented the file."""
    init(git_repo, profile="terraform")
    text = pcc(git_repo).read_text()
    gl_rev = repo_by_url(load(git_repo), GITLEAKS)["rev"]
    text = text.replace(f"rev: {gl_rev}", "rev: v99.0.0  # bumped by Renovate")
    text = text.replace("repos:\n", "repos:\n# team: black first, see CONTRIBUTING\n"
                        "- repo: https://github.com/psf/black\n  rev: 24.1.0  # py3.8 compat\n"
                        "  hooks:\n  - id: black\n", 1)
    pcc(git_repo).write_text(text)
    init(git_repo, update=True)
    after = pcc(git_repo).read_text()
    assert "rev: v99.0.0  # bumped by Renovate" in after
    assert "# team: black first, see CONTRIBUTING" in after
    assert "rev: 24.1.0  # py3.8 compat" in after
    assert after == text  # nothing to change, nothing rewritten
    assert not (git_repo / ".pre-commit-config.yaml.bak").exists()


def test_update_keeps_newer_local_tool_pin(git_repo):
    init(git_repo, profile="terraform")
    text = pcc(git_repo).read_text()
    text = re.sub(r"tflint@v[0-9.]+", "tflint@v99.0.0", text)
    pcc(git_repo).write_text(text)
    init(git_repo, update=True)
    assert "tflint@v99.0.0" in pcc(git_repo).read_text()


def test_update_upgrades_an_older_pin_in_place(git_repo):
    init(git_repo, profile="base")
    text = pcc(git_repo).read_text()
    gl_rev = repo_by_url(load(git_repo), GITLEAKS)["rev"]
    pcc(git_repo).write_text(text.replace(f"rev: {gl_rev}", "rev: v8.0.0  # old"))
    init(git_repo, update=True)
    assert repo_by_url(load(git_repo), GITLEAKS)["rev"] == gl_rev
    assert "# old" in pcc(git_repo).read_text()  # the comment stays with the key


def test_explicit_rev_can_go_backwards(git_repo):
    init(git_repo, profile="docker")
    init(git_repo, update=True, rev="v0.0.1")
    assert repo_by_url(load(git_repo), SOURCE)["rev"] == "v0.0.1"


def test_update_keeps_indentation_style(git_repo):
    init(git_repo, profile="base")
    # a team that reformatted with indented sequences (prettier style)
    config, _ = cli.load_config_text(pcc(git_repo).read_text())
    styled_dumper = cli._yaml(indent=4, block_seq_indent=2)
    pcc(git_repo).write_text(cli.dump_config(config, SOURCE, styled_dumper))
    styled = pcc(git_repo).read_text()
    init(git_repo, update=True, profile="base,docker")
    out = pcc(git_repo).read_text()
    assert "\n  - repo: https://github.com/pre-commit/pre-commit-hooks" in styled
    assert "\n  - repo: https://github.com/pre-commit/pre-commit-hooks" in out
    assert "hadolint" in out


@pytest.mark.parametrize("rev", ["3d3c42e5aac5d1f0e3b8c9a7d6e5f4a3b2c1d0e9", "1234abc", "deadbeef"])
def test_shas_are_not_versions(rev):
    assert cli.parse_version(rev) is None


def test_numeric_versions_still_parse():
    assert cli.parse_version("20240101") == (20240101, 0, 0, 0, 1)
    assert cli.parse_version("24.1.0") == (24, 1, 0, 0, 1)


def test_frozen_sha_is_compared_by_its_tag(git_repo, monkeypatch):
    monkeypatch.setattr(cli, "resolve_tag", lambda url, tag: "b" * 40)
    init(git_repo, profile="base")
    text = pcc(git_repo).read_text()
    gl_rev = repo_by_url(load(git_repo), GITLEAKS)["rev"]
    sha = "a" * 40
    pcc(git_repo).write_text(text.replace(f"rev: {gl_rev}", f"rev: {sha}  # frozen: v99.0.0"))
    init(git_repo, update=True)
    assert f"rev: {sha}  # frozen: v99.0.0" in pcc(git_repo).read_text()
    # an older frozen tag is upgraded to slsec's tag, and stays frozen (to the new tag's commit)
    pcc(git_repo).write_text(text.replace(f"rev: {gl_rev}", f"rev: {sha}  # frozen: v8.0.0"))
    init(git_repo, update=True)
    out = pcc(git_repo).read_text()
    assert f"rev: {'b' * 40}  # frozen: {gl_rev}" in out and "frozen: v8.0.0" not in out


def test_frozen_pin_falls_back_to_tag_with_a_warning_when_offline(git_repo, monkeypatch, capsys):
    monkeypatch.setattr(cli, "resolve_tag", lambda url, tag: None)
    init(git_repo, profile="base")
    text = pcc(git_repo).read_text()
    gl_rev = repo_by_url(load(git_repo), GITLEAKS)["rev"]
    pcc(git_repo).write_text(text.replace(f"rev: {gl_rev}", f"rev: {'a' * 40}  # frozen: v8.0.0"))
    capsys.readouterr()
    init(git_repo, update=True)
    assert repo_by_url(load(git_repo), GITLEAKS)["rev"] == gl_rev
    assert f"{GITLEAKS} was pinned to a commit" in capsys.readouterr().out


def test_unfrozen_repos_are_not_frozen_by_update(git_repo, monkeypatch):
    monkeypatch.setattr(cli, "resolve_tag", lambda url, tag: pytest.fail("no network lookups without --freeze"))
    init(git_repo, profile="base")
    text = pcc(git_repo).read_text()
    gl_rev = repo_by_url(load(git_repo), GITLEAKS)["rev"]
    pcc(git_repo).write_text(text.replace(f"rev: {gl_rev}", "rev: v8.0.0"))
    init(git_repo, update=True)
    assert repo_by_url(load(git_repo), GITLEAKS)["rev"] == gl_rev


@pytest.mark.parametrize(
    "pinned,expected",
    [
        ("semgrep>=1.90,<2", cli.SEMGREP_DEPENDENCY),  # older: raised to slsec's
        ("semgrep>=9.0,<10", "semgrep>=9.0,<10"),  # newer: the team's pin stays
        ("semgrep==1.150.0", "semgrep==1.150.0"),
    ],
)
def test_update_moves_the_semgrep_pin_forward_only(git_repo, pinned, expected):
    init(git_repo, profile="python", sast_engine="semgrep")
    text = pcc(git_repo).read_text().replace(cli.SEMGREP_DEPENDENCY, pinned)
    pcc(git_repo).write_text(text)
    init(git_repo, update=True)
    hooks = [h for r in load(git_repo)["repos"] for h in r["hooks"] if h["id"] == "slsec-sast"]
    assert hooks[0]["additional_dependencies"] == [expected]


def test_freeze_revs(git_repo):
    init(git_repo, profile="terraform")
    config, dumper = cli.load_config_text(pcc(git_repo).read_text())
    shas = {}

    def fake_resolve(url, tag):
        if "gitleaks" in url:
            return None  # e.g. offline
        return shas.setdefault(url, f"abc{len(shas):037x}")

    failed = cli.freeze_revs(config, resolve=fake_resolve)
    out = cli.dump_config(config, SOURCE, dumper)
    assert failed == [f"{GITLEAKS}@{repo_by_url(load(git_repo), GITLEAKS)['rev']}"]
    for url, sha in shas.items():
        tag = repo_by_url(load(git_repo), url)["rev"]
        assert f"rev: {sha}  # frozen: {tag}" in out
    reloaded, _ = cli.load_config_text(out)
    assert cli.current_version(repo_by_url(reloaded, SOURCE)) == f"v{__version__}"


# ------------------------------------------------------------------ doctor --ci


def doctor(path, capsys, **kw):
    args = SimpleNamespace(path=str(path), ci=kw.pop("ci", True), require_mode=kw.pop("require_mode", None),
                           require_profiles=kw.pop("require_profiles", None))
    rc = cli.cmd_doctor(args)
    return rc, capsys.readouterr().out


def edit_config(repo, fn):
    data = yaml.safe_load(pcc(repo).read_text())
    fn(data)
    pcc(repo).write_text(yaml.safe_dump(data, sort_keys=False))


def find_hook(data, hook_id):
    return next(h for r in data["repos"] for h in r.get("hooks", []) if h["id"] == hook_id)


def test_clean_setup_passes(git_repo, capsys):
    init(git_repo, profile="terraform,python")
    rc, out = doctor(git_repo, capsys)
    assert rc == 0, out


def test_deleted_required_hook_fails(git_repo, capsys):
    init(git_repo, profile="terraform")

    def drop(data):
        for r in data["repos"]:
            r["hooks"] = [h for h in r["hooks"] if h["id"] != "slsec-checkov"]
        data["repos"] = [r for r in data["repos"] if r["hooks"]]

    edit_config(git_repo, drop)
    rc, out = doctor(git_repo, capsys)
    assert rc == 1
    assert "[FAIL] required hook slsec-checkov (terraform profile) is missing" in out


def test_deleted_gitleaks_fails(git_repo, capsys):
    init(git_repo, profile="base")
    edit_config(git_repo, lambda d: d.update(repos=[r for r in d["repos"] if "gitleaks" not in r["repo"]]))
    rc, out = doctor(git_repo, capsys)
    assert rc == 1 and "required hook gitleaks" in out


@pytest.mark.parametrize(
    "hook_id,change,expect",
    [
        ("slsec-checkov", {"stages": ["manual"]}, "manual-only"),
        ("slsec-checkov", {"stages": ["post-merge"]}, "keeps it out of the pre-commit stage"),
        ("slsec-checkov", {"args": ["--mode", "warn"]}, "--mode warn"),
        ("slsec-checkov", {"entry": "true"}, "overrides the hook's command"),
        ("gitleaks", {"language": "fail"}, "language: fail"),
        ("detect-private-key", {"stages": ["commit-msg"]}, "keeps it out"),
        ("slsec-checkov", {"pass_filenames": False}, "pass_filenames: false"),
        ("detect-private-key", {"pass_filenames": False}, "pass_filenames: false"),
        ("gitleaks", {"args": ["--exit-code", "0"]}, "--exit-code 0"),
        ("gitleaks", {"args": ["--exit-code=0"]}, "--exit-code 0"),
    ],
)
def test_neutered_required_hook_fails(git_repo, capsys, hook_id, change, expect):
    init(git_repo, profile="terraform")
    edit_config(git_repo, lambda d: find_hook(d, hook_id).update(change))
    rc, out = doctor(git_repo, capsys)
    assert rc == 1, out
    assert expect in out


def test_local_hook_entry_must_run_the_tool(git_repo, capsys):
    init(git_repo, profile="jenkins")
    edit_config(git_repo, lambda d: find_hook(d, "npm-groovy-lint").update(entry="echo skipped"))
    rc, out = doctor(git_repo, capsys)
    assert rc == 1 and "doesn't run npm-groovy-lint" in out


def test_excludes_are_flagged_for_review(git_repo, capsys):
    init(git_repo, profile="terraform")

    def change(d):
        find_hook(d, "slsec-checkov")["exclude"] = "^legacy/"
        d["exclude"] = "^vendor/"

    edit_config(git_repo, change)
    rc, out = doctor(git_repo, capsys)
    assert rc == 0, out  # visible, not fatal: excluding generated code is legitimate
    assert "slsec-checkov has `exclude: ^legacy/`" in out
    assert "top-level `exclude: ^vendor/`" in out


def test_skip_env_of_required_hook_fails_in_ci(git_repo, capsys, monkeypatch):
    init(git_repo, profile="base")
    monkeypatch.setenv("SKIP", "gitleaks,check-json")
    rc, out = doctor(git_repo, capsys)
    assert rc == 1 and "skips required hook gitleaks" in out


@pytest.mark.parametrize("reason,fails", [("x", True), ("TODO", True), ("n/a", True), ("short", True),
                                          ("access logs shipped by the central account (SEC-123)", False)])
def test_weak_exception_reasons(git_repo, capsys, reason, fails):
    init(git_repo, profile="terraform")
    settings = git_repo / ".slsec.yaml"
    text = settings.read_text().replace(
        "skip_checks: []", f"skip_checks:\n    - id: CKV_AWS_18\n      reason: {reason!r}"
    )
    settings.write_text(text)
    rc, out = doctor(git_repo, capsys)
    assert (rc == 1) is fails, out
    if fails:
        assert "checkov.skip_checks CKV_AWS_18" in out
    # locally it's a warning, not a failure
    rc, out = doctor(git_repo, capsys, ci=False)
    assert "[FAIL] checkov.skip_checks" not in out


def test_require_mode(git_repo, capsys):
    init(git_repo, profile="base")  # mode: warn
    rc, out = doctor(git_repo, capsys, require_mode="block")
    assert rc == 1 and "mode is 'warn' but this pipeline requires 'block'" in out
    init(git_repo, profile="base", mode="block")
    (git_repo / ".slsec.yaml").write_text((git_repo / ".slsec.yaml").read_text().replace("mode: warn", "mode: block"))
    rc, out = doctor(git_repo, capsys, require_mode="block")
    assert rc == 0, out


def test_require_profiles_overrides_slsec_yaml(git_repo, capsys):
    """A PR that drops a profile from .slsec.yaml *and* its hook is still caught."""
    init(git_repo, profile="base")
    rc, out = doctor(git_repo, capsys, require_profiles="terraform")
    assert rc == 1 and "slsec-checkov (terraform profile) is missing" in out
    rc, out = doctor(git_repo, capsys, require_profiles="cobol")
    assert rc == 1 and "unknown profile 'cobol'" in out


def test_detected_but_unrecorded_profile_warns(git_repo, capsys):
    init(git_repo, profile="base")
    (git_repo / "main.tf").write_text("")
    rc, out = doctor(git_repo, capsys)
    assert "found terraform files but those profiles aren't enabled" in out


def test_sca_hook_is_required_when_configured(git_repo, capsys):
    init(git_repo, profile="base", sca="osv")
    edit_config(git_repo, lambda d: find_hook(d, "slsec-osv").update(stages=["manual"]))
    rc, out = doctor(git_repo, capsys)
    assert rc == 1 and "slsec-osv" in out


# ------------------------------------------------------------------ CI templates stay in step


def test_ci_templates_install_this_release_for_the_doctor_gate():
    wf = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "slsec-reusable.yml").read_text(encoding="utf-8"))
    inputs = wf[True]["workflow_call"]["inputs"]  # PyYAML reads the `on:` key as True
    assert inputs["slsec-version"]["default"] == __version__
    assert re.fullmatch(r"zricethezav/gitleaks:v[0-9.]+@sha256:[0-9a-f]{64}", inputs["gitleaks-image"]["default"])
    groovy = (REPO_ROOT / "vars" / "slsecScan.groovy").read_text(encoding="utf-8")
    assert f"slsecVersion           : '{__version__}'" in groovy


def _set_repo(data, hook_id, url):
    for r in data["repos"]:
        if any(h["id"] == hook_id for h in r.get("hooks", [])):
            r["repo"] = url
            return


@pytest.mark.parametrize("hook_id", ["gitleaks", "detect-private-key", "slsec-checkov"])
def test_required_hook_redefined_locally_fails(git_repo, capsys, hook_id):
    """A `repo: local` hook can reuse a required id with any entry; that's not the scanner."""
    init(git_repo, profile="terraform")

    def change(d):
        for r in d["repos"]:
            r["hooks"] = [h for h in r["hooks"] if h["id"] != hook_id]
        d["repos"] = [r for r in d["repos"] if r["hooks"]]
        d["repos"].append(
            {"repo": "local", "hooks": [{"id": hook_id, "name": hook_id, "entry": "true", "language": "system"}]}
        )

    edit_config(git_repo, change)
    rc, out = doctor(git_repo, capsys)
    assert rc == 1, out
    assert f"required hook {hook_id}" in out
    assert "is configured but disabled: redefined as a `repo: local` hook" in out


@pytest.mark.parametrize(
    "hook_id,url,fix",
    [
        ("gitleaks", "https://github.com/someone/gitleaks-fork", "--trusted-repos"),
        ("slsec-checkov", "https://github.com/someone/slsec-fork", "--source-url"),
    ],
)
def test_required_hook_from_another_repo_fails(git_repo, capsys, hook_id, url, fix):
    init(git_repo, profile="terraform")
    edit_config(git_repo, lambda d: _set_repo(d, hook_id, url))
    rc, out = doctor(git_repo, capsys)
    assert rc == 1, out
    assert f"it comes from `{url}`" in out and fix in out


def test_trusted_mirror_and_url_spelling_pass(git_repo, capsys, monkeypatch):
    init(git_repo, profile="terraform")
    mirror = "https://artifactory.example.invalid/github/gitleaks/gitleaks"

    def change(d):
        _set_repo(d, "gitleaks", mirror + ".git")
        _set_repo(d, "detect-private-key", "git@github.com:pre-commit/pre-commit-hooks.git")

    edit_config(git_repo, change)
    rc, out = doctor(git_repo, capsys)
    assert rc == 1 and "artifactory.example.invalid" in out
    monkeypatch.setenv("SLSEC_TRUSTED_REPOS", mirror)
    rc, out = doctor(git_repo, capsys)
    assert rc == 0, out


@pytest.mark.parametrize(
    "profile,hook_id,change,expect",
    [
        ("docker", "hadolint", {"args": ["--no-fail"]}, "--no-fail"),
        ("docker", "hadolint", {"args": ["--failure-threshold", "none"]}, "none/ignore"),
        ("docker", "hadolint", {"args": ["-t", "ignore"]}, "none/ignore"),
        ("github-actions", "zizmor", {"args": ["--no-exit-codes"]}, "--no-exit-codes"),
        ("github-actions", "zizmor", {"pass_filenames": False}, "pass_filenames"),
        ("python", "slsec-sast", {"args": ["--rules-dir", "empty/"]}, "--rules-dir"),
        ("jenkins", "npm-groovy-lint", {"entry": "npm-groovy-lint --noserver --failon none"}, "--failon none"),
    ],
)
def test_args_that_never_fail_are_rejected(git_repo, capsys, profile, hook_id, change, expect):
    init(git_repo, profile=profile)
    edit_config(git_repo, lambda d: find_hook(d, hook_id).update(change))
    rc, out = doctor(git_repo, capsys)
    assert rc == 1, out
    assert expect in out


def test_gitleaks_config_and_type_overrides_are_flagged_for_review(git_repo, capsys):
    init(git_repo, profile="terraform")

    def change(d):
        find_hook(d, "gitleaks")["args"] = ["--config", "other.toml"]
        find_hook(d, "slsec-checkov")["types"] = ["markdown"]

    edit_config(git_repo, change)
    rc, out = doctor(git_repo, capsys)
    assert rc == 0, out
    assert "gitleaks args point it at a custom config the PR controls" in out
    assert "slsec-checkov has `types: ['markdown']`" in out


def test_doctor_does_not_treat_a_sha_pin_as_old(git_repo, capsys):
    init(git_repo, profile="python")
    edit_config(git_repo, lambda d: _set_rev(d, SOURCE, "3d3c42e5aac5d1f0e3b8c9a7d6e5f4a3b2c1d0e9"))
    rc, out = doctor(git_repo, capsys)
    assert "isn't a version tag" in out
    assert "latest known is" not in out


def _set_rev(data, url, rev):
    for r in data["repos"]:
        if r["repo"] == url:
            r["rev"] = rev
