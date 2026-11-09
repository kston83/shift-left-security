import json
import os
import re
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from conftest import FIXTURES, REPO_ROOT, checkov_available
from slsec.config import load_config
from slsec.hooks import checkov_hook as hook


@pytest.mark.parametrize(
    "path,tf,docker",
    [
        ("main.tf", True, False),
        ("envs/prod/terraform.tfvars", True, False),
        ("stack.tf.json", True, False),
        ("Dockerfile", False, True),
        ("svc/Dockerfile.prod", False, True),
        ("build/app.dockerfile", False, True),
        ("Containerfile", False, True),
        ("docs/dockerfile-guide.md", False, False),
        ("README.md", False, False),
    ],
)
def test_classification(path, tf, docker):
    assert hook.is_terraform(path) is tf
    assert hook.is_dockerfile(path) is docker


def test_terraform_dirs_groups_by_directory_without_collapsing():
    files = [
        "infra/net/main.tf",
        "infra/net/variables.tf",
        "infra/net/sub/x.tf",
        "infra/app/main.tf",
        "infra/apple/main.tf",
        "modules/.terraform/modules/m/main.tf",
        "README.md",
    ]
    # each directory is scanned on its own; a parent no longer swallows its children
    assert hook.terraform_dirs(files) == ["infra/app", "infra/apple", "infra/net", "infra/net/sub"]


def test_root_dir_does_not_swallow_the_repo():
    assert hook.terraform_dirs(["main.tf", "mod/a.tf"]) == [".", "mod"]


def test_windows_separators():
    assert hook.terraform_dirs(["infra\\net\\main.tf"]) == ["infra/net"]


@pytest.mark.parametrize(
    "dirs,root",
    [
        (["infra/net", "infra/app"], "infra"),
        (["infra/net"], "infra/net"),
        (["infra/apple", "infra/app"], "infra"),
        ([".", "mod"], "."),
        (["a/x", "b/y"], "."),
    ],
)
def test_scan_root_is_the_common_ancestor(dirs, root):
    assert hook.scan_root(dirs) == root


def _tree(base: Path, *files: str) -> None:
    for f in files:
        p = base / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("", encoding="utf-8")


def _skipped(base: Path, skips):
    """Map skip regexes back to the repo-relative paths they hide."""
    candidates = [p for p in base.rglob("*")]
    hidden = set()
    for rx in skips:
        hits = [p for p in candidates if re.search(rx, os.path.abspath(str(p)))]
        assert len(hits) == 1, (rx, hits)
        hidden.add(hits[0].relative_to(base).as_posix())
    return hidden


def test_skip_paths_keep_a_root_file_scan_to_the_root(tmp_path):
    _tree(tmp_path, "main.tf", "variables.tf", "infra/net/main.tf", "modules/vpc/main.tf", ".terraform/x.tf")
    skips = hook.skip_paths(["."], tmp_path, lambda p: True)
    assert _skipped(tmp_path, skips) == {"infra", "modules"}


def test_skip_paths_walk_down_to_staged_dirs_only(tmp_path):
    _tree(tmp_path, "main.tf", "infra/top.tf", "infra/net/main.tf", "infra/net/sub/x.tf", "infra/app/main.tf")
    skips = hook.skip_paths(["infra/net"], tmp_path, lambda p: True)
    # scan root is infra/net itself: only its subdirectory is hidden
    assert hook.scan_root(["infra/net"]) == "infra/net"
    assert _skipped(tmp_path, skips) == {"infra/net/sub"}
    skips = hook.skip_paths(["infra/net", "infra/app"], tmp_path, lambda p: True)
    # root is infra: its own files aren't staged, so they're hidden; net/sub too
    assert _skipped(tmp_path, skips) == {"infra/top.tf", "infra/net/sub"}


def test_skip_paths_honour_precommit_excludes(tmp_path):
    _tree(tmp_path, "infra/main.tf", "infra/legacy.tf", "infra/generated.tf.json")
    (tmp_path / ".pre-commit-config.yaml").write_text(
        "exclude: ^infra/generated\n"
        "repos:\n"
        "- repo: https://example.invalid/slsec\n"
        "  rev: v1\n"
        "  hooks:\n"
        "  - id: slsec-checkov\n"
        "    exclude: legacy\\.tf$\n",
        encoding="utf-8",
    )
    wanted = hook.precommit_filter(tmp_path)
    assert wanted("infra/main.tf")
    assert not wanted("infra/legacy.tf")
    assert not wanted("infra/generated.tf.json")
    skips = hook.skip_paths(["infra"], tmp_path, wanted)
    assert _skipped(tmp_path, skips) == {"infra/legacy.tf", "infra/generated.tf.json"}


def test_skip_path_regexes_survive_checkovs_module_finder(tmp_path):
    """checkov 3.4.x joins the skip list character by character into one regex; brackets would crash it."""
    _tree(tmp_path, "a/main.tf", "a/b [old]/x.tf", "a/c(1)/y.tf")
    skips = hook.skip_paths(["a"], tmp_path, lambda p: True)
    assert len(skips) == 2
    re.compile("|".join(f"({skips})"))  # what checkov's find_modules does
    assert not any(ch in s for s in skips for ch in "[]\\")


def test_hook_files_pattern_matches_the_manifest():
    manifest = yaml.safe_load((REPO_ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
    entry = next(h for h in manifest if h["id"] == "slsec-checkov")
    assert entry["files"] == hook.HOOK_FILES


@pytest.mark.parametrize(
    "line,bad",
    [
        ("# checkov:skip=CKV_AWS_18: this IS the access-log bucket; logging to itself would loop", False),
        ("#checkov:skip=CKV_AWS_18:central logging account handles it (SEC-123)", False),
        ("# checkov:skip=CKV_AWS_18", True),
        ("# checkov:skip=CKV_AWS_18:", True),
        ("# checkov:skip=CKV_AWS_18: x", True),
        ("# checkov:skip=CKV_AWS_18: TODO", True),
        ("# checkov:skip=CKV_AWS_18: false positive", True),
        ("// checkov:skip=CKV_AWS_18: n/a", True),
        ("# nothing to see", False),
    ],
)
def test_inline_skip_reasons(tmp_path, line, bad):
    f = tmp_path / "main.tf"
    f.write_text(f'resource "aws_s3_bucket" "b" {{\n  {line}\n}}\n', encoding="utf-8")
    problems = hook.inline_skip_problems([str(f)])
    assert bool(problems) is bad
    if bad:
        assert problems[0][1] == 2 and problems[0][2] == "CKV_AWS_18"


def test_reasonless_inline_skip_blocks_in_block_mode(git_repo, monkeypatch, capsys):
    (git_repo / "Dockerfile").write_text("# checkov:skip=CKV_DOCKER_3\nFROM scratch\n", encoding="utf-8")
    monkeypatch.setattr(hook, "checkov_command", lambda: [sys.executable, "-c", "raise SystemExit(0)"])
    assert hook.run(["Dockerfile"]) == 0  # warn mode: reported only
    assert "Dockerfile:1: checkov:skip=CKV_DOCKER_3: no reason given" in capsys.readouterr().out
    monkeypatch.setenv("SLSEC_MODE", "block")
    assert hook.run(["Dockerfile"]) == 1


def test_tofu_files_are_reported_not_silently_passed(git_repo, monkeypatch, capsys):
    (git_repo / "main.tofu").write_text("", encoding="utf-8")
    assert hook.run(["main.tofu"]) == 0
    assert "OpenTofu .tofu file(s) were NOT scanned" in capsys.readouterr().out
    monkeypatch.setenv("SLSEC_STRICT", "1")
    assert hook.run(["main.tofu"]) == 2


def test_build_args_warn_mode(tmp_path):
    cfg = load_config(tmp_path, env={})
    args = hook.build_args("terraform", ["a", "b"], cfg)
    assert args[:4] == ["-d", "a", "-d", "b"]
    assert "--soft-fail" in args
    assert "--skip-download" in args
    skip = args[args.index("--skip-check") + 1].split(",")
    assert "CKV_DOCKER_2" in skip


def test_build_args_block_mode_and_reports(tmp_path):
    cfg = load_config(tmp_path, env={"SLSEC_MODE": "block"})
    args = hook.build_args("dockerfile", ["Dockerfile"], cfg, report_dir=tmp_path)
    assert args[:2] == ["-f", "Dockerfile"]
    assert "--soft-fail" not in args
    out = args[args.index("--output-file-path") + 1]
    assert out.startswith("console,") and out.endswith("checkov-dockerfile.xml")


def test_no_iac_files_is_noop(git_repo):
    assert hook.run(["README.md", "src/app.py"]) == 0


def test_invalid_config_fails_closed(git_repo):
    (git_repo / ".slsec.yaml").write_text("mode: sometimes\n")
    assert hook.run(["main.tf"]) == 2


# ---------------------------------------------------------------- real checkov

needs_checkov = pytest.mark.skipif(not checkov_available(), reason="checkov not installed")


def _copy(src: Path, dest: Path) -> None:
    shutil.copytree(src, dest)


@pytest.mark.integration
@needs_checkov
def test_insecure_terraform_warns_but_passes(git_repo, capsys):
    _copy(FIXTURES / "terraform" / "insecure", git_repo / "infra")
    assert hook.run(["infra/main.tf"]) == 0
    out = capsys.readouterr().out
    assert "mode=warn" in out


@pytest.mark.integration
@needs_checkov
def test_insecure_terraform_blocks_in_block_mode(git_repo):
    _copy(FIXTURES / "terraform" / "insecure", git_repo / "infra")
    (git_repo / ".slsec.yaml").write_text("mode: block\n")
    assert hook.run(["infra/main.tf"]) == 1


@pytest.mark.integration
@needs_checkov
def test_secure_terraform_is_clean_in_block_mode(git_repo):
    # Only main.tf is "staged"; variables.tf must still be resolved via the directory scan.
    _copy(FIXTURES / "terraform" / "secure", git_repo / "infra")
    (git_repo / ".slsec.yaml").write_text("mode: block\n")
    assert hook.run(["infra/main.tf"]) == 0


@pytest.mark.integration
@needs_checkov
def test_dockerfiles(git_repo):
    _copy(FIXTURES / "docker", git_repo / "docker")
    (git_repo / ".slsec.yaml").write_text("mode: block\n")
    assert hook.run(["docker/insecure/Dockerfile"]) == 1
    # secure Dockerfile only lacks HEALTHCHECK, which the baseline skips
    assert hook.run(["docker/secure/Dockerfile"]) == 0


@pytest.mark.integration
@needs_checkov
def test_repo_exception_suppresses_finding(git_repo):
    _copy(FIXTURES / "docker", git_repo / "docker")
    (git_repo / ".slsec.yaml").write_text(
        "mode: block\n"
        "checkov:\n"
        "  skip_checks:\n"
        "    - {id: CKV_DOCKER_4, reason: test}\n"
        "    - {id: CKV_DOCKER_7, reason: test}\n"
        "    - {id: CKV_DOCKER_1, reason: test}\n"
        "    - {id: CKV_DOCKER_3, reason: test}\n"
    )
    assert hook.run(["docker/insecure/Dockerfile"]) == 0


@pytest.mark.integration
@needs_checkov
def test_reports_written(git_repo):
    _copy(FIXTURES / "terraform" / "insecure", git_repo / "infra")
    reports = git_repo / "reports"
    assert hook.run(["infra/main.tf", "--report-dir", str(reports)]) == 0
    assert (reports / "checkov-terraform.sarif").stat().st_size > 0
    assert (reports / "checkov-terraform.xml").stat().st_size > 0


@pytest.mark.integration
@needs_checkov
def test_split_runs_add_up_in_one_report(git_repo, monkeypatch):
    """pre-commit splits a long file list into several hook runs; with one SLSEC_RUN_ID they share a report."""
    _copy(FIXTURES / "terraform" / "insecure", git_repo / "a")
    _copy(FIXTURES / "terraform" / "insecure", git_repo / "b")
    reports_dir = git_repo / "reports"
    monkeypatch.setenv("SLSEC_RUN_ID", "run-1")
    assert hook.run(["a/main.tf", "--report-dir", str(reports_dir)]) == 0
    assert hook.run(["b/main.tf", "--report-dir", str(reports_dir)]) == 0
    doc = json.loads((reports_dir / "checkov-terraform.sarif").read_text(encoding="utf-8"))
    assert len(doc["runs"]) == 1
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in doc["runs"][0]["results"]}
    assert uris == {"a/main.tf", "b/main.tf"}
    # a later CI run replaces the report instead of adding to it
    monkeypatch.setenv("SLSEC_RUN_ID", "run-2")
    assert hook.run(["b/main.tf", "--report-dir", str(reports_dir)]) == 0
    doc = json.loads((reports_dir / "checkov-terraform.sarif").read_text(encoding="utf-8"))
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in doc["runs"][0]["results"]}
    assert uris == {"b/main.tf"}


@pytest.mark.integration
@needs_checkov
def test_root_file_does_not_scan_the_whole_repo(git_repo):
    _copy(FIXTURES / "terraform" / "insecure", git_repo / "infra")
    (git_repo / "main.tf").write_text('terraform {\n  required_version = ">= 1.5"\n}\n', encoding="utf-8")
    reports_dir = git_repo / "reports"
    assert hook.run(["main.tf", "--report-dir", str(reports_dir)]) == 0
    sarif = reports_dir / "checkov-terraform.sarif"
    results = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0].get("results", []) if sarif.exists() else []
    assert not [r for r in results if "infra/" in json.dumps(r)]
