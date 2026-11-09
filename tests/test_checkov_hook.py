import shutil
from pathlib import Path

import pytest

from conftest import FIXTURES, checkov_available
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


def test_terraform_dirs_groups_and_collapses_nested():
    files = [
        "infra/net/main.tf",
        "infra/net/variables.tf",
        "infra/net/sub/x.tf",
        "infra/app/main.tf",
        "infra/apple/main.tf",  # sibling with a shared prefix must not collapse
        "modules/.terraform/modules/m/main.tf",
        "README.md",
    ]
    assert hook.terraform_dirs(files) == ["infra/app", "infra/apple", "infra/net"]


def test_root_dir_wins():
    assert hook.terraform_dirs(["main.tf", "mod/a.tf"]) == ["."]


def test_windows_separators():
    assert hook.terraform_dirs(["infra\\net\\main.tf"]) == ["infra/net"]


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
