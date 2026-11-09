"""The docs stay in step with the code.

docs/reference.md must mention every CLI flag, hook argument, `.slsec.yaml` key, environment
variable, GitHub Actions input and secret, and Jenkins option, and the documented CI defaults must
match the templates. Version pins in the README, docs and examples must match this release and the
profile templates. Internal links and anchors are checked by the link-check job in self-test.yml.
"""

import argparse
import re
from pathlib import Path

import pytest
import yaml

from conftest import REPO_ROOT
from slsec import __version__, cli, tools

REFERENCE = (REPO_ROOT / "docs" / "reference.md").read_text(encoding="utf-8")
WORKFLOW = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "slsec-reusable.yml").read_text(encoding="utf-8"))
WORKFLOW_CALL = WORKFLOW[True]["workflow_call"]  # PyYAML reads the `on:` key as True
GROOVY = (REPO_ROOT / "vars" / "slsecScan.groovy").read_text(encoding="utf-8")

DOC_FILES = [REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").glob("*.md"))]
EXAMPLE_FILES = sorted(p for p in (REPO_ROOT / "examples").iterdir() if p.is_file())
SCRIPT_FILES = sorted((REPO_ROOT / "scripts").glob("install.*"))


def documented(name: str) -> bool:
    """`name` appears in reference.md as code (backticks), at the start of the span."""
    return f"`{name}" in REFERENCE


def section(heading: str) -> str:
    """The text of reference.md from `heading` up to the next heading of the same or higher level."""
    start = REFERENCE.index(heading + "\n")
    level = heading.split(" ", 1)[0]
    rest = REFERENCE[start + len(heading):]
    ends = [m.start() for m in re.finditer(r"^#{1,%d} " % len(level), rest, re.M)]
    return rest[: ends[0]] if ends else rest


def table_row(name: str, heading: str) -> list:
    """Cells of the table row whose first cell is `name`, in the section under `heading`."""
    for line in section(heading).splitlines():
        if line.startswith(f"| `{name}` |"):
            return [c.strip() for c in line.strip().strip("|").split("|")]
    raise AssertionError(f"no table row for `{name}` under {heading!r} in docs/reference.md")


# ------------------------------------------------------------------ CLI


def _subcommands(parser: argparse.ArgumentParser) -> dict:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def _long_flags(parser: argparse.ArgumentParser) -> list:
    return [
        opt
        for action in parser._actions
        for opt in action.option_strings
        if opt.startswith("--") and opt != "--help"
    ]


CLI_CASES = [
    (name, flag)
    for name, sub in _subcommands(cli.build_parser()).items()
    for flag in _long_flags(sub)
] + [("slsec", flag) for flag in _long_flags(cli.build_parser())]


@pytest.mark.parametrize("command,flag", CLI_CASES)
def test_cli_flag_documented(command, flag):
    assert documented(flag), f"`slsec {command} {flag}` is not in docs/reference.md"


@pytest.mark.parametrize("command", sorted(_subcommands(cli.build_parser())))
def test_cli_command_has_a_section(command):
    assert f"### `slsec {command}`" in REFERENCE


@pytest.mark.parametrize("module", sorted((REPO_ROOT / "src" / "slsec" / "hooks").glob("*_hook.py")), ids=lambda p: p.stem)
def test_hook_arguments_documented(module):
    flags = re.findall(r"add_argument\(\s*\"(--[a-z-]+)\"", module.read_text(encoding="utf-8"))
    assert flags, f"no flags found in {module.name}; has the parser moved?"
    missing = [f for f in flags if not documented(f)]
    assert not missing, f"{module.name}: {missing} not in docs/reference.md"


def test_tools_commands_documented():
    src = (REPO_ROOT / "src" / "slsec" / "tools.py").read_text(encoding="utf-8")
    commands = re.findall(r"add_parser\(\"(\w+)\"", src)
    assert commands
    for c in commands:
        assert f"python -m slsec.tools {c}" in REFERENCE, c
    for flag in re.findall(r"add_argument\(\"(--[a-z-]+)\"", src):
        assert flag in REFERENCE, flag


@pytest.mark.parametrize("profile", cli.PROFILES)
def test_profile_documented(profile):
    table_row(profile, "## Profiles and hooks")


# ------------------------------------------------------------------ .slsec.yaml and environment


def _config_keys() -> list:
    src = (REPO_ROOT / "src" / "slsec" / "config.py").read_text(encoding="utf-8")
    keys = set(re.findall(r"\bdata\.get\(\"(\w+)\"", src))
    for var, prefix in (("providers", "providers."), ("checkov_repo", "checkov."), ("sast_repo", "sast.")):
        keys |= {prefix + k for k in re.findall(rf"\b{var}\.get\(\"(\w+)\"", src)}
    # sections are documented through their keys
    keys -= {"providers", "checkov", "sast"}
    keys |= set(re.findall(r"\bitem\.get\(\"(\w+)\"", src))  # exception fields: id, reason, expires
    return sorted(keys)


@pytest.mark.parametrize("key", _config_keys())
def test_slsec_yaml_key_documented(key):
    assert documented(key), f".slsec.yaml key {key!r} is not in docs/reference.md"


def test_config_key_scan_finds_the_known_keys():
    keys = _config_keys()
    for key in ("mode", "strict", "profiles", "providers.sca", "providers.sast_engine",
                "checkov.skip_checks", "checkov.enable_checks", "sast.exclude_rules", "reason", "expires"):
        assert key in keys


NOT_ENV_VARS = {"SLSEC_PLACEHOLDER"}  # a Python constant in cli.py


def _env_vars() -> list:
    names = set()
    for path in [*(REPO_ROOT / "src").rglob("*.py"), *SCRIPT_FILES]:
        names |= set(re.findall(r"\bSLSEC_[A-Z0-9_]*[A-Z0-9]\b", path.read_text(encoding="utf-8")))
    names |= {tools.override_env_var(name) for name in tools.TOOLS}
    return sorted(names - NOT_ENV_VARS)


@pytest.mark.parametrize("name", _env_vars())
def test_environment_variable_documented(name):
    assert documented(name), f"environment variable {name} is not in docs/reference.md"


# ------------------------------------------------------------------ CI templates


@pytest.mark.parametrize("name", sorted(WORKFLOW_CALL["inputs"]))
def test_workflow_input_documented_with_its_default(name):
    spec = WORKFLOW_CALL["inputs"][name]
    cells = table_row(name, "### Inputs")
    assert cells[1] == spec["type"], f"{name}: type {cells[1]} != {spec['type']}"
    default = spec.get("default", "")
    expected = '`""`' if default == "" else f"`{str(default).lower() if isinstance(default, bool) else default}`"
    if "…" in cells[2]:  # abbreviated (a digest): what's shown must be the start of the real default
        shown = cells[2].strip("`").split("…", 1)[0]
        assert str(default).startswith(shown), f"{name}: documented default {cells[2]} isn't a prefix of {default}"
    else:
        assert expected in cells[2], f"{name}: documented default {cells[2]} != {expected}"


def test_scanner_versions_in_reference_match_the_pins():
    hooks = (REPO_ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
    checkov = re.search(r'"checkov==([^"]+)"', hooks).group(1)
    assert f"checkov {checkov}" in REFERENCE, f"reference.md should say checkov {checkov}"
    for name, spec in tools.TOOLS.items():
        assert f"{name} {spec['version']}" in REFERENCE, f"reference.md should say {name} {spec['version']}"


@pytest.mark.parametrize("name", sorted(WORKFLOW_CALL["secrets"]))
def test_workflow_secret_documented(name):
    assert documented(name), f"secret {name} is not in docs/reference.md"


def _groovy_map(header: str) -> dict:
    """key -> default text from a Groovy map literal that starts at `header`."""
    start = GROOVY.index(header)
    body = GROOVY[start: GROOVY.index("]", GROOVY.index("[", start) + 1) + 1]
    return {
        k: v
        for k, v in re.findall(r"^\s+(\w+)\s*:\s*('[^']*'|[^\s,]+)", body, re.M)
    }


JENKINS_OPTIONS = _groovy_map("Map opts = [")
JENKINS_SONAR = _groovy_map("Map sonar = [")


def test_groovy_map_parsing_finds_options():
    assert {"failOnFindings", "reportDir", "trustedRepos", "jfrogTokenCredentialsId"} <= set(JENKINS_OPTIONS)
    assert {"enabled", "installation", "command", "timeoutMinutes", "abortPipeline"} <= set(JENKINS_SONAR)


@pytest.mark.parametrize("name", sorted(JENKINS_OPTIONS))
def test_jenkins_option_documented_with_its_default(name):
    cells = table_row(name, "### Options")
    default = JENKINS_OPTIONS[name]
    assert f"`{default}`" in cells[1], f"{name}: documented default {cells[1]} != `{default}`"


@pytest.mark.parametrize("name", sorted(set(JENKINS_SONAR) | {"sonar"}))
def test_jenkins_sonar_key_documented(name):
    table_row(name, "### `sonar` map" if name != "sonar" else "### Options")


@pytest.mark.parametrize("name", sorted(set(re.findall(r"\bcfg\.(\w+)", GROOVY))))
def test_jenkins_legacy_option_documented(name):
    assert documented(name), f"slsecScan option {name} is not in docs/reference.md"


# ------------------------------------------------------------------ versions in docs and examples


VERSION_PATTERNS = [
    re.compile(r"shift-left-security[^\s@'\"]*@v(\d+\.\d+\.\d+)"),  # uses: ...@vX, git+...@vX
    re.compile(r"shift-left-security/v(\d+\.\d+\.\d+)/"),  # raw.githubusercontent.com/.../vX/scripts
    re.compile(r"slsec@v(\d+\.\d+\.\d+)"),  # @Library('slsec@vX')
    re.compile(r"repo:\s*\S*shift-left-security\S*\s*\n\s*rev:\s*v(\d+\.\d+\.\d+)"),
    re.compile(r"SLSEC_REV:-v(\d+\.\d+\.\d+)|else \{ 'v(\d+\.\d+\.\d+)' \}"),  # install scripts
]


@pytest.mark.parametrize("path", DOC_FILES + EXAMPLE_FILES + SCRIPT_FILES, ids=lambda p: p.relative_to(REPO_ROOT).as_posix())
def test_slsec_version_references_match_this_release(path):
    text = path.read_text(encoding="utf-8")
    found = [v for pattern in VERSION_PATTERNS for m in pattern.finditer(text) for v in m.groups() if v]
    stale = sorted({v for v in found if v != __version__})
    assert not stale, f"{path.name} references slsec v{', v'.join(stale)}; this release is v{__version__}"


def _template_pins() -> dict:
    """repo basename -> rev, and tool -> version, from the profile templates."""
    pins = {}
    for path in (REPO_ROOT / "src" / "slsec" / "templates" / "profiles").glob("*.yaml"):
        for repo in yaml.safe_load(path.read_text(encoding="utf-8")).get("repos", []):
            if "rev" in repo:
                pins[repo["repo"].rstrip("/").rsplit("/", 1)[-1]] = repo["rev"]
            for hook in repo.get("hooks", []):
                for dep in hook.get("additional_dependencies", []):
                    name, _, ver = dep.rpartition("@")
                    pins[name] = ver
    return pins


TEMPLATE_PINS = _template_pins()


@pytest.mark.parametrize("path", DOC_FILES + EXAMPLE_FILES, ids=lambda p: p.relative_to(REPO_ROOT).as_posix())
def test_hook_pins_in_docs_and_examples_match_the_templates(path):
    text = path.read_text(encoding="utf-8")
    wrong = []
    for url, rev in re.findall(r"repo:\s*(\S+)\s*\n\s*rev:\s*(\S+)", text):
        name = url.rstrip("/").rsplit("/", 1)[-1]
        if name in TEMPLATE_PINS and rev != TEMPLATE_PINS[name]:
            wrong.append(f"{url} rev {rev} (templates: {TEMPLATE_PINS[name]})")
    for name, ver in re.findall(r"((?:github\.com/[\w./-]+)|npm-groovy-lint)@(v?[\d.]+)", text):
        if name in TEMPLATE_PINS and ver != TEMPLATE_PINS[name]:
            wrong.append(f"{name}@{ver} (templates: {TEMPLATE_PINS[name]})")
    assert not wrong, f"{path.name}: {wrong}"


def test_example_gitleaks_image_digest_matches_the_workflow():
    digest = WORKFLOW_CALL["inputs"]["gitleaks-image"]["default"].split("@", 1)[1]
    for path in EXAMPLE_FILES:
        for found in re.findall(r"gitleaks:v[\d.]+@(sha256:[0-9a-f]{64})", path.read_text(encoding="utf-8")):
            assert found == digest, path.name


# ------------------------------------------------------------------ examples work


@pytest.mark.parametrize("path", [p for p in EXAMPLE_FILES if p.suffix in (".yml", ".yaml")], ids=lambda p: p.name)
def test_example_yaml_parses(path):
    assert yaml.safe_load(path.read_text(encoding="utf-8"))


def test_mirror_example_passes_the_setup_gate_with_its_mirrors(git_repo, capsys):
    """examples/pre-commit-config.mirror.yaml + examples/slsec.yaml, with the CI settings from
    examples/github-security-enforced.yml, pass `slsec doctor --ci`; without them they don't."""
    examples = REPO_ROOT / "examples"
    (git_repo / ".pre-commit-config.yaml").write_text(
        (examples / "pre-commit-config.mirror.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (git_repo / ".slsec.yaml").write_text((examples / "slsec.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    ci = yaml.safe_load((examples / "github-security-enforced.yml").read_text(encoding="utf-8"))["jobs"]["slsec"]["with"]

    def doctor(**policy):
        args = argparse.Namespace(path=str(git_repo), ci=True, require_mode=None, require_profiles=None,
                                  source_url=None, trusted_repos=None)
        for k, v in policy.items():
            setattr(args, k, v)
        rc = cli.cmd_doctor(args)
        return rc, capsys.readouterr().out

    rc, out = doctor(
        require_mode=ci["require-mode"],
        require_profiles=ci["require-profiles"],
        source_url=ci["slsec-source"],
        trusted_repos=ci["trusted-repos"],
    )
    assert rc == 0, out
    rc, out = doctor(source_url="https://github.com/kston83/shift-left-security")
    assert rc == 1 and "an internal mirror?" in out


# ------------------------------------------------------------------ links and anchors

LINKED_FILES = [REPO_ROOT / "README.md", REPO_ROOT / "CONTRIBUTING.md", REPO_ROOT / "CHANGELOG.md",
                *sorted((REPO_ROOT / "docs").glob("*.md"))]
FENCE = re.compile(r"^\s*(```|~~~)")
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")


def _prose_lines(path: Path):
    """(line number, line) outside fenced code blocks."""
    in_fence = False
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            yield n, line


def github_slug(heading: str) -> str:
    """The anchor GitHub generates for a heading's text."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # links -> their text
    text = text.replace("`", "").replace("*", "").strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)  # keeps letters, digits, _, -, space
    return text.replace(" ", "-")


def anchors(path: Path) -> set:
    seen: dict = {}
    result = set()
    for _, line in _prose_lines(path):
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if not m:
            continue
        slug = github_slug(m.group(1))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        result.add(slug if count == 0 else f"{slug}-{count}")
    return result


def test_github_slug_examples():
    assert github_slug("The setup gate: CI can't trust the PR's own config") == "the-setup-gate-ci-cant-trust-the-prs-own-config"
    assert github_slug("Jenkins / CloudBees CI") == "jenkins--cloudbees-ci"
    assert github_slug("`python -m slsec.tools`") == "python--m-slsectools"
    assert github_slug("`--no-verify`, `SKIP` and `SLSEC_MODE`") == "--no-verify-skip-and-slsec_mode"


@pytest.mark.parametrize("path", LINKED_FILES, ids=lambda p: p.relative_to(REPO_ROOT).as_posix())
def test_internal_links_and_anchors_resolve(path):
    broken = []
    for n, line in _prose_lines(path):
        for target in LINK.findall(line):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target):  # http:, https:, mailto:
                continue
            file_part, _, fragment = target.partition("#")
            dest = (path.parent / file_part).resolve() if file_part else path
            if not dest.exists():
                broken.append(f"{path.name}:{n}: {target} (no such file)")
            elif fragment and dest.suffix == ".md" and fragment not in anchors(dest):
                broken.append(f"{path.name}:{n}: {target} (no heading #{fragment} in {dest.name})")
    assert not broken, "\n".join(broken)
