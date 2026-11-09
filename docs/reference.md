# Reference

Every setting, command, flag, CI input and option, taken from the code at this release. Guides
explain when to use them: [developer guide](developer-guide.md), [platform guide](platform-guide.md),
[security overview](security-overview.md). `tests/test_docs.py` fails when a flag, input, option,
setting or environment variable is added to the code but not to this page.

* [`.slsec.yaml`](#slsecyaml)
* [Environment variables](#environment-variables)
* [`slsec` commands](#slsec-commands): [`init`](#slsec-init), [`doctor`](#slsec-doctor), [`ci`](#slsec-ci)
* [`python -m slsec.tools`](#python--m-slsectools)
* [Profiles and hooks](#profiles-and-hooks)
* [Hook arguments](#hook-arguments)
* [Reports](#reports)
* [GitHub Actions reusable workflow](#github-actions-reusable-workflow): [inputs](#inputs), [secrets](#secrets)
* [Jenkins `slsecScan()`](#jenkins-slsecscan): [options](#options), [`sonar` map](#sonar-map)

## `.slsec.yaml`

Read from the repo root; `.slsec.yml` also works (`.slsec.yaml` wins if both exist). Without the
file every setting takes its default. Keys not listed here are ignored. An annotated copy is in
[examples/slsec.yaml](../examples/slsec.yaml).

| Key | Type | Default | Notes |
|---|---|---|---|
| `mode` | `warn` \| `block` | `warn` | Applies to slsec's own hooks only. `block`: findings from `slsec-checkov`, `slsec-sast` and the SCA hooks fail the hook, and so do weak inline `checkov:skip` reasons. gitleaks, `detect-private-key`, the hygiene hooks and the linters (tflint, hadolint and npm-groovy-lint at error severity; zizmor, actionlint) fail in either mode. `SLSEC_MODE` overrides it |
| `strict` | `true` \| `false` | `false` | `true`: a scanner that can't run (CLI missing, no credentials, offline, timeout, broken rules, unscannable `.tofu` files) fails the hook instead of warning. `SLSEC_STRICT` overrides it in both directions; the CI templates set it |
| `profiles` | list | `[]` | Written by `slsec init`. `slsec init --update` re-applies these profiles, and `slsec doctor` requires their hooks |
| `providers.sast_engine` | `opengrep` \| `semgrep` \| `none` | `opengrep` | Engine for `slsec-sast`. `none` keeps the hook but it does nothing |
| `providers.sca` | `osv` \| `snyk` \| `jfrog` \| `none` | `none` | Pre-push dependency scanner. When not `none`, `slsec doctor` requires the `slsec-<sca>` hook. `slsec init` writes this key; see [`--sca`](#slsec-init) for what it picks |
| `checkov.skip_checks` | list of exceptions | `[]` | Repo-wide checkov exceptions, added to the [shared baseline](../src/slsec/configs/checkov/baseline.yaml) |
| `checkov.enable_checks` | list of check ids | `[]` | Turns back on a check that the shared baseline skips |
| `sast.exclude_rules` | list of exceptions | `[]` | Repo-wide `slsec-sast` rule exclusions (rule ids as written in the rule files) |

Each exception (`checkov.skip_checks[]`, `sast.exclude_rules[]`) is a mapping:

| Key | Required | Notes |
|---|---|---|
| `id` | yes | Check id (`CKV_AWS_18`) or rule id (`python.lang.security.audit.subprocess-shell-true`) |
| `reason` | yes | Empty or missing: the hooks stop with a configuration error. A placeholder (`x`, `TODO`, `n/a`, `false positive`, …) or anything under 10 characters: `slsec doctor` warns and `slsec doctor --ci` fails |
| `expires` | no | `YYYY-MM-DD`. The exception applies up to and including that day; after it, the check runs again and the hooks and `slsec doctor` say so |

Validation errors (wrong type, unknown `mode` or provider, bad date) stop every slsec hook with
`configuration error: …` and exit code 2, whatever the mode.

## Environment variables

| Variable | Read by | Effect |
|---|---|---|
| `SLSEC_MODE` | all slsec hooks, `slsec doctor` | `warn` or `block`; overrides `mode` in `.slsec.yaml` |
| `SLSEC_STRICT` | all slsec hooks | `1/true/yes/on` or `0/false/no/off`; overrides `strict` in `.slsec.yaml`. Set by both CI templates (`strict` input/option) |
| `SLSEC_REPORT_DIR` | all slsec hooks | Also write SARIF/JUnit reports here (see [Reports](#reports)). Set by both CI templates and `slsec ci` |
| `SLSEC_RUN_ID` | all slsec hooks | Reports with the same run id are merged (pre-commit splits long file lists into several hook runs). Set by both CI templates and `slsec ci` |
| `SLSEC_CI` | (informational) | Set to `1` by both CI templates and `slsec ci`; no hook changes behaviour on it |
| `SLSEC_SOURCE_URL` | `slsec init`, `slsec doctor`, install scripts | Git URL of slsec (an internal mirror, for example). Default `https://github.com/kston83/shift-left-security` |
| `SLSEC_REV` | install scripts | slsec tag to install and pin. Default `v0.3.0` |
| `SLSEC_TRUSTED_REPOS` | `slsec doctor` | Same as `--trusted-repos`, when the flag isn't given |
| `SLSEC_CACHE_DIR` | `slsec-sast`, `slsec-osv` | Cache for downloaded scanners. Default `%LOCALAPPDATA%\slsec\Cache` (Windows), `~/Library/Caches/slsec` (macOS), `${XDG_CACHE_HOME:-~/.cache}/slsec` (Linux) |
| `SLSEC_OPENGREP_PATH` | `slsec-sast` | Use this opengrep binary instead of downloading the pinned one. Not hash-checked: you vouch for it |
| `SLSEC_OSV_SCANNER_PATH` | `slsec-osv` | Same, for osv-scanner (an `osv-scanner` already on `PATH` is used first) |
| `SLSEC_SAST_RULES_DIR` | `slsec-sast` | Use a different rule pack root instead of the bundled packs |
| `SLSEC_SCA_TIMEOUT` | SCA hooks | Seconds per scan before the provider counts as unavailable. Default `300` |
| `SKIP` | pre-commit | Comma-separated hook ids to skip. `slsec doctor --ci` fails when it names a required hook |
| `SNYK_TOKEN`, `SNYK_OAUTH_TOKEN` | `slsec-snyk` | Snyk credentials (or a prior `snyk auth`) |
| `JF_URL`, `JF_ACCESS_TOKEN` | `slsec-jfrog` via `jf` | Headless JFrog credentials (or a prior `jf c add`) |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | scanner downloads, pre-commit, pip | Standard proxy settings |
| `PRE_COMMIT_HOME` | pre-commit | Where pre-commit keeps hook environments (default `~/.cache/pre-commit`). `slsecScan()` sets it to `.slsec-cache/pre-commit` in the workspace |

## `slsec` commands

```text
$ slsec --help
usage: slsec [-h] [--version] {init,doctor,ci} ...

Shift-left security: drop-in pre-commit hooks and policy.

positional arguments:
  {init,doctor,ci}
    init            add slsec hooks + config to a repo
    doctor          check that slsec is set up correctly in a repo
    ci              check the setup (doctor --ci), then run all hooks over the
                    whole repo with reports
```

`--version` prints the version. Each command takes an optional `path` (default `.`); slsec
works from the root of the git repository that contains it.

### `slsec init`

Adds the hooks and config files to a repo, or refreshes them. It merges into an existing
`.pre-commit-config.yaml` (keeping comments and formatting, saving the old file as `.bak`), writes
the tool configs for the chosen profiles, creates `.slsec.yaml` if missing, and runs
`pre-commit install --hook-type pre-commit --hook-type pre-push`.

| Flag | Default | Notes |
|---|---|---|
| `--profile LIST` | auto-detect | Comma-separated profiles (see [Profiles and hooks](#profiles-and-hooks)). `base` is always added. With `--update` and no `--profile`, the profiles in `.slsec.yaml` |
| `--mode warn\|block` | `warn` | Written to a new `.slsec.yaml`. An existing file is never changed; edit `mode` in it |
| `--sca osv\|snyk\|jfrog\|none` | see notes | Pre-push SCA hook. Not given: the `providers.sca` already in `.slsec.yaml`; `none` if that file exists without the key; `osv` for a repo with no `.slsec.yaml`. Anything other than `none` also sets `default_install_hook_types: [pre-commit, pre-push]`. Switching provider removes the other providers' hooks. **v0.3.0 differs:** without `--update` it uses `none`, so pass `--sca` explicitly |
| `--sast-engine opengrep\|semgrep\|none` | see notes | Engine for `slsec-sast`. Not given: the `providers.sast_engine` in `.slsec.yaml`, else `opengrep` (v0.3.0: `opengrep` unless `--update`). `semgrep` adds `semgrep>=1.120,<2` to the hook's `additional_dependencies` |
| `--update` | off | Refresh pins and hooks using the profiles and providers recorded in `.slsec.yaml` |
| `--force` | off | Replace tool config files (`.gitleaks.toml`, `.tflint.hcl`, …) that differ from slsec's, keeping a `.bak`. Without it they're kept |
| `--no-install` | off | Don't run `pre-commit install` |
| `--source-url URL` | `$SLSEC_SOURCE_URL` or the GitHub URL | Repo URL written for slsec's own hooks |
| `--rev TAG` | `v<this version>` | slsec tag to pin. Without `--rev`, pins only move forward: a newer pin (from Renovate, say) is kept |
| `--freeze` | off | Pin each hook repo to the commit SHA behind its tag (`rev: <sha>  # frozen: v1.2.3`), like `pre-commit autoupdate --freeze`. Needs network. Repos already frozen stay frozen on later updates |

Exit codes: 0 done, 2 not a git repository / unknown profile / invalid existing YAML or providers.
If `pre-commit` isn't on `PATH`, init still writes the files and prints how to install it.

<details><summary><code>slsec init --help</code></summary>

```text
usage: slsec init [-h] [--profile PROFILE] [--mode {warn,block}]
                  [--sca {osv,snyk,jfrog,none}]
                  [--sast-engine {opengrep,semgrep,none}] [--update] [--force]
                  [--no-install] [--source-url SOURCE_URL] [--rev REV]
                  [--freeze]
                  [path]

options:
  --profile PROFILE     comma-separated: base, terraform, docker, github-
                        actions, jenkins, java, node, python, go, dotnet
                        (default: auto-detect)
  --mode {warn,block}   IaC/lint findings: warn (default) or block
  --sca {osv,snyk,jfrog,none}
                        pre-push dependency scanner (default: osv for a new
                        install, otherwise the value in .slsec.yaml, none if
                        unset)
  --sast-engine {opengrep,semgrep,none}
                        commit-stage SAST engine (default: the value in
                        .slsec.yaml, else opengrep)
  --update              refresh pins using the profiles recorded in
                        .slsec.yaml
  --force               replace tool config files that differ (keeps .bak)
  --no-install          don't run `pre-commit install`
  --source-url SOURCE_URL
                        git URL of the slsec repo (default: $SLSEC_SOURCE_URL
                        or built-in)
  --rev REV             slsec tag to pin (default: v0.3.0; without --rev an
                        existing newer pin is kept)
  --freeze              pin each hook repo to the commit SHA its tag points to
                        (`# frozen: <tag>` comment, like `pre-commit
                        autoupdate --freeze`); needs network access
```

</details>

### `slsec doctor`

Checks the setup and prints `[ok]`, `[warn]`, `[FAIL]` and `[info]` lines. Exit code 1 if anything
failed, otherwise 0. Without `--ci` it is advisory for a laptop: policy problems are warnings, and
it also checks that pre-commit is installed and the git hooks are active. With `--ci` it is the
**setup gate** the CI templates run; see [security-overview.md](security-overview.md#the-setup-gate)
and the [failure list in troubleshooting.md](troubleshooting.md#setup-gate-failures).

| Flag | Default | Notes |
|---|---|---|
| `--ci` | off | Skip the laptop checks (pre-commit on `PATH`, git hooks installed) and turn weak exception reasons and `SKIP` of required hooks into failures |
| `--require-mode warn\|block` | none | Fail unless `.slsec.yaml` sets this mode |
| `--require-profiles LIST` | none | Comma-separated profiles whose required hooks must be present, whatever `.slsec.yaml` says |
| `--source-url URL` | `$SLSEC_SOURCE_URL` or the GitHub URL | Where slsec's own hooks (`slsec-*`) must come from |
| `--trusted-repos LIST` | `$SLSEC_TRUSTED_REPOS` | Comma-separated extra repo URLs any required hook may come from (internal mirrors). Applies to slsec's own hooks too |

Repo URLs are compared loosely: scheme, case, a trailing `/` and `.git` don't matter, and
`git@host:org/repo` matches `https://host/org/repo`.

<details><summary><code>slsec doctor --help</code></summary>

```text
usage: slsec doctor [-h] [--ci] [--require-mode {warn,block}]
                    [--require-profiles LIST] [--source-url SOURCE_URL]
                    [--trusted-repos LIST]
                    [path]

options:
  --ci                  CI gate: skip local-only checks (git hook, pre-commit
                        on PATH) and fail on weakened policy (weak exception
                        reasons, SKIP of required hooks)
  --require-mode {warn,block}
                        fail unless .slsec.yaml sets this mode
  --require-profiles LIST
                        comma-separated profiles whose hooks must be present,
                        whatever .slsec.yaml says (base, terraform, docker,
                        github-actions, jenkins, java, node, python, go,
                        dotnet)
  --source-url SOURCE_URL
                        git URL slsec's own hooks must come from (default:
                        $SLSEC_SOURCE_URL or built-in)
  --trusted-repos LIST  comma-separated extra repo URLs that required hooks
                        may come from, such as internal mirrors (default:
                        $SLSEC_TRUSTED_REPOS)
```

</details>

### `slsec ci`

For CI systems other than GitHub Actions and Jenkins. Runs `slsec doctor --ci`, then
`pre-commit run --all-files` for the `pre-commit` stage and then the `pre-push` stage, with
`SLSEC_REPORT_DIR`, `SLSEC_CI=1` and a `SLSEC_RUN_ID` set. Exit code: the highest of the three
(0 = all passed). It doesn't run the full-history gitleaks scan or upload anything; add those
in your pipeline. Needs `pre-commit` on `PATH` (exit 2 otherwise).

| Flag | Default | Notes |
|---|---|---|
| `--report-dir DIR` | `slsec-reports` | Where SARIF/JUnit go |
| `--skip-doctor` | off | Don't run the setup gate first |
| `--require-mode`, `--require-profiles`, `--source-url`, `--trusted-repos` | | Passed to the setup gate; same as [`slsec doctor`](#slsec-doctor) |

Run the slsec that `slsec ci` uses from a pinned install in the pipeline, not from the repo
under test, or the PR controls its own gate.

## `python -m slsec.tools`

Manages the scanner binaries slsec downloads (opengrep 1.32.0, osv-scanner 2.7.0), each checked
against a SHA-256 built into the package.

| Command | What |
|---|---|
| `python -m slsec.tools fetch [NAME ...]` | Download and verify into the cache now, for example while building a CI image or before going offline |
| `python -m slsec.tools status [NAME ...]` | Show the cache state without downloading |
| `python -m slsec.tools regen NAME TAG [--download]` | Maintainers: print the registry entry for a new release |

```text
$ python -m slsec.tools status
opengrep 1.32.0 [windows-x86_64]: cached C:\Users\me\AppData\Local\slsec\Cache\opengrep\1.32.0\opengrep.exe
osv-scanner 2.7.0 [windows-x86_64]: cached C:\Users\me\AppData\Local\slsec\Cache\osv-scanner\2.7.0\osv-scanner.exe
```

How a binary is chosen, in order: `SLSEC_<TOOL>_PATH`; the cached copy (re-hashed before each
use); a copy on `PATH` that is byte-identical to the pinned release; a fresh download, verified
before it's moved into the cache. (`slsec-osv` is the exception: it uses any `osv-scanner` on
`PATH` first.)

## Profiles and hooks

`slsec init` detects profiles from the files in the repo and merges each profile's hooks into
`.pre-commit-config.yaml`. **Required** hooks are the ones `slsec doctor` checks are present and
switched on; the others are hygiene the team may tune.

| Profile | Detected from | Hooks (required in bold) | Tool configs written |
|---|---|---|---|
| `base` | always | **`gitleaks`**, **`detect-private-key`**, `check-merge-conflict`, `check-added-large-files` (1 MB), `check-yaml`, `check-json` | `.gitleaks.toml` |
| `terraform` | `*.tf`, `*.tf.json`, `*.tofu` | **`slsec-checkov`**, `tflint` (local hook, Go) | `.tflint.hcl` |
| `docker` | `Dockerfile*`, `Containerfile*`, `*.dockerfile` | **`slsec-checkov`**, **`hadolint`** | `.hadolint.yaml` |
| `github-actions` | `.github/workflows/*.yml` | **`zizmor`**, `actionlint` | `zizmor.yml` |
| `jenkins` | `Jenkinsfile*`, `vars/*.groovy` | **`npm-groovy-lint`** (local hook, Node) | `.groovylintrc.json` |
| `java` | `pom.xml`, `build.gradle(.kts)`, `*.java`, `*.kt` | **`slsec-sast`**, `check-xml` | |
| `node` | `package.json` | **`slsec-sast`**, `check-case-conflict` | |
| `python` | `pyproject.toml`, `setup.py`, `requirements*.txt`, `*.py` | **`slsec-sast`**, `check-ast`, `debug-statements` | |
| `go` | `go.mod` | **`slsec-sast`**, `check-case-conflict` | |
| `dotnet` | `*.csproj`, `*.sln`, `*.cs`, `*.fsproj` | **`slsec-sast`**, `check-xml` | |
| SCA (`providers.sca`) | | **`slsec-osv`** / **`slsec-snyk`** / **`slsec-jfrog`** (pre-push) | |

Interchangeable ids count for a required hook: `gitleaks-system` or `gitleaks-docker` for
`gitleaks`, `hadolint-docker` for `hadolint`.

slsec's own hooks (from [`.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml)):

| Hook id | Stage | Files | What |
|---|---|---|---|
| `slsec-checkov` | pre-commit | `*.tf`, `*.tf.json`, `*.tfvars(.json)`, `*.tofu(.json)`, Dockerfiles/Containerfiles | checkov 3.4.3 with the shared baseline; Terraform scanned per staged directory, Dockerfiles per file; checks inline `checkov:skip=` reasons; `.tofu` reported as not scanned |
| `slsec-sast` | pre-commit | java, kotlin, js/jsx/ts/tsx, python/pyi, go, c# | Opengrep or Semgrep CE with the bundled rule packs for those languages |
| `slsec-osv` | pre-push | dependency manifests and lockfiles | `osv-scanner scan source` |
| `slsec-snyk` | pre-push | same | `snyk test` |
| `slsec-jfrog` | pre-push | same | `jf audit` |

All five also run in the `manual` stage (`pre-commit run --hook-stage manual <id>`). The manifest
pattern covers `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
`pnpm-lock.yaml`, `pom.xml`, `build.gradle(.kts)`, `gradle.lockfile`, `*.versions.toml`,
`requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `go.mod`,
`go.sum`, `*.csproj`, `packages.lock.json`, `Directory.Packages.props` and `packages.config`.

## Hook arguments

Set in `args:` of the hook in `.pre-commit-config.yaml`. The setup gate fails a required hook whose
args switch it off (see [troubleshooting](troubleshooting.md#setup-gate-failures)).

| Hook | Flag | Notes |
|---|---|---|
| `slsec-checkov`, `slsec-sast`, `slsec-sca` | `--mode warn\|block` | Overrides `.slsec.yaml`. `--mode warn` on a required hook fails the setup gate |
| `slsec-checkov`, `slsec-sast`, `slsec-sca` | `--report-dir DIR` | Same as `SLSEC_REPORT_DIR` |
| `slsec-sast` | `--rules-dir DIR` | Replace the bundled rule packs. Fails the setup gate |
| `slsec-sca` | `--provider osv\|snyk\|jfrog` | Set by each SCA hook's `entry`; don't override it |

Exit codes: 0 means clean, findings in `mode: warn`, or a scanner that couldn't run without
`strict`. Anything else fails the commit or push: findings in `mode: block`, a scanner that couldn't
run under `strict`, a configuration error in `.slsec.yaml` (exit 2), or checkov itself crashing or
not starting (in either mode).

## Reports

With `SLSEC_REPORT_DIR` set (both CI templates and `slsec ci` set it), the hooks write:

| File | From | GitHub code scanning category / Warnings NG id |
|---|---|---|
| `checkov-terraform.sarif`, `checkov-terraform.xml` | `slsec-checkov` | `slsec-checkov-terraform` |
| `checkov-dockerfile.sarif`, `checkov-dockerfile.xml` | `slsec-checkov` | `slsec-checkov-dockerfile` |
| `slsec-sast.sarif`, `slsec-sast.xml` | `slsec-sast` | `slsec-sast` |
| `slsec-osv.sarif`, `slsec-snyk.sarif`, `slsec-jfrog.sarif` | SCA hook | `slsec-osv`, `slsec-snyk`, `slsec-jfrog` |
| `gitleaks.sarif` | CI full-history scan (not a hook) | `slsec-gitleaks` |

`.xml` files are JUnit. Reports from runs with the same `SLSEC_RUN_ID` are merged; a report left by
another run id is replaced.

## GitHub Actions reusable workflow

`kston83/shift-left-security/.github/workflows/slsec-reusable.yml@v0.3.0`. How to call it:
[ci.md](ci.md#github-actions). The caller grants `contents: read` and `security-events: write`.

### Inputs

| Input | Type | Default | Notes |
|---|---|---|---|
| `python-version` | string | `3.14` | Python for pre-commit and the hook environments. 3.15 doesn't work yet (checkov's dependencies) |
| `pre-commit-version` | string | `4.3.0` | |
| `gitleaks-image` | string | `zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0…` | Image for the full-history scan, pinned by digest. Point it at a mirror registry if needed |
| `gitleaks-version` | string | `""` | Deprecated. If set, uses `zricethezav/gitleaks:v<version>` by tag (no digest) and warns |
| `slsec-version` | string | `0.3.0` | slsec release installed from `slsec-source` (tag `v<version>`) to run `slsec doctor --ci` |
| `slsec-source` | string | `https://github.com/kston83/shift-left-security` | Git URL of slsec, such as an internal mirror. Also the `--source-url` the gate checks slsec's hooks against |
| `enforce-setup` | boolean | `true` | Fail when the setup gate fails. `false`: warning only |
| `require-mode` | string | `""` | `warn` or `block`: fail unless `.slsec.yaml` sets it |
| `require-profiles` | string | `""` | Comma-separated profiles whose hooks must be present whatever `.slsec.yaml` says |
| `trusted-repos` | string | `""` | Comma-separated extra hook repo URLs (internal mirrors) the gate accepts for required hooks, slsec's own included |
| `upload-sarif` | boolean | `true` | Upload SARIF to code scanning. Private repos need GitHub Advanced Security |
| `fail-on-findings` | boolean | `true` | `false`: hook failures are warnings (report-only). Also lets a failed Sonar quality gate pass. Doesn't affect the setup gate or secrets in history |
| `strict` | boolean | `true` | Sets `SLSEC_STRICT`: a scanner that can't run fails the hooks. Overrides `strict` in `.slsec.yaml` |
| `install-jfrog-cli` | boolean | `false` | Install `jf` (`jfrog/setup-jfrog-cli`) configured from `JF_URL` / `JF_ACCESS_TOKEN` |
| `sonarqube` | boolean | `false` | Add the SonarQube job (scan + quality gate) |
| `sonar-args` | string | `""` | Extra scanner arguments, e.g. `-Dsonar.projectKey=my-project` |
| `sonar-project-base-dir` | string | `.` | `sonar.projectBaseDir` |

### Secrets

All optional; map only the ones you use (no `secrets: inherit`).

| Secret | Used by | Without it |
|---|---|---|
| `SNYK_TOKEN` | pre-push step (`slsec-snyk`) only | A configured `slsec-snyk` fails (`strict: true`) or warns (`strict: false`) |
| `JF_URL`, `JF_ACCESS_TOKEN` | pre-push step (`slsec-jfrog`); `install-jfrog-cli` | Same |
| `SONAR_TOKEN`, `SONAR_HOST_URL` | Sonar job only | The Sonar job fails (it only runs with `sonarqube: true`) |

Job result: fails when the setup gate fails (unless `enforce-setup: false`), when gitleaks finds
secrets in history, and when a hook stage fails (unless `fail-on-findings: false`). A gitleaks scan
that couldn't run is a warning.

## Jenkins `slsecScan()`

`@Library('slsec@v0.3.0') _` then `slsecScan(...)`. Setup: [ci.md](ci.md#jenkins--cloudbees-ci).
Needs a Linux or macOS agent with Python 3.11+, git and curl, and a full (non-shallow) checkout.

### Options

| Option | Default | Notes |
|---|---|---|
| `failOnFindings` | `true` | `false`: hook failures mark the build UNSTABLE instead of failing it |
| `strict` | `true` | Exports `SLSEC_STRICT`; overrides `strict` in `.slsec.yaml` |
| `slsecVersion` | `'0.3.0'` | slsec release (from `slsecSource`, tag `v<version>`) that runs the `slsec doctor --ci` gate |
| `slsecSource` | `'https://github.com/kston83/shift-left-security'` | Git URL of slsec, such as an internal mirror; also the gate's `--source-url` |
| `enforceSetup` | `true` | `false`: a failed setup gate marks the build UNSTABLE instead of failing it |
| `requireMode` | `''` | `'warn'` or `'block'`: fail unless `.slsec.yaml` sets it |
| `requireProfiles` | `''` | e.g. `'terraform,python'`: their hooks must be present whatever `.slsec.yaml` says |
| `trustedRepos` | `''` | Comma-separated extra hook repo URLs (internal mirrors) the gate accepts, slsec's own hooks included |
| `python` | `'python3'` | Python used to create the virtualenvs |
| `preCommitVersion` | `'4.3.0'` | |
| `gitleaks` | `true` | Run the full-history gitleaks scan |
| `gitleaksVersion` | `'8.30.1'` | gitleaks release. A `gitleaks` on the agent's `PATH` is used only if it reports this version; otherwise the release is downloaded and checked against its checksums file |
| `gitleaksBaseUrl` | `'https://github.com/gitleaks/gitleaks/releases/download'` | Download base; point it at an Artifactory generic remote for agents without GitHub access |
| `reportDir` | `'slsec-reports'` | Relative workspace subdirectory for JUnit + SARIF. Deleted at the start of each build, so it must not hold tracked files |
| `publish` | `true` | `junit` (doesn't change the build result), Warnings NG `recordIssues` with one id per scanner, and `archiveArtifacts` |
| `snykTokenCredentialsId` | `null` | "Secret text" credential bound as `SNYK_TOKEN` around the pre-push stage only |
| `jfrogUrlCredentialsId` | `null` | Bound as `JF_URL` |
| `jfrogTokenCredentialsId` | `null` | Bound as `JF_ACCESS_TOKEN` |
| `sonar` | `[enabled: false]` | Map, below. `sonar: true` also works |
| `sonarServer`, `sonarCommand`, `sonarTimeoutMinutes` | | 0.1.x names for `sonar.installation`, `sonar.command`, `sonar.timeoutMinutes`; still accepted |

Returns `[doctor: <rc>, hooks: <rc>, prePush: <rc>, gitleaks: <rc>]`. Build result: fails (or
UNSTABLE with `enforceSetup: false`) on a failed setup gate; fails on secrets in history; UNSTABLE
when gitleaks couldn't run; fails (or UNSTABLE with `failOnFindings: false`) when a hook stage failed.

### `sonar` map

| Key | Default | Notes |
|---|---|---|
| `enabled` | `false` | |
| `installation` | `'SonarQube'` | Server name in Manage Jenkins > System > SonarQube servers |
| `command` | `'sonar-scanner'` | For Java and .NET use the build-integrated scanner, e.g. `'./mvnw -B verify sonar:sonar'` |
| `timeoutMinutes` | `10` | How long `waitForQualityGate` waits |
| `abortPipeline` | value of `failOnFindings` | Passed to `waitForQualityGate abortPipeline:` |
