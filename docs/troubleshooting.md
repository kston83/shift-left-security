# Troubleshooting and FAQ

* [Windows: paths, line endings, PowerShell](#windows-paths-line-endings-powershell)
* [Python and uv versions](#python-and-uv-versions)
* [The first run is slow](#the-first-run-is-slow)
* [Offline and air-gapped machines](#offline-and-air-gapped-machines)
* [Proxies, TLS inspection and mirrors](#proxies-tls-inspection-and-mirrors)
* [checkov install or dependency conflicts](#checkov-install-or-dependency-conflicts)
* [Setup gate failures](#setup-gate-failures)
* [Suppressions need a real reason](#suppressions-need-a-real-reason)
* [Other common problems](#other-common-problems)

## Windows: paths, line endings, PowerShell

**"LF will be replaced by CRLF" warnings after `slsec init`.** slsec writes its files with LF line
endings. With `core.autocrlf=true` (the Git for Windows default) Git warns that it will convert
them in your working copy:

```text
warning: in the working copy of '.pre-commit-config.yaml', LF will be replaced by CRLF the next time Git touches it
```

It's harmless: Git stores LF either way and the hooks read both. To keep LF in the working copy
too, add a `.gitattributes` to the repo (this is what slsec uses for itself):

```gitattributes
* text=auto eol=lf
*.ps1 text eol=crlf
```

**checkov shows `File: \main.tf`.** checkov prints paths relative to the directory it scanned,
with a backslash on Windows. `\main.tf:5-7` in a scan of `infra/` means `infra/main.tf`, lines 5-7.

**"Filename too long" while pre-commit clones hook repos.** Enable long paths for Git:
`git config --global core.longpaths true`.

**The install script won't run.** Windows PowerShell blocks downloaded scripts by default. Run it
for this one invocation without changing the machine policy:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

or use `uvx` instead (see the [quick start](../README.md#quick-start)).

**Setting environment variables for one command.** `SKIP=x git commit` is bash syntax. In
PowerShell set it, run, then clear it:

```powershell
$env:SLSEC_MODE = "block"; pre-commit run --all-files; Remove-Item Env:SLSEC_MODE
```

**opengrep on Windows** is a native binary that slsec downloads with its DLLs into
`%LOCALAPPDATA%\slsec\Cache\opengrep\<version>\`. If you provide your own with
`SLSEC_OPENGREP_PATH`, keep `opengrep.exe` and its DLLs in the same folder. Semgrep CE works on
Windows from version 1.120.

## Python and uv versions

| Python | Status |
|---|---|
| 3.11, 3.12, 3.13 | Supported. 3.11 is the floor: the install scripts refuse anything older |
| 3.14 | Recommended. slsec is developed and tested on it, and the CI templates use it |
| 3.15 | Not yet. checkov's dependencies (pycares, orjson) and PyYAML don't ship 3.15 wheels, so `slsec-checkov` fails to install. slsec's weekly canary job will show when that changes |

pre-commit builds the hook environments with the Python that pre-commit itself runs on. If that's
3.15, pin the hooks to 3.14 in `.pre-commit-config.yaml`:

```yaml
default_language_version:
  python: python3.14
```

or install pre-commit on 3.14: `uv tool install --python 3.14 pre-commit`. `slsec init` prints a
note when it runs on 3.15 and the repo uses checkov.

**`uv` (or `pre-commit`) isn't found after installing it.** uv installs tools into a directory that
may not be on `PATH` yet. Run `uv tool update-shell` and open a new terminal.

**`slsec: Python is older than 3.11`** from the install script: install 3.11+ (3.14 recommended),
or install uv and re-run; the script prefers uv, then pipx, then the Python on `PATH`.

## The first run is slow

pre-commit builds an isolated environment for every hook the first time it runs on a machine
(checkov and its dependencies; Go, to build tflint; Node, for npm-groovy-lint), and slsec downloads
opengrep (and osv-scanner, if used). Measured on a Windows laptop with nothing cached, a Terraform
+ Python repo: **about 11 minutes** for the first commit, then **10 to 20 seconds** per commit.

* Do it once up front: `pre-commit install-hooks`, or `pre-commit run --all-files`.
* Pre-fetch slsec's binaries: `python -m slsec.tools fetch` (in an environment where slsec is
  installed).
* GitHub Actions: the reusable workflow caches `~/.cache/pre-commit`, keyed on
  `.pre-commit-config.yaml`, so only the first run after a config change is slow.
* Jenkins: environments live in `.slsec-cache/` in the workspace. Use a persistent workspace or a
  shared cache to keep them between builds.
* Build agents and dev containers: bake the caches into the image (`pre-commit install-hooks`,
  `python -m slsec.tools fetch` with `SLSEC_CACHE_DIR` set to a directory in the image).

## Offline and air-gapped machines

What happens when there's no network:

| Hook | Offline behaviour |
|---|---|
| Hook environments | pre-commit can't build them. Build them while online (`pre-commit install-hooks`) or point it at internal mirrors |
| `slsec-sast` | Works offline once opengrep is cached. On first use with no network it warns and skips (fails with `strict: true`) |
| `slsec-osv` | Needs api.osv.dev. Offline, it warns and lets the push through (fails with `strict: true`); the hook has no offline-database option |
| `slsec-snyk`, `slsec-jfrog` | Need their service; same warn-or-fail behaviour |
| everything else | Works offline |

Setting up mirrors for every download (slsec, hook repos, PyPI, Go, npm, the scanner binaries,
gitleaks for CI) is covered in the
[platform guide](platform-guide.md#internal-mirrors-and-air-gapped-networks).

## Proxies, TLS inspection and mirrors

* Set `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`. slsec's binary downloads, pre-commit, pip and git
  all honour them.
* **TLS inspection (a corporate root CA):** slsec downloads with Python's default TLS settings.
  On Windows that's the Windows certificate store, so a CA your IT department installed there
  works. On macOS and Linux, set `SSL_CERT_FILE` to a bundle that includes the corporate CA. pip
  needs `PIP_CERT` (or `cert` in `pip.conf`), and git needs `http.sslCAInfo`.
* **Internal PyPI:** `PIP_INDEX_URL`. pre-commit uses pip for the Python hook environments, so the
  setting applies there too.
* **Internal Git mirrors of the hook repos:** change the `repo:` URLs in `.pre-commit-config.yaml`
  and list them in CI's `trusted-repos`, or the setup gate fails them. Example:
  [examples/pre-commit-config.mirror.yaml](../examples/pre-commit-config.mirror.yaml).

## checkov install or dependency conflicts

* **The hook can't conflict with your project's dependencies.** pre-commit installs checkov into
  its own environment for `slsec-checkov`. Conflicts appear only if you install `slsec[checkov]`
  into a project virtualenv; install it as a tool instead (`uv tool install`, `pipx`), or just let
  pre-commit handle it.
* **"Failed building wheel for pycares" / orjson / PyYAML:** pre-commit is on a Python with no
  prebuilt wheels for those packages, which today means 3.15. See
  [Python and uv versions](#python-and-uv-versions).
* **A Renovate PR bumps checkov and the hook starts failing:** new checkov versions add policies.
  The PR is labelled `policy-change` in slsec; read the release notes, fix or suppress the new
  findings with reasons, then merge.
* **Clearing a broken environment:** `pre-commit clean` removes every cached hook environment; the
  next run rebuilds them.

## Setup gate failures

`slsec doctor --ci` runs first in CI (and `slsec doctor` gives the same messages as warnings on a
laptop). Each `[FAIL]` line, what causes it, and the fix:

| Message | Cause | Fix |
|---|---|---|
| `.pre-commit-config.yaml missing. Run slsec init` | No pre-commit config in the repo | `slsec init`, commit the result |
| `.pre-commit-config.yaml invalid YAML: …` / `settings invalid: …` | A YAML or `.slsec.yaml` validation error | Fix the file at the line shown |
| `required hook X (P profile) is missing from .pre-commit-config.yaml` | A hook the profile needs isn't configured. `P` comes from `.slsec.yaml` `profiles`, CI's `require-profiles`, or `sca=…` | `slsec init --update`, or add the hook back |
| ``required hook X is configured but disabled: `stages: [...]` keeps it out of the pre-commit stage`` (or ``makes it manual-only``) | `stages:` on the hook, or `default_stages`, leaves out the stage it runs in | Remove the `stages:` override |
| ``… disabled: `language: fail` `` | The hook was replaced with a deliberate failure stub | Restore the hook |
| ``… disabled: redefined as a `repo: local` hook`` or ``… `entry: …` doesn't run <tool>`` | The required id points at a local command instead of the real scanner | Use the upstream hook (for tflint and npm-groovy-lint, keep the entry starting with the tool) |
| ``… disabled: `entry: …` overrides the hook's command`` | `entry:` on a remote hook | Remove `entry:` |
| ``… disabled: it comes from `URL`, not … (an internal mirror? pass it with --source-url in the CI definition)`` (or ``--trusted-repos``) | The hook's `repo:` isn't the upstream, the slsec source or a trusted mirror | If it's your mirror: set `slsec-source` or `trusted-repos` in CI. Otherwise restore the upstream URL |
| ``… disabled: `pass_filenames: false` gives it no files to scan`` | The hook would scan nothing | Remove `pass_filenames: false` |
| ``… disabled: `--mode warn` in args overrides .slsec.yaml`` | `args: [--mode, warn]` on a slsec hook | Remove it; set `mode` in `.slsec.yaml` |
| ``… disabled: `--exit-code 0` never fails`` (gitleaks); `` `--no-fail` never fails`` or ``a failure threshold of none/ignore never fails`` (hadolint); `` `--no-exit-codes` never fails`` (zizmor); `` `--failon none` never fails`` (npm-groovy-lint); `` `--rules-dir` replaces the bundled rule packs`` (`slsec-sast`) | Arguments that stop the scanner ever failing | Remove the argument; suppress specific findings instead |
| `SKIP=… skips required hook X` | CI's environment sets `SKIP` | Remove `SKIP` from the pipeline |
| `mode is 'warn' but this pipeline requires 'block'` | CI sets `require-mode: block` | Set `mode: block` in `.slsec.yaml` (or, if the repo isn't ready, change the CI requirement through the security owners) |
| `checkov.skip_checks ID: reason 'x' is a placeholder; …` (also `sast.exclude_rules`, `is too short`, `no reason given`) | An exception's reason is a placeholder or under 10 characters | Write a real reason ([below](#suppressions-need-a-real-reason)) |
| `--require-profiles: unknown profile 'x'` | A typo in CI's `require-profiles` | Use the [profile names](reference.md#profiles-and-hooks) |
| GitHub: `could not install slsec v… from …` / `slsec-version must look like 1.2.3` | The gate's own install failed (bad version, unreachable source) | Check `slsec-version` and `slsec-source`; on GHES, check the runner can reach the source |

Warnings (`[warn]`) don't fail the build. They flag things a reviewer should look at: `exclude`,
`files` or `types` on a required hook, a top-level `exclude`, gitleaks pointed at another config,
profile files that aren't enabled, a slsec pin behind the gate's version, or an expired exception.

## Suppressions need a real reason

Every exception (inline `checkov:skip=`, `checkov.skip_checks`, `sast.exclude_rules`) needs a
reason a reviewer can evaluate. A reason is rejected if it is shorter than 10 characters or is one
of these placeholders (case and trailing punctuation ignored): `x`, `xx`, `xxx`, `-`, `.`, `?`, `na`,
`n/a`, `none`, `todo`, `tbd`, `fixme`, `skip`, `skipped`, `ignore`, `ignored`, `wip`, `temp`,
`temporary`, `test`, `false positive`, `fp`, `reason`, `no reason`, `not applicable`, `accepted`,
`ok`, `fine`.

| Rejected | Accepted |
|---|---|
| `# checkov:skip=CKV_AWS_18: TODO` | `# checkov:skip=CKV_AWS_18: this IS the access-log bucket; logging to itself would loop` |
| `reason: "false positive"` | `reason: "value is a public test fixture key from the vendor docs (SEC-412)"` |
| `reason: "ok"` | `reason: "access logs shipped by the central logging account (ticket SEC-123)"` |

Where it's enforced:

* Missing `reason` in `.slsec.yaml`: every slsec hook stops with `configuration error` (exit 2).
* Placeholder reason in `.slsec.yaml`: `slsec doctor` warns; the CI setup gate fails.
* Placeholder or missing reason on an inline `checkov:skip=`: printed in `mode: warn`, fails the
  commit in `mode: block`.

Temporary exceptions should carry `expires: YYYY-MM-DD` ([suppressions.md](suppressions.md)).

## Other common problems

**"pre-commit is not installed, so git hooks were not activated"** after `slsec init`. Install it
(`uv tool install pre-commit`) and run `pre-commit install --hook-type pre-commit --hook-type pre-push`.

**A hook passes on my laptop but fails in CI.** CI scans every file, not just staged ones; runs the
pre-push SCA stage over all manifests; is strict (a scanner that can't run fails); and ignores your
local `SLSEC_MODE` / `SKIP`. Reproduce with `SLSEC_STRICT=1 pre-commit run --all-files` and
`pre-commit run --hook-stage pre-push --all-files`.

**`Snyk dependency scan skipped: no Snyk credentials found`.** Run `snyk auth` or set `SNYK_TOKEN`.
In CI, pass the `SNYK_TOKEN` secret (GitHub) or `snykTokenCredentialsId` (Jenkins).
See [providers.md](providers.md#snyk).

**CI: "gitleaks found secrets in git history".** A secret is in a past commit. Rotate it first. Then
either rewrite history to remove it, or add the finding's fingerprint (from `gitleaks.sarif`) to
`.gitleaksignore`. See [suppressions.md](suppressions.md#secrets-gitleaks).

**CI: SARIF upload fails on a private repo.** Private repos need GitHub
Advanced Security for code scanning. Set `upload-sarif: false`; the reports are still kept as a
workflow artifact.

**Jenkins: `reportDir … holds files tracked by git`.** `slsecScan()` deletes `reportDir` at the
start of each build and won't delete tracked files. Choose a directory that isn't in the repo.

**Jenkins: `Warnings Next Generation plugin not installed`.** SARIF is still archived; install the
plugin to see results per scanner.

**`.tofu` files "were NOT scanned".** checkov doesn't read OpenTofu's `.tofu` extension yet. Keep
resources you want checked in `.tf` files.
