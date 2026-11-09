# Developer guide

For developers on a team that uses slsec. It covers setting up your clone, what runs when you commit
and push, how to read a finding, and how to fix or suppress it. Setting slsec up for a repo for
the first time is in the [README quick start](../README.md#quick-start).

## Set up your clone

If the repo already has `.pre-commit-config.yaml` and `.slsec.yaml`, you only need pre-commit and
the git hooks. Once per machine, install pre-commit (any one of these):

```sh
uv tool install pre-commit      # or: pipx install pre-commit, or: python -m pip install --user pre-commit
```

Then, once per clone, from the repo root:

```sh
pre-commit install --hook-type pre-commit --hook-type pre-push
```

Check the setup (optional; needs slsec itself, which `uvx` runs without installing):

```sh
uvx --from git+https://github.com/kston83/shift-left-security@v0.3.0 slsec doctor
```

```text
slsec doctor (0.3.0) for C:\src\demo
  [ok]   .pre-commit-config.yaml present
  [ok]   secret scanning (gitleaks) hook configured
  [ok]   slsec hooks pinned at v0.3.0
  [ok]   settings: mode=warn (.slsec.yaml)
  [ok]   pre-commit installed
  [ok]   git pre-commit hook active

0 failure(s), 0 warning(s)
```

Requirements: git and Python 3.11+ (3.14 recommended; not 3.15 yet, see
[troubleshooting](troubleshooting.md#python-and-uv-versions)). pre-commit installs every scanner
itself.

**The first commit is slow.** pre-commit builds an environment for each hook the first time it
runs: checkov, Go for tflint, Node for npm-groovy-lint, the opengrep binary. On a Windows laptop
with nothing cached, the first commit in a Terraform + Python repo took about 11 minutes. Later
commits took 10 to 20 seconds. To get the wait out of the way, run `pre-commit install-hooks` (or
`pre-commit run --all-files`) once after cloning.

## What runs when

| When | What | Scope |
|---|---|---|
| `git commit` | gitleaks, private-key check, hygiene checks, then the profile hooks: `slsec-checkov`, tflint, hadolint, zizmor, actionlint, npm-groovy-lint, `slsec-sast` | Staged files only. `slsec-checkov` scans each Terraform directory that holds a staged file, without recursing |
| `git push` | The SCA hook (`slsec-osv`, `slsec-snyk` or `slsec-jfrog`), if the repo has one | Only when the push changes a dependency manifest or lockfile |
| CI, on every push and PR | The same hooks over every file, both stages, plus gitleaks over the full git history | Whole repo |

What blocks depends on `mode` in `.slsec.yaml`:

| Hook | `mode: warn` (default) | `mode: block` |
|---|---|---|
| gitleaks, `detect-private-key` | **blocks** | **blocks** |
| tflint, hadolint, npm-groovy-lint (error severity), zizmor, actionlint, hygiene checks | blocks | blocks |
| `slsec-checkov`, `slsec-sast`, SCA hooks | prints findings, doesn't block | **blocks** |

A scanner that can't run (offline on first use, Snyk not logged in) prints a warning and lets the
commit or push through, unless the repo sets `strict: true`. CI runs it anyway.

## Reading a finding

### A secret (always blocks)

```text
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GITHUB_TOKEN = "REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.871928
File:        settings.py
Line:        1
Fingerprint: settings.py:github-pat:1
```

`RuleID` says what kind of secret it is, and `File` / `Line` say where. The commit didn't happen, so
the secret isn't in git history. Move it out of the file (environment variable, secret manager)
and commit again. If the value was ever pushed or shared, rotate it.

### An IaC finding (`slsec-checkov`)

```text
slsec checkov (IaC policy)...............................................Failed
- hook id: slsec-checkov

Check: CKV_AWS_18: "Ensure the S3 bucket has access logging enabled"
	FAILED for resource: aws_s3_bucket.logs
	File: \main.tf:5-7

[slsec-checkov] commit blocked by IaC findings. Fix them, or suppress inline with a reason:
    # checkov:skip=CKV_XXX_N: <why this is acceptable>
  See docs/suppressions.md.
```

`File` is relative to the scanned directory (here `infra/`; Windows shows it with a backslash).
checkov scans the whole directory, so findings in files you didn't touch can show up. Search the
check id (`CKV_AWS_18`) for the fix; the [checkov policy index](https://www.checkov.io/5.Policy%20Index/terraform.html)
explains each one. In `mode: warn` the same output appears, followed by
`mode=warn: findings are reported but won't block this commit`.

### A code finding (`slsec-sast`)

```text
    app.py
   ❯❯❱ python.lang.security.audit.subprocess-shell-true
          Found 'subprocess' function 'call' with 'shell=True'. This is dangerous because this call will spawn
          the command using a shell process. [...] Use 'shell=False' instead.

            4┆ return subprocess.call(cmd, shell=True)

[slsec-sast] findings above are warnings only (mode=warn).
```

The rule id (`python.lang.security.audit.subprocess-shell-true`) is what you'd exclude; the message
says what to change.

### A dependency finding (pre-push)

The SCA hook prints the vulnerable package, version and advisory, and in `mode: block`:

```text
[slsec-sca] push blocked by osv-scanner dependency findings. Upgrade the affected packages, or record an exception in your osv-scanner policy.
```

Upgrade the package in the manifest and lockfile, then push again.

## Fix it, or suppress it properly

Fix it if you can. If the finding is a false positive or an accepted risk, suppress it as close to
the code as possible, with a reason a reviewer can judge. "TODO", "x", "n/a", "false positive" and
anything under 10 characters are rejected:

```text
[slsec-checkov] inline suppressions need a reason a reviewer can evaluate:
  infra/main.tf:6: checkov:skip=CKV_AWS_18: reason 'TODO' is a placeholder
  Write it as:  # checkov:skip=CKV_XXX_N: <why this is acceptable>
```

| Tool | Inline suppression |
|---|---|
| checkov | `# checkov:skip=CKV_AWS_18: this IS the access-log bucket; logging to itself would loop` |
| opengrep / Semgrep | `# nosemgrep: <rule-id>  -- <why>` on the line, or the line before |
| tflint | `# tflint-ignore: <rule> # <why>` |
| hadolint | `# hadolint ignore=DL3008` on the line before |
| zizmor | `# zizmor: ignore[<audit>] <why>` at the end of the line |
| gitleaks | `gitleaks:allow` in a comment on the line, only for values that aren't secrets |

Repo-wide exceptions (with an optional expiry date) go in `.slsec.yaml`. All the options are in
[suppressions.md](suppressions.md). Changes to `.slsec.yaml` are usually reviewed by the security
owners (CODEOWNERS), so allow time for that.

## `--no-verify`, `SKIP` and `SLSEC_MODE`

All three work locally and none of them gets you past CI:

| What you do | Locally | In CI |
|---|---|---|
| `git commit --no-verify` / `git push --no-verify` | No hooks run | The same hooks run over the whole repo and fail the build |
| `SKIP=slsec-checkov git commit ...` | That hook is skipped | Not skipped. The setup gate fails if CI's own environment skips a required hook |
| `SLSEC_MODE=warn git commit ...` | slsec findings don't block | CI uses `.slsec.yaml` (and can require `mode: block`) |
| Edit `.pre-commit-config.yaml` to remove or disable a hook | The hook doesn't run | The setup gate fails the build: required hooks are checked against policy the PR can't change |

**A secret committed with `--no-verify` is in git history** as soon as you push it. CI's
full-history scan will fail on it until it's dealt with, and cleaning it up means rotating the
credential and either rewriting history or adding its fingerprint to `.gitleaksignore`. It's much
cheaper to let the hook stop it.

## Running hooks by hand

```sh
pre-commit run --all-files                                  # every commit-stage hook, whole repo
pre-commit run slsec-checkov --files infra/main.tf          # one hook, some files
pre-commit run --hook-stage pre-push --all-files            # the SCA hook over every manifest
SLSEC_MODE=block pre-commit run --all-files                 # see what would block once mode is block
```

On PowerShell, set the variable first: `$env:SLSEC_MODE = "block"; pre-commit run --all-files`.

## Keeping up to date

Pins live in `.pre-commit-config.yaml` (`rev:`). Renovate opens PRs for them. Without Renovate, run
`slsec init --update` (it only moves pins forward and keeps your edits). A scanner upgrade can add
checks that block, so read the release notes in the PR.

## In your editor

The hooks are the floor, not the whole picture. For feedback as you type, use SonarQube for IDE in
connected mode or the Snyk IDE plugin if your org licenses them
([providers.md](providers.md)). If you use AI coding agents, see [ai-agents.md](ai-agents.md).
