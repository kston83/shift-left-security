# slsec: shift-left security hooks

slsec gives a repo secret scanning, IaC policy checks, SAST, dependency scanning and CI/CD
hygiene as [pre-commit](https://pre-commit.com) hooks, with a shared, versioned policy. Developers
get findings at commit time, on Windows, macOS or Linux. CI runs the **same** pinned hooks over the
whole repo, plus a full-history secret scan and a setup gate, so `git commit --no-verify` or a PR
that edits the config doesn't get around them. It is built on open-source scanners (gitleaks,
checkov, Opengrep, osv-scanner, zizmor, …). Snyk, JFrog and SonarQube plug in where your org
licenses them. Aligned with the
[OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/).

## Quick start

You need git and either [uv](https://docs.astral.sh/uv/) or Python 3.11+ (3.14 recommended).

1. From the root of the repo you want to protect, run the installer. It installs pre-commit if
   needed, then runs `slsec init`, which detects the profiles that apply, writes
   `.pre-commit-config.yaml`, `.slsec.yaml` and the tool configs, and installs the git hooks.

   ```powershell
   # Windows (PowerShell)
   irm https://raw.githubusercontent.com/kston83/shift-left-security/v0.3.0/scripts/install.ps1 -OutFile install.ps1
   powershell -ExecutionPolicy Bypass -File .\install.ps1 --sca osv
   ```

   ```sh
   # macOS / Linux
   curl -fsSLO https://raw.githubusercontent.com/kston83/shift-left-security/v0.3.0/scripts/install.sh
   sh install.sh --sca osv
   ```

   With uv you can skip the script: `uvx --from git+https://github.com/kston83/shift-left-security@v0.3.0 slsec init --sca osv`

   ```text
   Detected profiles: base, terraform, python  (override with --profile)
     .pre-commit-config.yaml: created
     .gitleaks.toml: created
     .tflint.hcl: created
     .slsec.yaml: created (mode=warn)
   pre-commit installed at .git\hooks\pre-commit
   pre-commit installed at .git\hooks\pre-push

   Done. Hooks are active. First run downloads the scanners; try: pre-commit run --all-files
   ```

2. Run every hook once: `pre-commit run --all-files`. The first run downloads and builds the
   scanners (a few minutes; about 11 on a Windows laptop with nothing cached). After that a commit
   takes seconds. New repos start in `mode: warn`: secrets and linter errors block, while IaC, SAST
   and dependency findings are printed without blocking.
3. Commit the generated files: `git add -A && git commit -m "Add slsec"`.
4. Add CI so the checks can't be skipped. For GitHub Actions, add `.github/workflows/security.yml`:

   ```yaml
   on: { push: { branches: [main] }, pull_request: {} }
   permissions: {}
   jobs:
     slsec:
       uses: kston83/shift-left-security/.github/workflows/slsec-reusable.yml@v0.3.0
       permissions: { contents: read, security-events: write }
       with:
         fail-on-findings: false   # report-only until the backlog is triaged
   ```

   For Jenkins, see [examples/Jenkinsfile](examples/Jenkinsfile). Everything else about CI:
   [docs/ci.md](docs/ci.md).

## What a blocked commit looks like

```text
$ git commit -m "Add settings"
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

Finding:     GITHUB_TOKEN = "REDACTED
Secret:      REDACTED
RuleID:      github-pat
File:        settings.py
Line:        1
Fingerprint: settings.py:github-pat:1
```

The commit didn't happen, so the secret isn't in git history. Then:

1. **Fix it.** Here, move the token to an environment variable or secret manager. Rotate it if it
   was ever pushed or shared.
2. **Or suppress it with a reason**, if the finding is a false positive or an accepted risk:
   `# checkov:skip=CKV_AWS_18: <why this is acceptable>`, `# nosemgrep: <rule-id> -- <why>`. Reasons
   like "TODO" or "false positive" are rejected. See [docs/suppressions.md](docs/suppressions.md).
3. **Don't reach for `--no-verify`.** CI runs the same checks over the whole repo and its history.

How to read each kind of finding: [developer guide](docs/developer-guide.md#reading-a-finding).

## What's covered

| Profile | Hooks | Blocks |
|---|---|---|
| `base` (always) | gitleaks (+ AI agent / MCP config rules), private-key, merge-conflict, large-file, YAML/JSON checks | Always |
| `terraform` | `slsec-checkov` (shared baseline), tflint | tflint errors always; checkov in `mode: block` |
| `docker` | `slsec-checkov`, hadolint | hadolint errors always; checkov in `mode: block` |
| `github-actions` | zizmor, actionlint | Always |
| `jenkins` | npm-groovy-lint | Errors, always |
| `java`, `node`, `python`, `go`, `dotnet` | `slsec-sast` (Opengrep, or Semgrep CE) | `mode: block` |
| SCA (`--sca osv\|snyk\|jfrog`) | `slsec-osv`, `slsec-snyk` or `slsec-jfrog`, at pre-push when a manifest changes | `mode: block` |

What each hook does and doesn't catch: [security overview](docs/security-overview.md#coverage).

## Docs

| You are | Start here |
|---|---|
| A developer on a team using slsec | [Developer guide](docs/developer-guide.md) |
| Rolling it out (platform / DevSecOps) | [Platform guide](docs/platform-guide.md), [CI integration](docs/ci.md), [Rolling out: warn to block](docs/rollout.md), [Providers](docs/providers.md) |
| Reviewing it (security / audit) | [Security overview](docs/security-overview.md), [OWASP mapping](docs/owasp-mapping.md) |
| Looking something up | [Reference](docs/reference.md), [Troubleshooting](docs/troubleshooting.md), [all docs](docs/README.md) |

Contributing and releasing: [CONTRIBUTING.md](CONTRIBUTING.md).

## Requirements

* Git, and Python 3.11+ (3.14 recommended). Python 3.15 doesn't work yet because checkov's
  dependencies don't ship 3.15 wheels ([details](docs/troubleshooting.md#python-and-uv-versions)).
* pre-commit (the installer adds it). pre-commit installs every scanner in isolated environments,
  bootstrapping Go and Node when a hook needs them.
* Network access on first use, or internal mirrors
  ([air-gapped setup](docs/platform-guide.md#internal-mirrors-and-air-gapped-networks)).
* CI: GitHub Actions, or Jenkins / CloudBees CI with a Linux or macOS agent. GitHub code scanning
  on private repos needs GitHub Advanced Security.
