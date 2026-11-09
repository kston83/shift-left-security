# slsec: shift-left security hooks

Drop-in [pre-commit](https://pre-commit.com) hooks and a shared security policy. One command
gives any repo secret scanning, IaC policy checks and CI/CD hygiene, and CI enforces the
**same** checks, so `git commit --no-verify` doesn't skip them.

Built on open-source scanners and aligned with the
[OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/). See
[docs/owasp-mapping.md](docs/owasp-mapping.md).

| Profile | Hooks | Blocks by default? |
|---|---|---|
| `base` (always) | gitleaks (+ AI agent / MCP config rules), private-key, merge-conflict, large-file, YAML/JSON checks | **Yes** (secrets always block) |
| `terraform` | `slsec-checkov` (shared baseline policy), tflint | Warn; `mode: block` to enforce |
| `docker` | `slsec-checkov`, hadolint | Warn; `mode: block` to enforce |
| `github-actions` | zizmor, actionlint | Yes |
| `jenkins` | npm-groovy-lint (Jenkinsfiles, shared-library Groovy) | Yes, on errors |

## Quick start

From the root of the repo you want to protect:

```powershell
# Windows
irm https://raw.githubusercontent.com/kston83/shift-left-security/v0.2.0/scripts/install.ps1 -OutFile install.ps1
.\install.ps1
```

```sh
# macOS / Linux
curl -fsSLO https://raw.githubusercontent.com/kston83/shift-left-security/v0.2.0/scripts/install.sh
sh install.sh
```

Or, if you already have [uv](https://docs.astral.sh/uv/):

```sh
uvx --from git+https://github.com/kston83/shift-left-security@v0.2.0 slsec init
```

`slsec init` detects which profiles apply. It then writes `.pre-commit-config.yaml` (merged
into any config you already have), the tool configs (`.gitleaks.toml`, `.tflint.hcl`, ...)
and `.slsec.yaml`, and runs `pre-commit install`. Common options:

```sh
slsec init --profile terraform,docker --mode block   # choose profiles, enforce from day one
slsec init --update                                  # refresh pins later (or let Renovate do it)
slsec doctor                                         # is everything wired up?
```

### Or wire it up by hand

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/kston83/shift-left-security
    rev: v0.2.0
    hooks:
      - id: slsec-checkov
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks
```

## CI (the part that makes it stick)

* **GitHub Actions**: call the reusable workflow, which uploads SARIF to code scanning:
  [examples/github-security.yml](examples/github-security.yml)
* **Jenkins / CloudBees CI**: load this repo as a shared library and call `slsecScan()`:
  [examples/Jenkinsfile](examples/Jenkinsfile)

Both run the commit and pre-push (SCA) stages and can pass optional Snyk, JFrog and SonarQube
credentials and a SonarQube quality gate. Details are in [docs/ci.md](docs/ci.md); provider setup is in
[docs/providers.md](docs/providers.md).

## Settings: `.slsec.yaml`

```yaml
mode: warn            # warn | block   (IaC + lint findings; secrets always block)
checkov:
  skip_checks:        # repo-level exceptions: reason required, expiry optional
    - id: CKV_AWS_18
      reason: "access logs shipped by the central logging account"
      expires: 2027-06-30
  enable_checks: []   # turn back on a check the shared baseline skips
```

Inline suppressions are preferred: `# checkov:skip=CKV_AWS_20: <reason>`. See
[docs/suppressions.md](docs/suppressions.md).

## Docs

* [OWASP DevSecOps mapping](docs/owasp-mapping.md)
* [Tool selection and roadmap](docs/tool-selection.md)
* [Rolling out: warn to block](docs/rollout.md)
* [Suppressions and exceptions](docs/suppressions.md)
* [CI integration](docs/ci.md)
* [Providers: Opengrep/Semgrep, osv-scanner, Snyk, JFrog, SonarQube](docs/providers.md)
* [AI coding agents](docs/ai-agents.md)
* [Contributing / releasing](CONTRIBUTING.md)

## Requirements

Git and Python 3.11+ (3.14 recommended; 3.15 isn't supported yet because checkov's
dependencies don't ship 3.15 wheels). pre-commit installs everything else (checkov, gitleaks, tflint,
hadolint, zizmor, ...) in isolated environments the first time the hooks run. It bootstraps
Go and Node itself when a hook needs them, so there's nothing else to install by hand.
