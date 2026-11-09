# slsec documentation

Start with the [README](../README.md) for what slsec is and the quick start.

## By reader

| You are | Read |
|---|---|
| A developer on a team that uses slsec | [Developer guide](developer-guide.md): setup, what runs when, reading and fixing findings, `--no-verify` |
| Rolling slsec out (platform / DevSecOps) | [Platform guide](platform-guide.md), then [CI integration](ci.md), [Rolling out: warn to block](rollout.md), [Providers](providers.md) |
| Reviewing it (security / audit) | [Security overview](security-overview.md), [OWASP DevSecOps mapping](owasp-mapping.md), [Tool selection](tool-selection.md) |
| Stuck | [Troubleshooting and FAQ](troubleshooting.md) |

## All pages

| Page | What |
|---|---|
| [developer-guide.md](developer-guide.md) | Everyday use: commits, pushes, findings, suppressions, bypasses |
| [platform-guide.md](platform-guide.md) | Decisions, rollout order, protecting the config, mirrors and air-gapped networks, keeping current |
| [ci.md](ci.md) | GitHub Actions reusable workflow, Jenkins `slsecScan()`, other CI systems, the setup gate, SonarQube in CI |
| [rollout.md](rollout.md) | The warn-to-block rollout plan |
| [providers.md](providers.md) | Opengrep / Semgrep CE, osv-scanner, Snyk, JFrog, SonarQube |
| [suppressions.md](suppressions.md) | Inline, repo-wide and org-wide exceptions; leaked secrets |
| [security-overview.md](security-overview.md) | Trust boundaries, coverage per hook, the setup gate, pinning, evidence |
| [owasp-mapping.md](owasp-mapping.md) | Coverage against the OWASP DevSecOps Guideline and the CI/CD Top 10 |
| [tool-selection.md](tool-selection.md) | Why these scanners, what was considered, roadmap |
| [ai-agents.md](ai-agents.md) | AI coding agents and MCP config secrets |
| [troubleshooting.md](troubleshooting.md) | Windows, Python versions, slow first run, offline, proxies, setup-gate failures |
| [reference.md](reference.md) | Every `.slsec.yaml` key, environment variable, CLI flag, CI input and Jenkins option |

## Examples

| File | What |
|---|---|
| [github-security.yml](../examples/github-security.yml) | GitHub Actions caller workflow (rollout) |
| [github-security-enforced.yml](../examples/github-security-enforced.yml) | GitHub Actions with `require-mode`, `require-profiles` and internal mirrors |
| [Jenkinsfile](../examples/Jenkinsfile) | Jenkins pipeline (rollout) |
| [Jenkinsfile.enforced](../examples/Jenkinsfile.enforced) | Jenkins with `requireMode`, `requireProfiles`, `trustedRepos` and mirrors |
| [pre-commit-config.mirror.yaml](../examples/pre-commit-config.mirror.yaml) | Hook repos served from internal Git mirrors |
| [slsec.yaml](../examples/slsec.yaml) | `.slsec.yaml` with every setting |
| [CODEOWNERS](../examples/CODEOWNERS) | Files the security owners should review |

Contributing and releasing: [CONTRIBUTING.md](../CONTRIBUTING.md). Changes: [CHANGELOG.md](../CHANGELOG.md).
