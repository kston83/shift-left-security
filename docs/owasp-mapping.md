# OWASP DevSecOps Guideline mapping

How slsec covers the stages of the
[OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/), and what's
planned.

| OWASP stage | Where it runs | slsec today (v0.3) | Planned |
|---|---|---|---|
| **Pre-commit: secrets** | commit hook + CI full history | gitleaks (default ruleset + AI agent / MCP config rules), `detect-private-key` | trufflehog with live-secret verification (nightly CI) |
| **Pre-commit: linting / hygiene** | commit hook | merge-conflict, large-file, YAML/JSON validity | |
| **Static analysis (SAST)** | commit hook (fast rules) → CI (deep) | `slsec-sast` (Opengrep default, Semgrep CE optional) with bundled rule packs ([providers.md](providers.md)); deep SAST via the optional SonarQube quality gate in CI | language linters (ruff `S`, eslint security plugins, gosec); Snyk Code in the IDE |
| **Software composition analysis (SCA)** | pre-push hook → CI | `slsec-osv` (default), `slsec-snyk`, `slsec-jfrog` on manifest changes; CI scans every manifest and uploads SARIF | govulncheck reachability; JFrog Curation |
| **Infrastructure as Code scanning** | commit hook + CI | checkov (Terraform/OpenTofu, Dockerfile) with shared baseline; tflint; hadolint | Kubernetes/Helm (checkov + kubeconform); KICS for Docker Compose |
| **Container scanning** | CI | n/a | trivy / JFrog Xray image scans in CI |
| **CI/CD pipeline security** (OWASP Top 10 CI/CD Security Risks) | commit hook | zizmor + actionlint (GitHub Actions), npm-groovy-lint (Jenkins) | |
| **DAST** | CI / staging | out of scope for hooks | OWASP ZAP in pipeline (separate) |
| **Vulnerability management** | central | SARIF/JUnit from every run (GitHub code scanning, Jenkins Warnings NG) | DefectDojo ingestion, Dependency-Track for SBOMs (cdxgen) |

## OWASP Top 10 CI/CD Security Risks covered by the hooks

| Risk | Control |
|---|---|
| CICD-SEC-1 Insufficient flow control | reusable workflow + Jenkins step enforce the hooks centrally |
| CICD-SEC-3 Dependency chain abuse | zizmor `unpinned-uses` (SHA pinning), Renovate with release-age cooldown |
| CICD-SEC-4 Poisoned pipeline execution | zizmor (`dangerous-triggers`, `template-injection`, `pull_request_target` checkouts) |
| CICD-SEC-5 Insufficient PBAC | zizmor `excessive-permissions`; reusable workflow uses least-privilege `permissions` |
| CICD-SEC-6 Insufficient credential hygiene | gitleaks, zizmor `artipacked` (persisted checkout credentials) |
| CICD-SEC-7 Insecure system configuration | npm-groovy-lint for Jenkinsfiles; Jenkins step passes values via env, not Groovy interpolation |
