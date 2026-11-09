# Tool selection

Principles:

1. **Open source first.** Commercial tools the org already licenses (Snyk, JFrog, SonarQube)
   plug in where a hook adds value. The baseline never depends on them.
2. **The commit stage must be fast.** Hooks scan staged files only and should finish in
   roughly 10 seconds. Anything that needs the network or scans the whole project goes to
   pre-push or CI.
3. **Same checks locally and in CI.** CI runs the same pinned hooks, so results match.
4. **Cross-platform.** Wrappers are Python, and tools are installed by pre-commit (no
   bash, no manual installs), so Windows developers are first-class.

## Chosen

| Area | Tool | License | Why |
|---|---|---|---|
| Secrets | gitleaks | MIT | Fast staged-diff scanning, a large default ruleset, SARIF output |
| IaC policy | checkov | Apache-2.0 | Broadest OSS IaC coverage (Terraform, Dockerfile, k8s, Helm, CFN, ARM/Bicep), inline suppressions with reasons |
| Terraform lint | tflint | MPL-2.0 | Catches errors checkov doesn't; the terraform ruleset is built in (no network) |
| Dockerfile lint | hadolint (via hadolint-py) | GPL-3.0 (tool use only) | De-facto Dockerfile linter; wheels ship the binary for every OS |
| GHA security | zizmor | MIT | Purpose-built for GitHub Actions security (injection, permissions, pinning) |
| GHA correctness | actionlint | MIT | Syntax and expression checking for workflows |
| Jenkins | npm-groovy-lint | MIT | CodeNarc with a Jenkinsfile ruleset; installs Java 17 itself if needed |

## Considered

| Tool | Decision |
|---|---|
| trufflehog | AGPL-3.0; its strength is *verifying* live secrets (network). Good for nightly CI, too slow for commit hooks |
| detect-secrets | Baseline-file workflow suits legacy repos with many findings; gitleaks is faster and simpler for new adopters |
| trivy `config` | Absorbed tfsec. Good, but overlaps checkov; kept for CI image/fs scanning |
| KICS | Supports Docker Compose (checkov doesn't). Candidate for Compose in CI |
| terrascan | No longer maintained upstream; avoid |
| Semgrep CE | Taint analysis is limited to a single function; registry rules use the Semgrep Rules License. Supported as an optional engine in phase 2 |
| **Opengrep** | LGPL fork of Semgrep CE: same rule syntax, cross-function taint within a file, native Windows binaries. **Default SAST engine for phase 2** |
| CodeQL | Deep, but needs GHAS for private repos and a build for compiled languages. CI only, where licensed |
| SonarQube | Server-side, whole-project analysis; no meaningful hook. Shift-left via SonarQube for IDE in connected mode + CI quality gate (`slsecScan(sonar: [enabled: true])`) |
| Snyk / JFrog | SCA needs network + auth, so they run as optional **pre-push** hooks in phase 2, only when manifests change. Snyk Code belongs in the IDE plugin. Setup: [providers.md](providers.md) |
| prek | Rust reimplementation of pre-commit, compatible with the same config; teams may use it as a faster runner |

## Roadmap

* **Phase 2: developers.** `slsec-sast` (Opengrep/Semgrep + bundled rule packs for Java/Kotlin,
  JS/TS, Python, Go, .NET); SCA adapters (osv-scanner, Snyk, JFrog) at pre-push; provider docs
  for Snyk/JFrog/SonarQube.
* **Phase 3: backlog.** Dependency-confusion registry guard, GuardDog malicious-package checks,
  JFrog Curation guidance, govulncheck, ruff/eslint/gosec profiles, DefectDojo/Dependency-Track,
  fleet drift checks, Kubernetes/Helm, trivy image scans, commit signing / Scorecard.
