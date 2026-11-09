# CI integration

Developers can skip hooks (`--no-verify`, or simply never running `pre-commit install`), so CI
runs the **same pinned hooks** over the whole repo, plus a full-history gitleaks scan.

## GitHub Actions

```yaml
# .github/workflows/security.yml
on:
  push:
    branches: [main]
  pull_request:
permissions: {}
jobs:
  slsec:
    uses: kston83/shift-left-security/.github/workflows/slsec-reusable.yml@v0.1.0
    permissions:
      contents: read
      security-events: write
    # with:
    #   fail-on-findings: false   # report-only while burning down a backlog
    #   upload-sarif: false       # private repo without GitHub Advanced Security
```

What it does:

1. Checks out the full history, without persisting credentials.
2. Runs `pre-commit run --all-files` with `SLSEC_REPORT_DIR` set, so `slsec-checkov` also
   writes SARIF/JUnit.
3. Runs `gitleaks git` over the full history (pinned Docker image) and writes SARIF.
4. Uploads the SARIF to code scanning, one category per tool, and keeps the reports as an
   artifact.
5. Fails on secrets in history, and on hook failures unless `fail-on-findings: false`.

Hooks in `mode: warn` still exit 0, so IaC findings show up in code scanning without failing
the build until the repo switches to `mode: block`.

**SonarQube:** keep your existing `sonarqube-scan-action` job and quality gate. There's
no value in duplicating it here.

## Jenkins / CloudBees CI

1. Register this repo as a **Global Trusted Pipeline Library** named `slsec`. Use Manage
   Jenkins > System, or in CloudBees CI the controller or Operations Center. Pin it to a tag.
2. In the Jenkinsfile:

```groovy
@Library('slsec@v0.1.0') _

pipeline {
  agent { label 'linux' }
  stages {
    stage('Shift-left security') {
      steps {
        slsecScan()
      }
    }
  }
}
```

Options:

| Option | Default | Notes |
|---|---|---|
| `failOnFindings` | `true` | `false` marks the build UNSTABLE instead of failing it |
| `gitleaks` | `true` | Full-history scan; needs a non-shallow checkout |
| `gitleaksBaseUrl` | GitHub releases | Point at an Artifactory generic remote for air-gapped agents |
| `python` | `python3` | Agent needs Python 3.9+, git, curl |
| `reportDir` | `slsec-reports` | JUnit + SARIF land here |
| `publish` | `true` | `junit` (doesn't change the build result) + Warnings NG `recordIssues(sarif)` + archive |
| `sonar` | `false` | Runs `sonarCommand` inside `withSonarQubeEnv`, then `waitForQualityGate` |
| `sonarCommand` | `sonar-scanner` | e.g. `./mvnw -B sonar:sonar`, `./gradlew sonar` |
| `sonarServer` | `SonarQube` | Server name configured in Jenkins |

Plugins used: Pipeline, JUnit, Warnings Next Generation (optional; skipped if missing), and
SonarQube Scanner (only when `sonar: true`). The quality gate needs the SonarQube webhook
pointing at `<jenkins>/sonarqube-webhook/`.

Pre-commit environments are cached under `.slsec-cache/` in the workspace. To keep them
between builds, use a persistent workspace or mount a shared cache. You can also set
`PRE_COMMIT_HOME` on the agent.
