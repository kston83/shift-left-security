# CI integration

Developers can skip hooks (`--no-verify`, or simply never running `pre-commit install`), so CI
runs the **same pinned hooks** over the whole repo, plus a full-history gitleaks scan. Provider
setup (Snyk, JFrog, SonarQube, Opengrep/Semgrep) is in [providers.md](providers.md).

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
    uses: kston83/shift-left-security/.github/workflows/slsec-reusable.yml@v0.2.0
    permissions:
      contents: read
      security-events: write
    secrets:                       # all optional; pass only what you use
      SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
    # with:
    #   fail-on-findings: false   # report-only while burning down a backlog
    #   upload-sarif: false       # private repo without GitHub Advanced Security
```

What it does:

1. Checks out the full history, without persisting credentials.
2. Runs `pre-commit run --all-files --hook-stage pre-commit` with `SLSEC_REPORT_DIR` set, so
   `slsec-checkov` and `slsec-sast` also write SARIF/JUnit. No secrets are exposed to this step.
3. Runs the **pre-push stage** (`--hook-stage pre-push`, the SCA hooks) over every manifest.
   Only this step receives `SNYK_TOKEN`, `JF_URL` and `JF_ACCESS_TOKEN`. This is the same
   pair of stages `slsec ci` runs.
4. Runs `gitleaks git` over the full history (pinned Docker image) and writes SARIF.
5. Uploads each SARIF file to code scanning in its own category (`slsec-checkov-terraform`,
   `slsec-checkov-dockerfile`, `slsec-sast`, `slsec-osv`, `slsec-snyk`, `slsec-jfrog`,
   `slsec-gitleaks`), skipping reports that weren't produced, and keeps the reports as an
   artifact.
6. Fails on secrets in history, and on hook failures unless `fail-on-findings: false`.

Hooks in `mode: warn` still exit 0, so findings show up in code scanning without failing the
build until the repo switches to `mode: block`.

### Inputs

| Input | Default | Notes |
|---|---|---|
| `python-version` | `3.12` | |
| `pre-commit-version` | `4.3.0` | |
| `gitleaks-version` | `8.30.1` | |
| `upload-sarif` | `true` | Needs GitHub Advanced Security on private repos |
| `fail-on-findings` | `true` | `false` = report only. Also stops a failed Sonar quality gate from failing the run |
| `strict` | `true` | Sets `SLSEC_STRICT`: a scanner that can't run (missing CLI or credentials, timeout, broken rules) fails instead of warning. Overrides `strict:` in `.slsec.yaml` |
| `install-jfrog-cli` | `false` | Installs `jf` (`jfrog/setup-jfrog-cli`) using `JF_URL` / `JF_ACCESS_TOKEN`, for `slsec-jfrog` |
| `sonarqube` | `false` | Adds the SonarQube job (scan + quality gate) |
| `sonar-args` | `""` | Extra scanner arguments, e.g. `-Dsonar.projectKey=my-project` |
| `sonar-project-base-dir` | `.` | `sonar.projectBaseDir` |

### Secrets (all optional)

| Secret | Used by | Without it |
|---|---|---|
| `SNYK_TOKEN` | pre-push step (`slsec-snyk`) | If the repo uses `slsec-snyk`, the step fails (`strict: true`, the default) or warns (`strict: false`) |
| `JF_URL`, `JF_ACCESS_TOKEN` | pre-push step (`slsec-jfrog`); `install-jfrog-cli` | Same |
| `SONAR_TOKEN`, `SONAR_HOST_URL` | Sonar job only | The Sonar scan fails (only runs when `sonarqube: true`) |

Don't use `secrets: inherit`; map the individual secrets as shown in
[examples/github-security.yml](../examples/github-security.yml).

### SonarQube in GitHub Actions

Set `sonarqube: true` and pass `SONAR_TOKEN` and `SONAR_HOST_URL`. A separate job (read-only
`contents` permission) checks out the full history, runs `SonarSource/sonarqube-scan-action`,
then `SonarSource/sonarqube-quality-gate-action`, which fails the job when the quality gate
fails. Both actions are pinned to a commit SHA.

**Build-step caveat.** The scan action runs the generic SonarScanner CLI. That works for
interpreted languages (JavaScript/TypeScript, Python, Go, PHP and so on). **Java and .NET need a
build-integrated scanner** because the analysis reads compiled classes and the build graph:

* Maven: `mvn -B verify sonar:sonar`; Gradle: `./gradlew build sonar`
* .NET: `dotnet sonarscanner begin` ... `dotnet build` ... `dotnet sonarscanner end`

Vendor docs: <https://docs.sonarsource.com/sonarqube-server/latest/analyzing-source-code/ci-integration/github-actions-for-sonarqube-server/>.
For those projects, keep (or write) your own build job with the build-integrated scanner and
leave `sonarqube: false` here; the quality gate is still the enforcement point. Where a
`sonarqube-scan-action` job already exists, keep it: there's no value in duplicating it.

## Jenkins / CloudBees CI

1. Register this repo as a **Global Trusted Pipeline Library** named `slsec`. Use Manage
   Jenkins > System, or in CloudBees CI the controller or Operations Center. Pin it to a tag.
2. In the Jenkinsfile:

```groovy
@Library('slsec@v0.2.0') _

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
| `strict` | `true` | Exports `SLSEC_STRICT`: a scanner that can't run fails instead of warning. Overrides `strict:` in `.slsec.yaml` |
| `gitleaks` | `true` | Full-history scan; needs a non-shallow checkout |
| `gitleaksBaseUrl` | GitHub releases | Point at an Artifactory generic remote for air-gapped agents |
| `python` | `python3` | Agent needs Python 3.9+, git, curl |
| `reportDir` | `slsec-reports` | JUnit + SARIF land here |
| `publish` | `true` | `junit` (doesn't change the build result) + Warnings NG `recordIssues(sarif)` with one tool id per scanner + archive |
| `snykTokenCredentialsId` | `null` | "Secret text" credential id, bound as `SNYK_TOKEN` around the pre-push stage only |
| `jfrogUrlCredentialsId` | `null` | Bound as `JF_URL` |
| `jfrogTokenCredentialsId` | `null` | Bound as `JF_ACCESS_TOKEN` |
| `sonar` | `[enabled: false]` | Map, see below. `sonar: true` still works |

`sonar` map keys:

| Key | Default | Notes |
|---|---|---|
| `enabled` | `false` | |
| `installation` | `SonarQube` | Server name configured in Jenkins (Manage Jenkins > System > SonarQube servers) |
| `command` | `sonar-scanner` | Use `./mvnw -B verify sonar:sonar`, `./gradlew build sonar`, or the .NET scanner begin/build/end for Java and .NET |
| `timeoutMinutes` | `10` | Quality-gate wait |
| `abortPipeline` | `failOnFindings` | Passed to `waitForQualityGate abortPipeline:` |

```groovy
slsecScan(
  snykTokenCredentialsId: 'snyk-token',
  jfrogUrlCredentialsId: 'jfrog-url',
  jfrogTokenCredentialsId: 'jfrog-access-token',
  sonar: [enabled: true, installation: 'SonarQube', command: './mvnw -B verify sonar:sonar'],
)
```

The step runs the pre-commit stage, then the pre-push stage (SCA), then gitleaks. The credential
bindings wrap only the pre-push stage, and a `null` id skips its binding, so the Snyk and JFrog
hooks warn and skip when unconfigured.

Published results: Warnings NG shows separate result sets with the ids `slsec-checkov-terraform`,
`slsec-checkov-dockerfile`, `slsec-sast`, `slsec-osv`, `slsec-snyk`, `slsec-jfrog` and
`slsec-gitleaks` (only for reports that exist).

Plugins used: Pipeline, Credentials Binding (only with credential ids), JUnit, Warnings Next
Generation (optional; skipped if missing), and SonarQube Scanner (only when Sonar is enabled).
`waitForQualityGate` needs the SonarQube webhook pointing at `<jenkins>/sonarqube-webhook/`;
without it the step waits until `timeoutMinutes`.

Pre-commit environments are cached under `.slsec-cache/` in the workspace. To keep them
between builds, use a persistent workspace or mount a shared cache. You can also set
`PRE_COMMIT_HOME` on the agent.
