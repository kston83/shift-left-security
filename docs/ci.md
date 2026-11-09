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
    uses: kston83/shift-left-security/.github/workflows/slsec-reusable.yml@v0.3.0
    permissions:
      contents: read
      security-events: write
    secrets:                       # all optional; pass only what you use
      SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
    # with:
    #   fail-on-findings: false   # report-only while burning down a backlog
    #   upload-sarif: false       # private repo without GitHub Advanced Security
    #   require-mode: block       # once the repo has finished rolling out
    #   require-profiles: terraform,python
```

What it does:

1. Checks out the full history, without persisting credentials.
2. Runs **`slsec doctor --ci`** from the pinned slsec release (the setup gate, below).
3. Runs `pre-commit run --all-files --hook-stage pre-commit` with `SLSEC_REPORT_DIR` set, so
   `slsec-checkov` and `slsec-sast` also write SARIF/JUnit. No secrets are exposed to this step.
4. Runs the **pre-push stage** (`--hook-stage pre-push`, the SCA hooks) over every manifest.
   Only this step receives `SNYK_TOKEN`, `JF_URL` and `JF_ACCESS_TOKEN`. This is the same
   pair of stages `slsec ci` runs.
5. Runs `gitleaks git` over the full history (Docker image pinned by digest) and writes SARIF.
6. Uploads each SARIF file to code scanning in its own category (`slsec-checkov-terraform`,
   `slsec-checkov-dockerfile`, `slsec-sast`, `slsec-osv`, `slsec-snyk`, `slsec-jfrog`,
   `slsec-gitleaks`), skipping reports that weren't produced, and keeps the reports as an
   artifact.
7. Fails on secrets in history, on a failed setup gate unless `enforce-setup: false`, and on
   hook failures unless `fail-on-findings: false`.

### The setup gate: CI can't trust the PR's own config

The hooks run from the PR branch, so a PR can change what CI enforces: delete a hook, set
`mode: warn`, or add an exception with the reason "x". `slsec doctor --ci` checks the PR's
`.pre-commit-config.yaml` and `.slsec.yaml` against policy that the PR doesn't control (the slsec
release pinned by `slsec-version`, and this job's inputs). It fails when:

* a **required hook** is missing for a profile in `.slsec.yaml` or `require-profiles`:
  gitleaks and `detect-private-key` always; `slsec-checkov` for terraform/docker; hadolint;
  zizmor; npm-groovy-lint; `slsec-sast` for the language profiles; the configured SCA hook;
* a required hook is present but **switched off**: `stages` that leave out its stage,
  `entry`/`language: fail` overrides, `pass_filenames: false`, `--mode warn` in `args`,
  arguments that stop it ever failing (gitleaks `--exit-code 0`, hadolint `--no-fail`, zizmor
  `--no-exit-codes`, npm-groovy-lint `--failon none`, `slsec-sast --rules-dir`), or listed in `SKIP`;
* a required hook **comes from somewhere else**: redefined as a `repo: local` hook, or pulled from
  a repo other than its upstream (slsec's own hooks: `slsec-source`). Internal mirrors are
  accepted when listed in `trusted-repos` (`trustedRepos` in Jenkins); that list applies to every
  required hook, slsec's own included;
* an exception in `.slsec.yaml` has a **placeholder reason** ("x", "TODO", "n/a", under 10
  characters);
* `.slsec.yaml` doesn't set the mode named in `require-mode`.

`exclude:` / `files:` / `types:` overrides on required hooks, gitleaks pointed at another
`--config` or a `--baseline-path`, and profiles whose files exist but aren't enabled, are printed
as warnings to review: excluding generated code is legitimate.

This only helps if the CI definition itself is protected. The gate also doesn't read the tool
configs (`.gitleaks.toml`, `.hadolint.yaml`, …), and the full-history gitleaks scan uses the repo's
`.gitleaks.toml` and `.gitleaksignore`. Put the workflow, the config files and the suppression files
under **CODEOWNERS** with required reviews from the security owners
([examples/CODEOWNERS](../examples/CODEOWNERS)):

```text
# .github/CODEOWNERS
/.github/workflows/       @your-org/appsec
/Jenkinsfile              @your-org/appsec
/.pre-commit-config.yaml  @your-org/appsec
/.slsec.yaml              @your-org/appsec
/.gitleaks.toml           @your-org/appsec
/.gitleaksignore          @your-org/appsec
/.hadolint.yaml           @your-org/appsec
/.tflint.hcl              @your-org/appsec
/zizmor.yml               @your-org/appsec
/.groovylintrc.json       @your-org/appsec
```

Better still, enforce the workflow from outside the repo with an organization ruleset
("require workflows to pass"), so a PR can't remove the job or change its inputs.

Hooks in `mode: warn` still exit 0, so findings show up in code scanning without failing the
build until the repo switches to `mode: block`.

### Inputs and secrets

Every input and secret, with defaults, is in the
[reference](reference.md#github-actions-reusable-workflow). The ones teams change most:

* `fail-on-findings: false` while burning down a backlog ([rollout.md](rollout.md)).
* `require-mode: block` and `require-profiles` once a repo has finished rolling out.
* `slsec-source` and `trusted-repos` for internal mirrors ([platform guide](platform-guide.md#internal-mirrors-and-air-gapped-networks)).
* `strict: false` while provider tokens are being rolled out.
* `upload-sarif: false` on private repos without GitHub Advanced Security.

Secrets are all optional. Don't use `secrets: inherit`; map the individual secrets as shown in
[examples/github-security.yml](../examples/github-security.yml). A stricter setup with mirrors is
in [examples/github-security-enforced.yml](../examples/github-security-enforced.yml).

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
@Library('slsec@v0.3.0') _

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

Every option and `sonar` map key, with defaults, is in the
[reference](reference.md#jenkins-slsecscan). The agent needs Python 3.11+, git and curl, and the
checkout must not be shallow (the gitleaks scan reads the full history). A pipeline with setup-gate
requirements and internal mirrors is in [examples/Jenkinsfile.enforced](../examples/Jenkinsfile.enforced).
For Java and .NET, set `sonar.command` to the build-integrated scanner (`./mvnw -B verify sonar:sonar`,
`./gradlew build sonar`, or the .NET scanner begin/build/end).

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

## Other CI systems

`slsec ci` runs the setup gate, then both hook stages over the whole repo, and writes the same
reports (flags in the [reference](reference.md#slsec-ci)):

```sh
python -m venv /tmp/slsec && /tmp/slsec/bin/pip install pre-commit==4.3.0 \
  "slsec @ git+https://github.com/kston83/shift-left-security@v0.3.0"
PATH="/tmp/slsec/bin:$PATH" slsec ci --require-mode block
```

Install slsec from a pinned tag in the pipeline definition, not from the repo under test, so the
change being tested can't edit its own gate. `slsec ci` doesn't run the full-history gitleaks scan
or upload reports; add `gitleaks git . --redact --report-format sarif --report-path
slsec-reports/gitleaks.sarif` and your system's SARIF/JUnit publishing.
