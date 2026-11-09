# Security overview

For security and audit reviewers. It covers what slsec enforces and where, who can change what,
what each hook does and doesn't cover, how CI stops a PR from weakening its own checks, and where
the evidence ends up. Mapping to the OWASP DevSecOps Guideline: [owasp-mapping.md](owasp-mapping.md).

## Model

slsec runs the same pinned scanners in two places:

| Where | Purpose | Can the developer skip it? |
|---|---|---|
| Git hooks on the laptop (pre-commit, pre-push) | Fast feedback on the change being made; stops most secrets before they enter history | Yes: `--no-verify`, `SKIP`, uninstalling the hooks. This is by design |
| CI (GitHub Actions reusable workflow, Jenkins `slsecScan()`, or `slsec ci`) | Enforcement: the same hooks over the whole repo, gitleaks over the full history, a setup gate, reports | No, if the CI definition is protected (below) |

Local hooks fail open: a scanner that can't run warns and lets the commit through, unless the repo
sets `strict: true`. CI fails closed: the templates set `SLSEC_STRICT=1` by default, so a missing
token or broken scanner fails the build.

## Trust boundaries

| Controlled by | What | Protection |
|---|---|---|
| The PR author | `.pre-commit-config.yaml`, `.slsec.yaml`, tool configs (`.gitleaks.toml`, `.gitleaksignore`, `.hadolint.yaml`, `.tflint.hcl`, `zizmor.yml`, `.groovylintrc.json`), inline suppressions, and the CI definition file in the repo (`.github/workflows/*.yml`, `Jenkinsfile`) | Setup gate (partial, below) + CODEOWNERS review |
| The CI definition | slsec version used for the gate, `require-mode`, `require-profiles`, `trusted-repos`, `strict`, `fail-on-findings`, `enforce-setup` | CODEOWNERS on the file; a GitHub organization ruleset requiring the workflow; Jenkins trusted library pinned to a tag |
| The slsec release (this repo, at a tag) | The list of required hooks per profile, the disarming checks, the checkov baseline, gitleaks rules, SAST rule packs, scanner pins | Code review in this repo; tags; consumers pin a tag or a SHA |
| The organization | Rulesets, branch protection, Jenkins global library config, mirrors | Platform admin access |

## The setup gate

`slsec doctor --ci` runs in CI **before** the hooks. It is installed from the pinned slsec release
(`slsec-version` / `slsecVersion` from `slsec-source`), not from the PR, and reads its requirements
from the CI definition. It fails the build when:

* a required hook for a profile in `.slsec.yaml` or `require-profiles` is missing (the
  [list](reference.md#profiles-and-hooks));
* a required hook is switched off: `stages` that leave out its stage, a `default_stages` that does
  the same, `language: fail`, an `entry` override, `pass_filenames: false`, `--mode warn`, or
  arguments that stop it ever failing (gitleaks `--exit-code 0`, hadolint `--no-fail` or
  `--failure-threshold none`, zizmor `--no-exit-codes`, npm-groovy-lint `--failon none`,
  `slsec-sast --rules-dir`);
* a required hook is redefined as a `repo: local` hook (tflint and npm-groovy-lint, which are local
  by design, must still run their tool), or comes from a repo other than its upstream, the slsec
  source, or a `trusted-repos` URL;
* `SKIP` in CI's environment names a required hook;
* an exception in `.slsec.yaml` has a placeholder reason;
* `.slsec.yaml` doesn't set the mode named in `require-mode`;
* `.slsec.yaml` is invalid.

It prints warnings (not failures) for `exclude`, `files`, `types`, `types_or` and `exclude_types`
on required hooks, a top-level `exclude`, gitleaks pointed at another `--config` or a
`--baseline-path`, and profile files present in the repo but not enabled. Excluding generated code
is legitimate, so these need a reviewer.

Real output against a deliberately weakened config:

```text
$ slsec doctor --ci --require-mode block
slsec doctor (0.3.0) for /work/weak
  [ok]   .pre-commit-config.yaml present
  [ok]   secret scanning (gitleaks) hook configured
  [ok]   slsec hooks pinned at v0.3.0
  [ok]   settings: mode=warn (.slsec.yaml)
  [FAIL] required hook gitleaks / gitleaks-system / gitleaks-docker is configured but disabled: `--exit-code 0` never fails
  [FAIL] required hook detect-private-key is configured but disabled: `stages: ['manual']` makes it manual-only
  [FAIL] required hook slsec-checkov is configured but disabled: it comes from `https://git.example.internal/mirrors/shift-left-security`, not https://github.com/kston83/shift-left-security (an internal mirror? pass it with --source-url in the CI definition)
  [warn] slsec-checkov has `exclude: ^infra/legacy/`: those paths are not scanned (review the pattern)
  [FAIL] required hook slsec-sast is configured but disabled: it comes from `https://git.example.internal/mirrors/shift-left-security`, not https://github.com/kston83/shift-left-security (an internal mirror? pass it with --source-url in the CI definition)
  [warn] found docker files but those profiles aren't enabled in .slsec.yaml; run `slsec init --update --profile ...` (or require them in CI with --require-profiles)
  [FAIL] mode is 'warn' but this pipeline requires 'block' (set `mode: block` in .slsec.yaml)
  [FAIL] checkov.skip_checks CKV_AWS_18: reason 'x' is a placeholder; explain why the exception is acceptable

6 failure(s), 2 warning(s)
```

Each failure and its fix: [troubleshooting.md](troubleshooting.md#setup-gate-failures).

### What the gate doesn't check

* **The contents of the tool configs.** A PR can edit `.gitleaks.toml` (drop `useDefault`, add a
  path allowlist), `.gitleaksignore`, `.hadolint.yaml` (`failure-threshold`), `zizmor.yml`,
  `.tflint.hcl` or `.groovylintrc.json`, and the CI full-history gitleaks scan also reads the
  repo's `.gitleaks.toml`. These files need CODEOWNERS review.
* **The CI definition itself.** If a PR can edit the workflow or Jenkinsfile and merge without
  security review, it can change the gate's inputs or drop the job. Protect it with CODEOWNERS and,
  on GitHub, an organization ruleset.
* **Inline suppressions in code.** `checkov:skip=` needs a real reason (the hook enforces it in
  `mode: block`), but `nosemgrep`, `tflint-ignore`, `hadolint ignore`, `zizmor: ignore` and
  `gitleaks:allow` aren't checked for a reason. Review them like code.
* **Whether a mode or profile is right for the repo**, unless the CI definition says so with
  `require-mode` / `require-profiles`.

## Coverage

| Hook | Covers | Doesn't cover |
|---|---|---|
| gitleaks | Secrets in the staged diff (commit) and in every commit in history (CI): gitleaks' default rules plus slsec rules for AI agent and MCP config files ([ai-agents.md](ai-agents.md)) | Secrets that match no rule; whether a secret is live (no verification); secrets in history that the PR's `.gitleaks.toml` or `.gitleaksignore` allowlists |
| `detect-private-key` | PEM-style private key blocks in staged files | Keys in other encodings |
| `slsec-checkov` | Terraform (each directory holding a staged file, local module calls resolved) and Dockerfiles, against checkov's policies minus the [shared baseline](../src/slsec/configs/checkov/baseline.yaml) skips | OpenTofu `.tofu` files (reported, not scanned); remote modules (not downloaded); Kubernetes, Helm, CloudFormation, ARM/Bicep (checkov supports them, the hook doesn't send them); drift from what's deployed |
| tflint | Terraform errors with the built-in `recommended` preset | Provider-specific rules (cloud rulesets are opt-in) |
| hadolint | Dockerfile best practice; error severity blocks | Image contents and CVEs |
| zizmor, actionlint | GitHub Actions: injection, dangerous triggers, excessive permissions, unpinned actions, persisted credentials; workflow syntax | Actions' own code; runner hardening |
| npm-groovy-lint | Jenkinsfiles and shared-library Groovy (CodeNarc), errors block | Jenkins controller configuration |
| `slsec-sast` | Bundled Opengrep/Semgrep rule packs (about 180 rules) for Java, Kotlin, JS/TS, Python, Go and C#: injection, weak crypto, unsafe deserialization, XXE, JWT misuse, SSRF. Staged files at commit, every file in CI | Data flow across files or functions in other files; languages without a pack; business logic. Deep SAST belongs in SonarQube or CodeQL in CI |
| `slsec-osv` / `-snyk` / `-jfrog` | Known vulnerabilities in dependencies declared in manifests and lockfiles: at push when a manifest changes, all manifests in CI | Licence policy (the osv hook doesn't pass `--licenses`); vendored or copied code; container images. osv needs network access to api.osv.dev |

Not covered by slsec at all: DAST, container image scanning, runtime and cloud posture, commit
signing. See the roadmap in [tool-selection.md](tool-selection.md#roadmap).

## How slsec's own dependencies are pinned

| Component | Pin |
|---|---|
| Hook repos in `.pre-commit-config.yaml` | Tag; `slsec init --freeze` pins commit SHAs (`# frozen: <tag>`) |
| checkov in `slsec-checkov` | Exact version in `.pre-commit-hooks.yaml` |
| opengrep, osv-scanner binaries | Exact version and SHA-256 per platform built into slsec; the cached copy is re-hashed before every use. (An `osv-scanner` already on `PATH` is used as-is) |
| SAST rule packs | Vendored in this repo, unmodified from opengrep-rules at a recorded commit |
| gitleaks in GitHub Actions | Docker image pinned by digest |
| gitleaks in Jenkins | Release version, download checked against the release checksums file; a copy on the agent's `PATH` is used only if it reports that version |
| Actions in the reusable workflow | Commit SHA |
| slsec in CI's setup gate | Release tag (`slsec-version`) |
| Updates | Renovate, with a 7-day minimum release age; scanner bumps are labelled `policy-change` and never auto-merged |

A tag can be moved by whoever controls the upstream repo. Where that matters, freeze to SHAs
(`slsec init --freeze`) and mirror the repos internally.

## Evidence

| Platform | Where |
|---|---|
| GitHub Actions | Code scanning alerts, one category per scanner (`slsec-checkov-terraform`, `slsec-checkov-dockerfile`, `slsec-sast`, `slsec-osv`, `slsec-snyk`, `slsec-jfrog`, `slsec-gitleaks`); the `slsec-reports` workflow artifact with every SARIF and JUnit file; the job log, including the setup gate's output |
| Jenkins | Warnings NG result sets with the same ids; JUnit results; archived `slsec-reports/`; the console log |
| `slsec ci` | `slsec-reports/` (or `--report-dir`); publish it with your CI system |

Retention follows the platform's settings for artifacts and logs. Code scanning keeps alert
history. File names: [reference](reference.md#reports).

## Exceptions and their audit trail

Every exception has a reason, and the narrowest scope wins ([suppressions.md](suppressions.md)):

* inline next to the code (reviewed in the PR diff);
* repo-wide in `.slsec.yaml`, with an optional `expires` date after which the check runs again
  (CODEOWNERS review; placeholder reasons fail the setup gate);
* org-wide in the shared baseline in this repo (PR review here; called out in release notes).

Leaked secrets aren't suppressed: the credential is rotated first.
