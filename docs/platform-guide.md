# Platform guide: rolling slsec out

For the platform or DevSecOps engineers who set slsec up for teams. This page covers the decisions
and the order to do things in, and links to [ci.md](ci.md) (CI wiring), [rollout.md](rollout.md)
(warn to block), [providers.md](providers.md) (Snyk, JFrog, SonarQube, engines) and the
[reference](reference.md) for detail.

## 1. Decide per repo (or per org)

| Decision | Options | Default | Guidance |
|---|---|---|---|
| Profiles | `terraform`, `docker`, `github-actions`, `jenkins`, `java`, `node`, `python`, `go`, `dotnet` (+ `base`, always) | auto-detected | Let `slsec init` detect them, then check the list. In CI, `require-profiles` pins the ones a repo must keep |
| SAST engine | `opengrep`, `semgrep`, `none` | `opengrep` | Opengrep needs no account and ships native Windows binaries. Semgrep CE if you already standardise on it ([providers.md](providers.md#sast-opengrep-default-or-semgrep-ce)) |
| SCA provider | `osv`, `snyk`, `jfrog`, `none` | `osv` for a new repo (v0.3.0: `none`) | osv-scanner needs no account. Snyk or JFrog where the org licenses them ([providers.md](providers.md)). Pass `--sca` explicitly so the result doesn't depend on the slsec version |
| `mode` | `warn`, `block` | `warn` | Start in `warn`; move to `block` once the backlog is burned down ([rollout.md](rollout.md)) |
| `strict` (laptops) | `true`, `false` | `false` | Leave `false` on laptops so an expired Snyk login doesn't stop work. CI is strict by default |

## 2. Add slsec to a repo

1. From the repo root, run the installer or `uvx` (see the [quick start](../README.md#quick-start)),
   naming the choices explicitly so the result doesn't depend on detection:

   ```sh
   uvx --from git+https://github.com/kston83/shift-left-security@v0.3.0 \
     slsec init --profile terraform,docker,python --sca osv --mode warn
   ```

2. Commit `.pre-commit-config.yaml`, `.slsec.yaml` and the tool configs `init` wrote
   (`.gitleaks.toml`, `.tflint.hcl`, `.hadolint.yaml`, `zizmor.yml`, `.groovylintrc.json`).
3. Add the CI job: GitHub Actions ([examples/github-security.yml](../examples/github-security.yml))
   or Jenkins ([examples/Jenkinsfile](../examples/Jenkinsfile)). Details in [ci.md](ci.md). If the
   repo has existing findings, start with `fail-on-findings: false` / `failOnFindings: false`.
4. Make the CI job a required status check on the default branch.
5. Add CODEOWNERS ([below](#3-protect-the-configuration)).
6. Tell the team: link the [developer guide](developer-guide.md). Warn them that the first commit
   on each machine downloads the scanners and takes several minutes.
7. Burn down, then enforce: [rollout.md](rollout.md).

**Without `slsec init`:** the hooks are ordinary pre-commit hooks, so you can wire them by hand.
You lose `.slsec.yaml` defaults, the tool configs and `slsec init --update`, and `slsec doctor` will
ask for the hooks each profile requires ([reference](reference.md#profiles-and-hooks)).

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/kston83/shift-left-security
    rev: v0.3.0
    hooks:
      - id: slsec-checkov
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks
```

## 3. Protect the configuration

The hook configuration lives in the repo, so a PR can try to weaken it. The CI setup gate
(`slsec doctor --ci`) catches the common ways (a missing or disabled required hook, a placeholder
exception reason, `mode: warn` when `require-mode: block` is set); the full list is in
[ci.md](ci.md#the-setup-gate-ci-cant-trust-the-prs-own-config). The gate is only as strong as the
CI definition that runs it, so:

1. **CODEOWNERS** with required review from the security owners on the CI definition and every
   file that changes what's enforced. Copy [examples/CODEOWNERS](../examples/CODEOWNERS).
2. **Set requirements in the CI definition**, not in `.slsec.yaml`: `require-mode: block` once the
   repo is enforcing, and `require-profiles` for profiles the repo must never drop.
3. **GitHub:** enforce the workflow from outside the repo with an organization ruleset ("require
   workflows to pass"), so a PR can't delete the job or change its inputs.
4. **Jenkins:** keep the Jenkinsfile under CODEOWNERS, load the library from the Global Trusted
   Pipeline Libraries (pinned to a tag), and consider a shared pipeline template where the repo
   can't edit the `slsecScan` call.

What each control does and doesn't stop is in the [security overview](security-overview.md).

## 4. Choose the CI requirements

| Repo state | GitHub Actions `with:` | Jenkins `slsecScan(...)` |
|---|---|---|
| New, or backlog not yet triaged | `fail-on-findings: false` | `failOnFindings: false` |
| Provider tokens not rolled out yet | `strict: false` | `strict: false` |
| Enforcing | `require-mode: block` | `requireMode: 'block'` |
| Must keep certain profiles | `require-profiles: terraform,docker` | `requireProfiles: 'terraform,docker'` |
| Hooks come from internal mirrors | `slsec-source`, `trusted-repos` | `slsecSource`, `trustedRepos` |

`enforce-setup: false` / `enforceSetup: false` turns the setup gate into a warning. Use it only
briefly, while fixing a repo that fails it.

## Internal mirrors and air-gapped networks

Everything slsec fetches, and how to point it somewhere else:

| What | Fetched by | From (default) | Redirect with |
|---|---|---|---|
| slsec itself (install, `uvx`) | developer, CI | `github.com/kston83/shift-left-security` | `SLSEC_SOURCE_URL` + `SLSEC_REV` for the install scripts; `slsec init --source-url`; CI `slsec-source` / `slsecSource` |
| Hook repos (pre-commit-hooks, gitleaks, hadolint-py, zizmor-pre-commit, actionlint, slsec) | pre-commit | GitHub | Mirror the git repos internally, change the `repo:` URLs in `.pre-commit-config.yaml` ([example](../examples/pre-commit-config.mirror.yaml)), list the mirrors in `trusted-repos` / `trustedRepos` |
| Python packages for hook environments (checkov, slsec's dependencies, semgrep) | pre-commit via pip | PyPI | `PIP_INDEX_URL` (or `pip.conf` / `pip.ini`) pointing at your PyPI remote |
| Go toolchain and tflint module | pre-commit | go.dev, proxy.golang.org | Install Go on the machine; `GOPROXY` pointing at your Go remote |
| Node and npm-groovy-lint | pre-commit | nodejs.org, npmjs.org | Install Node on the machine; `NPM_CONFIG_REGISTRY` pointing at your npm remote |
| opengrep binary (`slsec-sast`) | slsec | GitHub releases | `SLSEC_OPENGREP_PATH`, or pre-fill the cache: `python -m slsec.tools fetch` with `SLSEC_CACHE_DIR` |
| osv-scanner binary (`slsec-osv`) | slsec | GitHub releases | `osv-scanner` on `PATH`, `SLSEC_OSV_SCANNER_PATH`, or pre-fill the cache as above |
| Vulnerability data (`slsec-osv`) | osv-scanner | api.osv.dev | No offline option through the hook: on an air-gapped network use Snyk or JFrog against your internal platform, or `sca: none` |
| gitleaks for the full-history scan | CI | Docker Hub (GHA), GitHub releases (Jenkins) | GHA `gitleaks-image` (a mirror registry; keep the digest); Jenkins `gitleaksBaseUrl` (an Artifactory generic remote of the releases), or install that exact gitleaks version on the agent |
| Actions used by the reusable workflow | GitHub | github.com | GHES: sync the actions (all are pinned by SHA) |

Proxies: `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` are honoured by slsec's downloads, pre-commit,
pip and git.

Two things to know about mirrors and the setup gate:

* slsec's own hooks must come from `slsec-source` or a URL in `trusted-repos`. Every other required
  hook must come from its upstream or a URL in `trusted-repos`. URLs are compared without scheme,
  case, `.git` or a trailing `/`.
* Run `slsec doctor --ci --source-url <mirror> --trusted-repos <list>` locally to check a mirrored
  config before wiring CI. A failure looks like this:

  ```text
  [FAIL] required hook slsec-checkov is configured but disabled: it comes from `https://git.example.internal/mirrors/shift-left-security`, not https://github.com/kston83/shift-left-security (an internal mirror? pass it with --source-url in the CI definition)
  ```

Jenkins pipeline with mirrors and requirements: [examples/Jenkinsfile.enforced](../examples/Jenkinsfile.enforced).
GitHub Actions: [examples/github-security-enforced.yml](../examples/github-security-enforced.yml).

## Keeping repos current

* **Renovate** (recommended): the pre-commit manager is off by default, so enable it in each repo's
  `renovate.json`:

  ```json
  {
    "extends": ["config:recommended", "helpers:pinGitHubActionDigests"],
    "pre-commit": { "enabled": true },
    "minimumReleaseAge": "7 days"
  }
  ```

* **Without Renovate:** `slsec init --update` in each repo. It only raises pins (never lowers one),
  keeps comments and team edits, and keeps SHA-frozen repos frozen.
* **CI pin:** bump `@v0.3.0` in the workflow `uses:` / `@Library` line, and `slsec-version` /
  `slsecVersion` if you set them, together with the hook pin.
* Scanner upgrades can add blocking checks. slsec's release notes call them out; Renovate labels
  those PRs `policy-change` in this repo.

## Changing policy for everyone

The shared checkov baseline, gitleaks rules and rule packs live in this repo
(`src/slsec/configs/`). A change reaches a repo when it bumps its slsec pin. See
[CONTRIBUTING.md](../CONTRIBUTING.md#changing-policy).

## Where results go

* GitHub: code scanning alerts, one category per scanner, plus a `slsec-reports` artifact.
* Jenkins: Warnings NG (one result set per scanner), JUnit, archived `slsec-reports/`.
* File names and categories: [reference](reference.md#reports).
