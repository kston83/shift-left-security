# Rolling out: warn to block

Security tooling that blocks on day one gets disabled on day two. slsec defaults to a gradual
rollout.

| Step | What | Who |
|---|---|---|
| 1. Install | `slsec init` (mode `warn`). Secrets block immediately; IaC/lint findings are printed but don't block | Team |
| 2. Add CI | Reusable workflow / `slsecScan()`; set `fail-on-findings: false` / `failOnFindings: false` if existing hooks fail on legacy code | Team + DevSecOps |
| 3. Burn down | Fix findings, or add inline suppressions with reasons. Reports in code scanning / Warnings NG show the backlog | Team |
| 4. Enforce | Set `mode: block` in `.slsec.yaml`; turn CI `fail-on-findings` back on; set `require-mode: block` in the CI job so a later PR can't quietly go back to `warn` | Team + DevSecOps |
| 5. Protect | CODEOWNERS on the CI workflow / Jenkinsfile, `.pre-commit-config.yaml`, `.slsec.yaml`, `.gitleaks.toml` and `.gitleaksignore` (see [ci.md](ci.md#the-setup-gate-ci-cant-trust-the-prs-own-config)) | DevSecOps |
| 6. Keep current | Renovate (or `slsec init --update`) bumps `rev`; read the release notes for new blocking rules | Team |

## Tips

* **Legacy repos with secrets in history:** the commit hook only scans *staged* changes, so
  old findings don't block developers. The CI full-history scan does report them. Rotate,
  then add the rotated fingerprints to `.gitleaksignore`.
* **First run is slow.** pre-commit downloads and builds the scanners once per machine,
  then caches them.
* **Monorepos:** `slsec-checkov` scans only the directories that hold staged files, without
  recursing: staging a root-level `.tf` file scans the root directory, not the whole repo.
  Files that the repo's pre-commit `exclude:` filters out are skipped even when they sit next
  to a staged file. (Resources pulled in through a `module` block from a staged directory are
  still evaluated, with the inputs that directory passes.)
* **OpenTofu:** checkov doesn't read `.tofu` files yet. `slsec-checkov` reports them as not
  scanned (and fails under `strict`); keep resources you want policy-checked in `.tf` files.
* **The setup gate is built in:** the reusable workflow, `slsecScan()` and `slsec ci` run
  `slsec doctor --ci`, which fails when a required hook is missing or switched off, an
  exception has a placeholder reason, or `require-mode` / `require-profiles` aren't met.
  It also warns when `rev` falls behind.
* **Pins:** `slsec init --update` only moves a pin forward, so it doesn't fight Renovate, and
  it keeps your comments and formatting. `slsec init --freeze` pins every hook repo to the
  commit SHA behind its tag (`rev: <sha>  # frozen: v1.2.3`, the `pre-commit autoupdate
  --freeze` format).
