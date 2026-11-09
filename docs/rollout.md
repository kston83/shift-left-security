# Rolling out: warn to block

Security tooling that blocks on day one gets disabled on day two. slsec defaults to a gradual
rollout.

| Step | What | Who |
|---|---|---|
| 1. Install | `slsec init` (mode `warn`). Secrets block immediately; IaC/lint findings are printed but don't block | Team |
| 2. Add CI | Reusable workflow / `slsecScan()`; set `fail-on-findings: false` / `failOnFindings: false` if existing hooks fail on legacy code | Team + DevSecOps |
| 3. Burn down | Fix findings, or add inline suppressions with reasons. Reports in code scanning / Warnings NG show the backlog | Team |
| 4. Enforce | Set `mode: block` in `.slsec.yaml`; turn CI `fail-on-findings` back on | Team |
| 5. Keep current | Renovate (or `slsec init --update`) bumps `rev`; read the release notes for new blocking rules | Team |

## Tips

* **Legacy repos with secrets in history:** the commit hook only scans *staged* changes, so
  old findings don't block developers. The CI full-history scan does report them. Rotate,
  then add the rotated fingerprints to `.gitleaksignore`.
* **First run is slow.** pre-commit downloads and builds the scanners once per machine,
  then caches them.
* **Monorepos:** `slsec-checkov` scans only the directories that hold staged files.
* **Measure adoption:** run `slsec doctor --ci` in pipelines to fail builds that have
  dropped the hooks or fallen far behind on `rev`.
