# Changelog

## v0.2.0 (unreleased)

Phase 2: developers. SAST and dependency scanning for Java/Kotlin, JS/TS, Python, Go and .NET.

### Added
* **`slsec-sast` hook** (commit stage). It scans staged files with **Opengrep** (default) or
  **Semgrep CE** (`providers.sast_engine: semgrep`, needs Semgrep 1.120+ for Windows), using
  bundled rule packs chosen by file extension.
  * Opengrep v1.32.0 is downloaded on first use for the current OS/arch, checked against a
    SHA-256 baked into the package, and cached. Air-gapped installs can set
    `SLSEC_OPENGREP_PATH` and `SLSEC_CACHE_DIR`.
  * Repo exceptions go in `sast.exclude_rules`. Each needs a `reason` and can carry `expires`.
* **Rule packs** for java (45 rules), kotlin (6), javascript/TypeScript (16), python (84),
  go (13) and csharp (19).
  * Vendored unmodified from opengrep-rules at `f1d2b56`, under **LGPL-2.1 with the Commons
    Clause**. Licence and notice files are in `src/slsec/configs/sast-rules/`; the rest of
    slsec stays Apache-2.0.
  * `scripts/refresh-sast-rules.py` updates them from an allowlist.
* **Pre-push SCA hooks**: `slsec-osv` (osv-scanner v2.7.0; uses one on PATH, otherwise downloads
  a pinned copy), `slsec-snyk` (`snyk test`) and `slsec-jfrog` (`jf audit`).
  * They run only when a manifest or lockfile changes.
  * A missing CLI, missing login, timeout or tool error warns and lets the push through, unless
    strict mode is on.
* **Developer profiles**: `java`, `node`, `python`, `go` and `dotnet`. `slsec init` detects them.
* **`slsec init` options**:
  * `--sca {osv,snyk,jfrog,none}` adds the matching pre-push hook, and sets
    `default_install_hook_types: [pre-commit, pre-push]` so a plain `pre-commit install`
    installs both hooks.
  * `--sast-engine {opengrep,semgrep,none}`.
  * `--update` reads both settings back from `.slsec.yaml` and switches provider cleanly.
* **`slsec doctor`** checks the SCA provider's CLI and login (offline, warnings only) and
  whether the pre-push hook is installed. For language repos it recommends SonarQube for IDE
  in connected mode.
* **`SLSEC_STRICT`** environment variable. It overrides `strict:` in `.slsec.yaml` in both
  directions.
* **CI**: both templates now run the pre-push stage too, upload one SARIF report per scanner,
  take optional provider credentials, and offer an optional SonarQube scan with a quality gate.
* `docs/providers.md`: setup for Opengrep/Semgrep, osv-scanner, Snyk, JFrog and SonarQube.

### Changed
* **Python 3.11+ is required (breaking).** Python 3.9 and 3.10 are end-of-life. slsec's
  Python hooks (`slsec-checkov`, `slsec-sast`, `slsec-osv`, `slsec-snyk`, `slsec-jfrog`)
  install into pre-commit's own Python, so they fail to install if pre-commit runs on 3.9 or 3.10.
  Fix: install pre-commit with 3.11+ (`uv tool install pre-commit` picks one for you), or set
  `default_language_version: {python: python3.14}` in `.pre-commit-config.yaml`. This also
  removes the zizmor 3.11+ caveat.
  * Use 3.14. Python 3.15 isn't supported yet because checkov's dependencies have no 3.15 wheels;
    `slsec init` warns about it.
  * The reusable workflow's `python-version` default moves from 3.12 to 3.14.
  * The install scripts check for Python 3.11+ before falling back to pip.
* **Development uses uv:** `uv.lock`, `.python-version` (3.14), and a PEP 735 `dev` dependency
  group that replaces the `dev` extra. CI tests 3.11 and 3.14 on Linux, Windows and macOS.
* **Strict mode applies everywhere, and CI is strict by default.** Both CI templates set
  `SLSEC_STRICT=1` (GitHub `strict` input, Jenkins `strict` option, default `true`). In CI, a
  scanner that can't run now fails the build instead of quietly skipping the scan. "Can't run"
  covers a missing CLI or credentials, a timeout, and a failed download or broken rule. While
  rolling out provider tokens, pass `strict: false`.
* **Jenkins (breaking for dashboards):** `slsecScan` publishes one Warnings NG report per
  scanner, so the single `slsec` id is gone. The new ids are `slsec-checkov-terraform`,
  `slsec-checkov-dockerfile`, `slsec-sast`, `slsec-osv`, `slsec-snyk`, `slsec-jfrog` and
  `slsec-gitleaks`. The step now returns `[hooks, prePush, gitleaks]`.
* `strict:` in `.slsec.yaml` must be a real boolean. A quoted `"false"` used to count as true;
  it is now a configuration error.

## v0.1.0 (2026-11-08)

First release, phase 1: IaC / DevOps.

* `slsec-checkov` hook: Terraform/OpenTofu (directory-level scan with variable resolution)
  and Dockerfile scanning with a shared baseline policy; `warn`/`block` modes; repo
  exceptions with required reasons and optional expiry; SARIF/JUnit reports for CI.
* `slsec init` / `doctor` / `ci` CLI with profiles: `base`, `terraform`, `docker`,
  `github-actions`, `jenkins`.
* gitleaks policy with extra rules for AI agent / MCP config files.
* Reusable GitHub Actions workflow and Jenkins shared-library step (`slsecScan`).
