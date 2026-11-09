# Changelog

## v0.1.0 (unreleased)

First release, phase 1: IaC / DevOps.

* `slsec-checkov` hook: Terraform/OpenTofu (directory-level scan with variable resolution)
  and Dockerfile scanning with a shared baseline policy; `warn`/`block` modes; repo
  exceptions with required reasons and optional expiry; SARIF/JUnit reports for CI.
* `slsec init` / `doctor` / `ci` CLI with profiles: `base`, `terraform`, `docker`,
  `github-actions`, `jenkins`.
* gitleaks policy with extra rules for AI agent / MCP config files.
* Reusable GitHub Actions workflow and Jenkins shared-library step (`slsecScan`).
