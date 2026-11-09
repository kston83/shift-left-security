# Suppressions and exceptions

Every exception needs a **reason** a reviewer can evaluate. Prefer the narrowest scope.

## 1. Inline, next to the code (preferred)

**checkov** (Terraform / Dockerfile):

```hcl
resource "aws_s3_bucket" "logs" {
  # checkov:skip=CKV_AWS_18: this IS the access-log bucket; logging to itself would loop
  bucket = "org-access-logs"
}
```

```dockerfile
# checkov:skip=CKV_DOCKER_3: distroless base image already runs as nonroot
FROM gcr.io/distroless/static:nonroot
```

`slsec-checkov` checks every `checkov:skip=` in the files it scans: one without a reason, or
with a placeholder ("x", "TODO", "n/a", "false positive", anything under 10 characters), is
reported and fails the hook in `mode: block`. Inline skips have no expiry; use an
`.slsec.yaml` exception with `expires` for anything temporary.

**SAST** (`slsec-sast`, Opengrep or Semgrep): a `nosemgrep` comment with the rule id, on the
finding's line or the line before it:

```python
subprocess.call(cmd, shell=True)  # nosemgrep: python.lang.security.audit.subprocess-shell-true -- cmd is a constant list built above
```

Always name the rule id: a bare `# nosemgrep` silences every rule on that line. The hook doesn't
check `nosemgrep` reasons (only `checkov:skip=` reasons are checked), so reviewers have to.

**tflint**: `# tflint-ignore: terraform_unused_declarations # reason`

**hadolint**: `# hadolint ignore=DL3008` on the line before the instruction.

**zizmor**: `# zizmor: ignore[unpinned-uses] reason` at the end of the line.

## 2. Repo-wide, in `.slsec.yaml`

Use this when a check doesn't apply to the whole repo:

```yaml
checkov:
  skip_checks:
    - id: CKV_AWS_18
      reason: "access logs shipped by the central logging account (ticket SEC-123)"
      expires: 2027-06-30   # optional; after this date the check is enforced again
```

* `reason` is required. The hook fails with a configuration error without it, and
  `slsec doctor --ci` (the CI setup gate) fails on placeholder reasons such as "x" or "TODO".
* Once `expires` passes, the exception stops applying, and `slsec doctor` and the hook both
  say so.
* `enable_checks: [ID]` turns back on a check the shared baseline skips.

SAST rules work the same way, under `sast.exclude_rules`, by rule id:

```yaml
sast:
  exclude_rules:
    - id: python.lang.security.audit.subprocess-shell-true
      reason: "build tooling only; every command is a constant from tools/commands.py (SEC-207)"
      expires: 2027-03-31
```

The reason rules (what counts as a placeholder) are in
[troubleshooting.md](troubleshooting.md#suppressions-need-a-real-reason). Every key is in the
[reference](reference.md#slsecyaml).

## 3. Org-wide, in the baseline

`src/slsec/configs/checkov/baseline.yaml` in this repo. Changes reach every repo when it bumps
`rev`, so open a PR and call it out in the release notes.

## Secrets (gitleaks)

Leaked secrets aren't "suppressed": **rotate the credential first**. Removing it from git
history doesn't revoke it. Then:

* A false positive on a specific line: add `gitleaks:allow` in a comment on that line.
* A test fixture: add a path allowlist to `.gitleaks.toml`:

  ```toml
  [[allowlists]]
  description = "synthetic test data"
  paths = ['''^tests/fixtures/''']
  ```

* A finding already in history that was rotated: add its fingerprint to `.gitleaksignore`.
