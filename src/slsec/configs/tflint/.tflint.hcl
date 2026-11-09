# slsec tflint config. Copied to the repo root by `slsec init`.
# The terraform ruleset is built into tflint, so no `tflint --init` or network access is needed.

config {
  call_module_type = "local"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

# Cloud rulesets catch provider-specific mistakes (invalid instance types, etc.).
# They are opt-in because they need `tflint --init` (network + GitHub API).
#
# plugin "aws" {
#   enabled = true
#   version = "0.40.0"
#   source  = "github.com/terraform-linters/tflint-ruleset-aws"
# }
