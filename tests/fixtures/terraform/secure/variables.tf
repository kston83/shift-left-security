# Kept in a separate file on purpose: slsec-checkov scans the whole directory,
# so checkov can resolve these values when evaluating main.tf.
variable "block_public_access" {
  type    = bool
  default = true
}

variable "log_bucket_name" {
  type    = string
  default = "slsec-fixture-access-logs"
}

variable "kms_key_arn" {
  type    = string
  default = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"
}
