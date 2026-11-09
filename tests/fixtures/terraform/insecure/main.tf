# Intentionally insecure Terraform: used to prove slsec-checkov catches findings.
# Do not copy this into real infrastructure.

variable "allowed_cidr" {
  type    = string
  default = "0.0.0.0/0"
}

resource "aws_security_group" "ssh_open" {
  name        = "ssh-open"
  description = "SSH open to the world"

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }
}

resource "aws_s3_bucket" "public" {
  bucket = "slsec-fixture-public"
}

resource "aws_s3_bucket_public_access_block" "public" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
