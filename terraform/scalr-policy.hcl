version = "v1"

policy "all_aws_controls" {
  enabled = true
  # Only warn, this can still be bypassed by anyone
  enforcement_level = "advisory"
}

policy "aws_high_severity" {
  enabled = true
  # Require approval from a user with policy-checks:override
  enforcement_level = "soft-mandatory"
}
