resource "aws_ses_domain_identity" "this" {
  domain = var.domain
}

resource "aws_ses_domain_dkim" "this" {
  domain = aws_ses_domain_identity.this.domain
}

resource "aws_ses_receipt_rule_set" "this" {
  rule_set_name = local.lampions_prefix
}

resource "aws_ses_receipt_rule" "this" {
  name          = local.lampions_prefix
  rule_set_name = aws_ses_receipt_rule_set.this.rule_set_name
  recipients    = [var.domain]
  enabled       = true
  scan_enabled  = false
  tls_policy    = "Optional"

  s3_action {
    position = 1
    bucket_name = aws_s3_bucket.this.bucket
    object_key_prefix = "inbox"
  }

  lambda_action {
    position = 2
    function_arn = aws_lambda_function.this.arn
    invocation_type = "Event"
  }
}
