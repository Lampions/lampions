resource "aws_ses_domain_identity" "domain" {
  domain = var.domain
}

resource "aws_ses_domain_dkim" "dkim" {
  domain = aws_ses_domain_identity.domain.domain
}

resource "aws_ses_receipt_rule_set" "rule_set" {
  rule_set_name = "${local.lampions_prefix}SesReceiptRuleSet"
}

resource "aws_ses_receipt_rule" "receipt_rule" {
  name          = "${local.lampions_prefix}SesReceiptRule"
  rule_set_name = aws_ses_receipt_rule_set.rule_set.rule_set_name
  recipients    = [var.domain]
  enabled       = true
  scan_enabled  = false
  tls_policy    = "Optional"

  s3_action {
    position = 1
    bucket_name = aws_s3_bucket.bucket.bucket
    object_key_prefix = "inbox"
  }

  lambda_action {
    position = 2
    function_arn = aws_lambda_function.lambda_function.arn
    invocation_type = "Event"
  }
}
