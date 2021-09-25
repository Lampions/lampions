# Lambda role policy document.
data "aws_iam_policy_document" "lampions_lambda_role_policy_document" {
  statement {
    sid    = "${local.lampions_prefix}LambdaFunctionCloudwatch"
    effect = "Allow"
    actions   = [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"]
    resources = ["*"]
  }
  statement {
    sid    = "${local.lampions_prefix}LambdaFunctionS3ListBucket"
    effect = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.lampions_s3_bucket.arn]
  }
  statement {
    sid    = "${local.lampions_prefix}LambdaFunctionS3GetBucket"
    effect = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.lampions_s3_bucket.arn}/*"]
  }
  statement {
    sid    = "${local.lampions_prefix}LambdaFunctionS3WriteRecipients"
    effect = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.lampions_s3_bucket.arn}/recipients.json"]
  }
  statement {
    sid    = "${local.lampions_prefix}LambdaFunctionSesListIdentities"
    effect = "Allow"
    actions   = ["ses:ListIdentities"]
    resources = ["*"]
  }
  statement {
    sid    = "${local.lampions_prefix}LambdaFunctionSesSendMail"
    effect = "Allow"
    actions   = ["ses:SendRawEmail"]
    resources = [aws_ses_domain_identity.lampions_ses_domain.arn]
  }
}

# Lambda role policy.
resource "aws_iam_policy" "lampions_lambda_role_policy" {
  name = "${local.lampions_prefix}LambdaRolePolicy"
  policy = data.aws_iam_policy_document.lampions_lambda_role_policy_document.json
}
