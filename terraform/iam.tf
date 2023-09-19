# Route user.
resource "aws_iam_user" "user" {
  name = "${local.lampions_prefix}RouteUser"
}

# Route user policy document.
data "aws_iam_policy_document" "route_user_policy_document" {
  statement {
    sid       = "${local.lampions_prefix}S3ListBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.bucket.arn]
  }

  statement {
    sid     = "${local.lampions_prefix}S3GetPutRoutes"
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:PutObject"]
    resources = [
      "${aws_s3_bucket.bucket.arn}/routes.json",
      "${aws_s3_bucket.bucket.arn}/recipients.json"
    ]
  }
}

# Route user policy.
resource "aws_iam_user_policy" "route_user_policy" {
  name   = "${local.lampions_prefix}RoutesAndRecipientsFilePolicy"
  user   = aws_iam_user.user.name
  policy = data.aws_iam_policy_document.route_user_policy_document.json
}

# Access key.
resource "aws_iam_access_key" "access_key" {
  user = aws_iam_user.user.name
}

# Lambda role policy document.
data "aws_iam_policy_document" "lambda_role_policy_document" {
  statement {
    sid    = "${local.lampions_prefix}LambdaFunctionCloudwatch"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["*"]
  }
  statement {
    sid       = "${local.lampions_prefix}LambdaFunctionS3ListBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.bucket.arn]
  }
  statement {
    sid       = "${local.lampions_prefix}LambdaFunctionS3GetBucket"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.bucket.arn}/*"]
  }
  statement {
    sid       = "${local.lampions_prefix}LambdaFunctionS3WriteRecipients"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.bucket.arn}/recipients.json"]
  }
  statement {
    sid       = "${local.lampions_prefix}LambdaFunctionSesListIdentities"
    effect    = "Allow"
    actions   = ["ses:ListIdentities"]
    resources = ["*"]
  }
  statement {
    sid       = "${local.lampions_prefix}LambdaFunctionSesSendMail"
    effect    = "Allow"
    actions   = ["ses:SendRawEmail"]
    resources = [aws_ses_domain_identity.domain.arn]
  }
}

# Lambda role policy.
data "aws_iam_policy_document" "lambda_role_policy" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

# Lambda role.
resource "aws_iam_role" "lambda_role" {
  name               = "${local.lampions_prefix}LambdaFunctionRole"
  assume_role_policy = data.aws_iam_policy_document.lambda_role_policy.json
  inline_policy {
    name   = "${local.lampions_prefix}LambdaRolePolicy"
    policy = data.aws_iam_policy_document.lambda_role_policy_document.json
  }
}
