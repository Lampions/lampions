# Route user.
resource "aws_iam_user" "user" {
  name = "${local.lampions_prefix}RouteUser"
}

# Route user policy document.
data "aws_iam_policy_document" "route_user_policy_document" {
  statement {
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.bucket.arn]
  }

  statement {
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

# Bucket policy document.
data "aws_iam_policy_document" "bucket_policy_document" {
  statement {
    effect = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.bucket.arn}/inbox/*"]
    principals {
      type        = "Service"
      identifiers = ["ses.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:Referer"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Lambda role policy document.
data "aws_iam_policy_document" "lambda_role_policy_document" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.bucket.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.bucket.arn}/*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.bucket.arn}/recipients.json"]
  }
  statement {
    effect    = "Allow"
    actions   = ["ses:ListIdentities"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["ses:SendRawEmail"]
    resources = [aws_ses_domain_identity.domain.arn]
  }
}

# Lambda role policy.
data "aws_iam_policy_document" "lambda_role_policy" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
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
