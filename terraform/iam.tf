# Route user.
resource "aws_iam_user" "this" {
  name = local.lampions_prefix
}

# Route user policy document.
data "aws_iam_policy_document" "user" {
  statement {
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.this.arn]
  }

  statement {
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:PutObject"]
    resources = [
      "${aws_s3_bucket.this.arn}/routes.json",
      "${aws_s3_bucket.this.arn}/recipients.json"
    ]
  }
}

# Route user policy.
resource "aws_iam_user_policy" "this" {
  name   = local.lampions_prefix
  user   = aws_iam_user.this.name
  policy = data.aws_iam_policy_document.user.json
}

# Access key.
resource "aws_iam_access_key" "this" {
  user = aws_iam_user.this.name
}

# Bucket policy document.
data "aws_iam_policy_document" "bucket" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/inbox/*"]
    principals {
      type        = "Service"
      identifiers = ["ses.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:Referer"
      values   = [data.aws_caller_identity.this.account_id]
    }
  }
}

# Lambda role policy document.
data "aws_iam_policy_document" "lambda" {
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
    resources = [aws_s3_bucket.this.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.this.arn}/*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/recipients.json"]
  }
  statement {
    effect    = "Allow"
    actions   = ["ses:ListIdentities"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["ses:SendRawEmail"]
    resources = [aws_ses_domain_identity.this.arn]
  }
}

# Lambda role policy.
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Lambda role.
resource "aws_iam_role" "this" {
  name               = local.lampions_prefix
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  inline_policy {
    name   = local.lampions_prefix
    policy = data.aws_iam_policy_document.lambda.json
  }
}
