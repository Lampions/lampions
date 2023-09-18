# Lambda role policy document.
data "aws_iam_policy_document" "lampions_lambda_role_policy_document" {
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
    resources = [aws_s3_bucket.lampions_s3_bucket.arn]
  }
  statement {
    sid       = "${local.lampions_prefix}LambdaFunctionS3GetBucket"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.lampions_s3_bucket.arn}/*"]
  }
  statement {
    sid       = "${local.lampions_prefix}LambdaFunctionS3WriteRecipients"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.lampions_s3_bucket.arn}/recipients.json"]
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
    resources = [aws_ses_domain_identity.lampions_ses_domain.arn]
  }
}

# Lambda role policy.
data "aws_iam_policy_document" "lampions_lambda_assume_role_policy" {
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
resource "aws_iam_role" "lampions_lambda_role" {
  name               = "${local.lampions_prefix}LambdaFunctionRole"
  assume_role_policy = data.aws_iam_policy_document.lampions_lambda_assume_role_policy.json
  inline_policy {
    name   = "${local.lampions_prefix}LambdaRolePolicy"
    policy = data.aws_iam_policy_document.lampions_lambda_role_policy_document.json
  }
}

data "template_file" "lambda" {
  template = file("${path.module}/../src/lampions/lambda.py")
}

data "template_file" "utils" {
  template = file("${path.module}/../src/lampions/utils.py")
}

# Lambda function code.
data "archive_file" "lampions_lambda_function_code" {
  type        = "zip"
  output_path = "lambda_function.zip"

  source {
    content  = data.template_file.lambda.rendered
    filename = "lambda.py"
  }

  source {
    content  = data.template_file.utils.rendered
    filename = "utils.py"
  }
}

# Lambda function.
resource "aws_lambda_function" "lampions_lambda_function" {
  function_name    = "${local.lampions_prefix}LambdaFunction"
  filename         = "lambda_function.zip"
  source_code_hash = data.archive_file.lampions_lambda_function_code.output_base64sha256
  role             = aws_iam_role.lampions_lambda_role.arn
  runtime          = "python3.11"
  handler          = "lambda.handler"

  environment {
    variables = {
      LAMPIONS_DOMAIN = "${var.domain}"
      LAMPIONS_REGION = "${var.region}"
    }
  }
}
