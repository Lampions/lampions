resource "null_resource" "install_dependencies" {
  provisioner "local-exec" {
    command = "pip install -t ${local.root_dir}/lambda_code ${local.root_dir}"
  }
}

# Lambda function code.
data "archive_file" "lambda_function_code" {
  depends_on  = [null_resource.install_dependencies]
  type        = "zip"
  source_dir  = "${local.root_dir}/lambda_code"
  output_path = "${local.root_dir}/lambda_code.zip"
}

# Lambda function.
resource "aws_lambda_function" "lambda_function" {
  function_name    = "${local.lampions_prefix}LambdaFunction"
  filename         = "${local.root_dir}/lambda_code.zip"
  source_code_hash = data.archive_file.lambda_function_code.output_base64sha256
  role             = aws_iam_role.lambda_role.arn
  runtime          = "python3.11"
  handler          = "lampions.lambda_function.handler"

  environment {
    variables = {
      LAMPIONS_DOMAIN = "${var.domain}"
      LAMPIONS_REGION = "${var.region}"
    }
  }
}

# Lambda function invocation permission.
resource "aws_lambda_permission" "allow_ses" {
  statement_id  = "${local.lampions_prefix}SesLambdaInvokeFunction"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function.function_name
  principal     = "ses.amazonaws.com"
}
