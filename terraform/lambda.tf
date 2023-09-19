resource "random_uuid" "lambda_src_hash" {
  keepers = {
    for filename in setunion(
      fileset(local.root_dir, "pyproject.toml"),
      fileset(local.root_dir, "src/**/*.py"),
      fileset(local.root_dir, "**/*.tf"),
    ):
    filename => filesha256("${local.root_dir}/${filename}")
  }
}

resource "null_resource" "install_dependencies" {
  provisioner "local-exec" {
    command = "pip install -ut ${local.lambda_code_dir} ${local.root_dir}"
  }

  triggers = {
    source_code_hash = random_uuid.lambda_src_hash.result
  }
}

# Lambda function code.
data "archive_file" "lambda_function_code" {
  depends_on  = [null_resource.install_dependencies]
  type        = "zip"
  source_dir  = "${local.lambda_code_dir}"
  output_path = "${local.lambda_code_dir}.zip"
}

# Lambda function.
resource "aws_lambda_function" "lambda_function" {
  function_name    = "${local.lampions_prefix}LambdaFunction"
  filename         = "${local.lambda_code_dir}.zip"
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
