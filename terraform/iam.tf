# Route user.
resource "aws_iam_user" "lampions_iam_route_user" {
  name = "${local.lampions_prefix}RouteUser"
}

# Route user policy document.
data "aws_iam_policy_document" "lampions_iam_route_user_policy_document" {
  statement {
    sid       = "${local.lampions_prefix}S3ListBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.lampions_s3_bucket.arn]
  }

  statement {
    sid     = "${local.lampions_prefix}S3GetPutRoutes"
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:PutObject"]
    resources = [
      "${aws_s3_bucket.lampions_s3_bucket.arn}/routes.json",
      "${aws_s3_bucket.lampions_s3_bucket.arn}/recipients.json"
    ]
  }
}

# Route user policy.
resource "aws_iam_user_policy" "lampions_iam_route_user_policy" {
  user   = aws_iam_user.lampions_iam_route_user.name
  policy = data.aws_iam_policy_document.lampions_iam_route_user_policy_document.json
}

# Access key.
resource "aws_iam_access_key" "lampions_iam_route_user_access_key" {
  user   = aws_iam_user.lampions_iam_route_user.name
}
