# S3 bucket for incoming emails and route aliases.
resource "aws_s3_bucket" "lampions_s3_bucket" {
  bucket = "lampions.${var.domain}"

  versioning {
    enabled = true
  }
}

# Bucket policy document.
data "aws_iam_policy_document" "lampions_s3_bucket_policy_document" {
  statement {
    sid    = "${local.lampions_prefix}SesS3Put"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ses.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.lampions_s3_bucket.arn}/inbox/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:Referer"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Bucket policy.
resource "aws_s3_bucket_policy" "lampions_s3_bucket_policy" {
  bucket = aws_s3_bucket.lampions_s3_bucket.id
  policy = data.aws_iam_policy_document.lampions_s3_bucket_policy_document.json
}
