# Bucket for incoming emails and route aliases.
resource "aws_s3_bucket" "bucket" {
  bucket = "lampions.${var.domain}"
}

# Bucket versioning.
resource "aws_s3_bucket_versioning" "bucket_versioning" {
  bucket = aws_s3_bucket.bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Bucket policy document.
data "aws_iam_policy_document" "bucket_policy_document" {
  statement {
    sid    = "${local.lampions_prefix}SesS3Put"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ses.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.bucket.arn}/inbox/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:Referer"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Bucket policy.
resource "aws_s3_bucket_policy" "bucket_policy" {
  bucket = aws_s3_bucket.bucket.id
  policy = data.aws_iam_policy_document.bucket_policy_document.json
}
