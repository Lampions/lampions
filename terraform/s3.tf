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

# Bucket policy.
resource "aws_s3_bucket_policy" "bucket_policy" {
  bucket = aws_s3_bucket.bucket.id
  policy = data.aws_iam_policy_document.bucket_policy_document.json
}
