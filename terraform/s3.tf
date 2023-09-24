# Bucket for incoming emails and route aliases.
resource "aws_s3_bucket" "this" {
  bucket = local.lampions_prefix
}

# Bucket versioning.
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Bucket policy.
resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.bucket.json
}
