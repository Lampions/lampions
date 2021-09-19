terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }

  required_version = ">= 0.14.9"
}

# External variable definitions.
variable "region" {
  type = string
  description = "AWS region"

  validation {
    condition = contains(["eu-west-1", "us-east-1", "us-west-2"], var.region)
    error_message = "Supported AWS regions are eu-west-1, us-east-1 and us-west-2."
  }
}

variable "domain" {
  type = string
}

# Local variables.
locals {
  lampions_prefix = join("", [for part in split(".", var.domain) : title(part)])
}

provider "aws" {
  profile = "default"
  region  = var.region
}

# S3 bucket for incoming emails and route aliases.
resource "aws_s3_bucket" "lampions_s3_bucket" {
  bucket = "lampions.${var.domain}"

  versioning {
    enabled = true
  }
}

# Bucket policy.
resource "aws_s3_bucket_policy" "lampions_s3_bucket_policy" {
  bucket = aws_s3_bucket.lampions_s3_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "${local.lampions_prefix}SesS3Put"
        Effect = "Allow"
        Principal = {
          Service = "ses.amazonaws.com"
        }
        Action = "s3:PutObject"
        Resource = [
          aws_s3_bucket.lampions_s3_bucket.arn,
          "${aws_s3_bucket.lampions_s3_bucket.arn}/inbox/*",
        ]
        Condition = {
          StringEquals = {
            "aws:Referer" = aws_s3_bucket.lampions_s3_bucket.arn
          }
        }
      }
    ]
  })
}
