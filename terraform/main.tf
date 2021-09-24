# Terraform configuration.
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
  type        = string
  description = "AWS region"

  validation {
    condition     = contains(["eu-west-1", "us-east-1", "us-west-2"], var.region)
    error_message = "Supported AWS regions are eu-west-1, us-east-1 and us-west-2."
  }
}

variable "domain" {
  type        = string
  description = "Root domain"
}

# Local variables.
locals {
  lampions_prefix = format("Lampions%s", join("", [for part in split(".", var.domain) : title(part)]))
}

provider "aws" {
  profile = "default"
  region  = var.region
}

data "aws_caller_identity" "current" {}

# S3 bucket for incoming emails and route aliases.
resource "aws_s3_bucket" "lampions_s3_bucket" {
  bucket = "lampions.${var.domain}"

  versioning {
    enabled = true
  }
}

# Bucket policy.
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

resource "aws_s3_bucket_policy" "lampions_s3_bucket_policy" {
  bucket = aws_s3_bucket.lampions_s3_bucket.id
  policy = data.aws_iam_policy_document.lampions_s3_bucket_policy_document.json
}
