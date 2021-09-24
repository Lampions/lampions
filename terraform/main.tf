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
