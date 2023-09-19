output "Region" {
  value = var.region
}

output "Domain" {
  value = var.domain
}

output "AccessKeyId" {
  value = aws_iam_access_key.access_key.id
}

output "SecretAccessKey" {
  value     = aws_iam_access_key.access_key.secret
  sensitive = true
}

output "DkimTokens" {
  value = aws_ses_domain_dkim.dkim.dkim_tokens
}
