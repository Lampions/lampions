output "Region" {
  value = var.region
}

output "Domain" {
  value = var.domain
}

output "AccessKeyId" {
  value = aws_iam_access_key.lampions_iam_route_user_access_key.id
}

output "SecretAccessKey" {
  value = aws_iam_access_key.lampions_iam_route_user_access_key.secret
  sensitive = true
}

output "DkimTokens" {
  value = aws_ses_domain_dkim.lampions_ses_domain_dkim.dkim_tokens
}
