output "region" {
  value = var.region
}

output "domain" {
  value = var.domain
}

output "access_key_id" {
  value = aws_iam_access_key.this.id
}

output "secret_access_key" {
  value     = aws_iam_access_key.this.secret
  sensitive = true
}

output "dkim_tokens" {
  value = aws_ses_domain_dkim.this.dkim_tokens
}
