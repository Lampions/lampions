resource "aws_ses_domain_identity" "lampions_ses_domain" {
  domain = var.domain
}

resource "aws_ses_domain_dkim" "lampions_ses_domain_dkim" {
  domain = aws_ses_domain_identity.lampions_ses_domain.domain
}
