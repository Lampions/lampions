output "access_key" {
  value = aws_iam_access_key.lampions_iam_route_user_access_key.id
}

output "secret_access_key" {
  value = aws_iam_access_key.lampions_iam_route_user_access_key.secret
  sensitive = true
}
