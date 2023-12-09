output "codecommit_repo_clone_url" {
  description = "AWS CodeCommit Repository Clone URL"
  value       = aws_codecommit_repository.code_repo.clone_url_http
}