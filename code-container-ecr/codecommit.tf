resource "aws_codecommit_repository" "code_repo" {
  repository_name = var.codecommit_repo_name
  description     = "The AWS CodeCommit repository where the code to build the container will be stored."
  default_branch  = var.codecommit_repo_default_branch_name
}