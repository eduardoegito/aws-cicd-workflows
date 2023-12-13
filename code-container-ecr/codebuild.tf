resource "aws_codebuild_project" "project_codebuild" {
  name          = var.codebuild_project_name
  description   = "AWS CodeBuild Project to build the container image"
  build_timeout = "5"
  service_role  = aws_iam_role.codebuild_service_role.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }
  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = true

    environment_variable {
      name  = "AWS_REGION"
      value = local.region_name
    }

    environment_variable {
      name  = "AWS_ACCOUNT_ID"
      value = local.account_id
    }

    environment_variable {
      name  = "ECR_REPO_NAME"
      value = aws_ecr_repository.ecr_repo.name
    }
    environment_variable {
      name  = "IMAGE_TAG_PREFIX"
      value = var.image_tag_prefix
    }
    environment_variable {
      name  = "PROJECT_NAME"
      value = var.project_name
    }

    environment_variable {
      name  = "TASK_DEFINITION"
      value = "arn:aws:ecs:${local.region_name}:${local.account_id}:task-definition/${aws_ecs_task_definition.project_task_definition.family}"
    }

    environment_variable {
      name  = "CONTAINER_NAME"
      value = var.project_name
    }

    environment_variable {
      name  = "SUBNET_1"
      value = aws_subnet.project_subnets.*.id[0]
    }

    environment_variable {
      name  = "SUBNET_2"
      value = aws_subnet.project_subnets.*.id[1]
    }

    environment_variable {
      name  = "SUBNET_3"
      value = aws_subnet.project_subnets.*.id[2]
    }

    environment_variable {
      name  = "SECURITY_GROUP"
      value = aws_security_group.project_sg.id
    }
  }

  logs_config {
    cloudwatch_logs {
      group_name  = var.codebuild_cloudwatch_logs_group_name
      stream_name = var.codebuild_cloudwatch_logs_stream_name
    }
  }

  source {
    type            = "CODECOMMIT"
    location        = aws_codecommit_repository.code_repo.clone_url_http
    git_clone_depth = 1

    git_submodules_config {
      fetch_submodules = true
    }
  }

  tags = {
    Environment = var.env
  }
}
