resource "aws_kms_key" "project_kms_key" {
  description = "KMS key used by project CodePipeline pipeline"
}

resource "aws_codepipeline" "imagebuild_pipeline" {
  name     = var.codepipeline_pipeline_name
  role_arn = aws_iam_role.codepipeline_role.arn
  artifact_store {
    location = data.aws_s3_bucket.codepipeline_artifacts_s3_bucket.id
    type     = "S3"

    encryption_key {
      id   = aws_kms_key.project_kms_key.id
      type = "KMS"
    }
  }
  stage {
    name = "Source"
    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeCommit"
      version          = "1"
      output_artifacts = ["source_output"]

      configuration = {
        RepositoryName       = aws_codecommit_repository.code_repo.id
        BranchName           = "main"
        PollForSourceChanges = "false"
      }
    }
  }

  stage {
    name = "Build"

    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["source_output"]
      output_artifacts = ["build_output"]
      version          = "1"

      configuration = {
        ProjectName = aws_codebuild_project.project_codebuild.name
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "CodeDeployToECS"
      version         = "1"
      input_artifacts = ["build_output"]

      configuration = {
        ApplicationName                = aws_codedeploy_app.project_codedeploy.name
        DeploymentGroupName            = aws_codedeploy_deployment_group.project_codedeploy_dg.deployment_group_name
        TaskDefinitionTemplateArtifact = "build_output"
        AppSpecTemplateArtifact        = "build_output"
      }
    }
  }
}