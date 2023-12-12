data "aws_iam_policy_document" "codebuild_service_assume_role" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "codebuild_service_role" {
  name = var.codebuild_service_role_name
  assume_role_policy = data.aws_iam_policy_document.codebuild_service_assume_role.json
}

data "aws_iam_policy_document" "codebuild_service_role_policy" {
  statement {
    sid     = "AccessToAWSCloudWatchLogs"
    effect  = "Allow"
    resources = ["arn:aws:logs:${local.region_name}:${local.account_id}:log-group:${var.codebuild_cloudwatch_logs_group_name}:*"]
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
  }
  statement {
    sid     = "AccessToAmazonECR"
    effect  = "Allow"
    resources = ["*"]
    actions = [
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:ListImages",
      "ecr:CompleteLayerUpload",
      "ecr:GetAuthorizationToken",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart"
    ]
  }
  statement {
    sid     = "AllowECRGetAuthToken"
    effect  = "Allow"
    resources = ["*"]
    actions = [
      "ecr:GetAuthorizationToken"
    ]
  }
  statement {
    sid     = "AllowGetTaskDefinition"
    effect  = "Allow"
    resources = ["*"]
    actions = [
      "ecs:DescribeTaskDefinition"
    ]
  }
  statement {
    sid     = "CodeBuildAccessToS3"
    effect  = "Allow"
    resources = [
      data.aws_s3_bucket.codepipeline_artifacts_s3_bucket.arn,
      "${data.aws_s3_bucket.codepipeline_artifacts_s3_bucket.arn}/*"
    ]
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetBucketVersioning",
      "s3:PutObjectAcl",
      "s3:PutObject"
    ]
  }
  statement {
    sid     = "CodeBuildAccesstoKMSCMK"
    effect  = "Allow"
    resources = [
      aws_kms_key.project_kms_key.arn
    ]
    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
      "kms:Encrypt",
      "kms:ReEncrypt*",
      "kms:Decrypt"
    ]
  }
}
resource "aws_iam_role_policy" "codebuild_service_role_policy" {
  role   = aws_iam_role.codebuild_service_role.name
  policy = data.aws_iam_policy_document.codebuild_service_role_policy.json
}

data "aws_iam_policy_document" "codepipeline_service_assume_role" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codepipeline.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "codepipeline_role" {
  name = var.codepipeline_role_name
  assume_role_policy = data.aws_iam_policy_document.codepipeline_service_assume_role.json
}

data "aws_iam_policy_document" "codepipeline_policy" {
  statement {
    sid     = "CodePipelineAccessToS3"
    effect  = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetBucketVersioning",
      "s3:PutObjectAcl",
      "s3:PutObject"
    ]
    resources = [
      data.aws_s3_bucket.codepipeline_artifacts_s3_bucket.arn,
      "${data.aws_s3_bucket.codepipeline_artifacts_s3_bucket.arn}/*"
    ]
  }
  statement {
    sid     = "CodePipelineAccesstoKMSCMK"
    effect  = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
      "kms:Encrypt",
      "kms:ReEncrypt*",
      "kms:Decrypt"
    ]
    resources = [aws_kms_key.project_kms_key.arn]
  }
  statement {
    sid     = "AccessToCodeCommitRepo"
    effect  = "Allow"
    actions = [
      "codecommit:GetBranch",
      "codecommit:GetCommit",
      "codecommit:UploadArchive",
      "codecommit:GetUploadArchiveStatus",
      "codecommit:GitPull"
    ]
    resources = [aws_codecommit_repository.code_repo.arn]
  }
  statement {
    sid     = "AllowCodeBuild"
    effect  = "Allow"
    actions = [
      "codebuild:BatchGetBuilds",
      "codebuild:StartBuild"
    ]
    resources = ["*"]
  }
  statement {
    sid     = "AllowCodeDeploy"
    effect  = "Allow"
    actions = [
      "codedeploy:CreateDeployment",
      "codedeploy:GetApplication",
      "codedeploy:GetApplicationRevision",
      "codedeploy:GetDeployment",
      "codedeploy:GetDeploymentConfig",
      "codedeploy:RegisterApplicationRevision"
    ]
    resources = ["*"]
  }
  statement {
    sid     = "AllowECS"
    effect  = "Allow"
    actions = [
      "ecs:*"
    ]
    resources = ["*"]
  }
  statement {
    sid     = "AllowPassRole"
    effect  = "Allow"
    actions = [
      "iam:PassRole"
    ]
    resources = ["*"]
  }
}
resource "aws_iam_role_policy" "codepipeline_policy" {
  name = var.codepipeline_role_policy_name
  role = aws_iam_role.codepipeline_role.id
  policy = data.aws_iam_policy_document.codepipeline_policy.json
}

data "aws_iam_policy_document" "cloudwatch_events_service_assume_role" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "cloudwatch_events_role" {
  name = var.cloudwatch_events_role_name
  assume_role_policy = data.aws_iam_policy_document.cloudwatch_events_service_assume_role.json
}

data "aws_iam_policy_document" "cloudwatch_events_policy" {
  statement {
    sid       = "CloudWatchPermissionToStartCodePipelinePipeline"
    effect    = "Allow"
    resources = [aws_codepipeline.imagebuild_pipeline.arn]
    actions = ["codepipeline:StartPipelineExecution"]
  }
}
resource "aws_iam_role_policy" "cloudwatch_events_policy" {
  name = var.cloudwatch_events_role_policy_name
  role = aws_iam_role.cloudwatch_events_role.id
  policy = data.aws_iam_policy_document.cloudwatch_events_policy.json
}

data "aws_iam_policy_document" "ecs_task_definition_service_assume_role" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "task_definition_role" {
  name = "${var.project_name}_task_definition"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_definition_service_assume_role.json
}

data "aws_iam_policy_document" "task_definition_policy" {
  statement {
    sid       = "AllowTaskDefinition"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetAuthorizationToken",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
  }
}
resource "aws_iam_role_policy" "task_definition_policy" {
  name = "${var.project_name}_task_definition_policy"
  role = aws_iam_role.task_definition_role.id
  policy = data.aws_iam_policy_document.task_definition_policy.json
}

data "aws_iam_policy_document" "codedeploy_assume_policy" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codedeploy.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "codedeploy" {
  name               = "codedeploy"
  assume_role_policy = data.aws_iam_policy_document.codedeploy_assume_policy.json
}

data "aws_iam_policy_document" "codedeploy" {
  statement {
    sid    = "AllowLoadBalancingAndECSModifications"
    effect = "Allow"
    actions = [
      "ecs:CreateTaskSet",
      "ecs:DeleteTaskSet",
      "ecs:DescribeServices",
      "ecs:UpdateServicePrimaryTaskSet",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyRule",
    ]
    resources = ["*"]
  }
  statement {
    sid    = "AllowS3"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetBucketVersioning",
      "s3:PutObjectAcl",
      "s3:PutObject"
    ]
    resources = ["${data.aws_s3_bucket.codepipeline_artifacts_s3_bucket.arn}/*"]
  }
  statement {
    sid    = "AllowKMS"
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
      "kms:Encrypt",
      "kms:ReEncrypt*",
      "kms:Decrypt"
    ]
    resources = [aws_kms_key.project_kms_key.arn]
  }
  statement {
    sid    = "AllowPassRole"
    effect = "Allow"
    actions = ["iam:PassRole"]
    resources = [aws_iam_role.task_definition_role.arn]
  }
}
resource "aws_iam_role_policy" "codedeploy" {
  role   = aws_iam_role.codedeploy.name
  policy = data.aws_iam_policy_document.codedeploy.json
}