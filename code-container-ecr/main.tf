data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_s3_bucket" "codepipeline_artifacts_s3_bucket" {
  bucket = var.codepipeline_artifacts_s3_bucket_name
}


resource "aws_ecr_repository" "ecr_repo" {
  name                 = var.ecr_repo_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_cloudwatch_event_rule" "trigger_image_build" {
  name        = var.cloudwatch_events_rule_name
  description = "Trigger the CodePipeline pipline to build the image for hugo whenever a new push is made to hugo CodeCommit repository"

  event_pattern = <<PATTERN
{
  "source": [ 
    "aws.codecommit"
  ],
  "detail-type": [
    "CodeCommit Repository State Change"
  ],
  "resources": [ 
    "${aws_codecommit_repository.code_repo.arn}"
  ],
  "detail": {
    "event": [
      "referenceCreated",
      "referenceUpdated"
    ],
    "referenceType": [
        "branch"
    ],
    "referenceName": [
      "main"
    ]
  }
}
PATTERN
}

resource "aws_cloudwatch_event_target" "trigger_image_build" {
  target_id = "trigger_image_build"
  rule      = aws_cloudwatch_event_rule.trigger_image_build.id
  arn       = aws_codepipeline.imagebuild_pipeline.arn

  role_arn = aws_iam_role.cloudwatch_events_role.arn
}