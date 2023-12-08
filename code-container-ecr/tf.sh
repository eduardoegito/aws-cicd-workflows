#!/bin/bash

command=$1
PROJECT_NAME=$2
ENV=$3

TF_VAR_env = ${ENV}
TF_VAR_codecommit_repo_name = ${PROJECT_NAME}_${ENV}
TF_VAR_ecr_repo_name = ${PROJECT_NAME}_${ENV}
TF_VAR_codebuild_project_name = ${PROJECT_NAME}_${ENV}_imagebuild
TF_VAR_codebuild_service_role_name = ${PROJECT_NAME}-${ENV}-codebuild-service-role
TF_VAR_codepipeline_pipeline_name = ${PROJECT_NAME}_${ENV}_imagebuild_pipeline
TF_VAR_codepipeline_role_name = ${PROJECT_NAME}_${ENV}_codepipeline_role
TF_VAR_codepipeline_role_policy_name = ${TFVAR_codepipeline_role_name}_policy
TF_VAR_cloudwatch_events_role_name = ${PROJECT_NAME}_${ENV}_cloudwatch_events_role
TF_VAR_cloudwatch_events_role_policy_name = ${TFVAR_cloudwatch_events_role_name}_policy
TF_VAR_cloudwatch_events_rule_name = ${PROJECT_NAME}_${ENV}_trigger_imagebuild_pipeline
TF_VAR_codebuild_cloudwatch_logs_group_name = ${PROJECT_NAME}_${ENV}_imagebuildloggroup
TF_VAR_codebuild_cloudwatch_logs_stream_name = ${PROJECT_NAME}_${ENV}_imagebuildlogstream

case ${command} in
    plan )
       terraform init 
       terraform plan -no-color -var-file=./terraform-${TF_VAR_env}.tfvars -out latest-${TF_VAR_env}.plan
       ;;
    apply )
       terraform init 
       terraform apply -no-color latest-${TF_VAR_env}.plan
       rm latest-${TF_VAR_env}.plan
       ;;
    init )
       terraform init 
       ;;
    destroy )
       terraform init
       terraform destroy -auto-approve -no-color -var-file=./terraform-${TF_VAR_env}.tfvars
       ;;
    show )
       terraform init
       terraform show -no-color latest-${TF_VAR_env}.plan
       ;;
    nothing )
      echo "nothing done"
      ;;
    * )
       terraform ${command} -no-color
       ;;
esac