# AWS DevOps Pipeline - CodeCommit, CodeBuild, CodeDeploy, CodePipeline, EventBridge and ECS Fargate

### TL,DR;
This project is part of my studies to get the AWS DevOps Professional Certification. Here, I used some AWS DevOps services (CodeCommit, CodeBuild, CodeDeploy, CodePipeline) and an ECS Fargate cluster to create a CI/CD pipeline build and deploy a simple Hugo static HTML page.
The AWS resources are being created by Terraform.

### Terraform code will create:

1. CodeCommit Repository to store the application code
2. EventBridge Rule to trigger CodePipeline 
3. CodePipeline containing the CodeCommit, CodeBuild and CodeDeploy integration
4. CodeBuild to build the application container image
5. CodeDeploy to deploy the application image to a ECS Cluster
6. ECS Cluster in Fargate mode to run the application
7. IAM Roles to give permissions between the resources