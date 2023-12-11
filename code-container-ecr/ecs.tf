locals {
  image_repo_url = aws_ecr_repository.ecr_repo.repository_url
}

resource "aws_ecs_cluster" "project_ecs_cluster" {
  name = "${var.project_name}_ecs_cluster"
}
resource "aws_ecs_task_definition" "project_task_definition" {
  family                   = var.project_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  container_definitions = <<DEFINITION
[
  {
    "name": "${var.project_name}",
    "image": "${local.image_repo_url}:latest",
    "essential": true,
    "portMappings": [
      {
        "containerPort": 80,
        "hostPort": 80
      }
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "${aws_cloudwatch_log_group.project_cw_log_group.name}",
        "awslogs-region": "${local.region_name}",
        "awslogs-stream-prefix": "${var.project_name}"
      }
    }
  }
]
DEFINITION
  execution_role_arn = aws_iam_role.task_definition_role.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
}
resource "aws_cloudwatch_log_group" "project_cw_log_group" {
  name = "/ecs/${var.project_name}"
}
resource "aws_ecs_service" "project_ecs_service" {
  name            = var.project_name
  cluster         = aws_ecs_cluster.project_ecs_cluster.id
  task_definition = aws_ecs_task_definition.project_task_definition.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets         = aws_subnet.project_subnets.*.id
    security_groups = [aws_security_group.project_sg.id]
    assign_public_ip = true
  }
  load_balancer {
    target_group_arn =  aws_lb_target_group.project_lb_tg.0.arn
    container_name   = var.project_name
    container_port   = 80
  }
  deployment_controller {
    type = "CODE_DEPLOY"
  }
  depends_on = [aws_lb_listener.project_lb_listener]
}