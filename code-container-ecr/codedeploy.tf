resource "aws_codedeploy_app" "project_codedeploy" {
  compute_platform = "ECS"
  name             = var.project_name
}

resource "aws_codedeploy_deployment_group" "project_codedeploy_dg" {
  app_name               = aws_codedeploy_app.project_codedeploy.name
  deployment_group_name  = "${var.project_name}-deploy-group"
  deployment_config_name = "CodeDeployDefault.ECSAllAtOnce"
  service_role_arn       = aws_iam_role.codedeploy.arn

  blue_green_deployment_config {
    deployment_ready_option {
      action_on_timeout = "CONTINUE_DEPLOYMENT"
    }

    terminate_blue_instances_on_deployment_success {
      action = "TERMINATE"
    }
  }

  ecs_service {
    cluster_name = aws_ecs_cluster.project_ecs_cluster.name
    service_name = aws_ecs_service.project_ecs_service.name
  }

  deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type   = "BLUE_GREEN"
  }

  load_balancer_info {
    target_group_pair_info {
      prod_traffic_route {
        listener_arns = [aws_lb_listener.project_lb_listener.arn]
      }

      target_group {
        name = aws_lb_target_group.project_lb_tg.*.name[0]
      }

      target_group {
        name = aws_lb_target_group.project_lb_tg.*.name[1]
      }
    }
  }
}