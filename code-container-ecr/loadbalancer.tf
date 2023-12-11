locals {
  target_groups = [
    "green",
    "blue",
  ]
}

resource "aws_security_group" "project_sg" {
  name   = "allow-http"
  vpc_id = aws_vpc.project_vpc.id

  ingress {
    from_port   = 80
    protocol    = "tcp"
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow-http-sg"
  }
}

resource "aws_lb" "project_lb" {
  name               = "project-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.project_sg.id]
  subnets            = aws_subnet.project_subnets.*.id

  tags = {
    Name = "project-loadbalancer"
  }
}

resource "aws_lb_target_group" "project_lb_tg" {
  count = length(local.target_groups)
  name = "project-tg-${element(local.target_groups, count.index)}"

  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.project_vpc.id
  target_type = "ip"

  health_check {
    path = "/"
    port = 80
  }
}

resource "aws_lb_listener" "project_lb_listener" {
  load_balancer_arn = aws_lb.project_lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.project_lb_tg.*.arn[0]
  }
}

resource "aws_lb_listener_rule" "project_lb_lr" {
  listener_arn = aws_lb_listener.project_lb_listener.arn

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.project_lb_tg.*.arn[0]
  }

  condition {
    path_pattern {
      values = ["/*"]
    }
  }
}