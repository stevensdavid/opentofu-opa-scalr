resource "aws_ecs_service" "valid_default" {
  name        = "example-service"
  launch_type = "FARGATE"

  cluster         = var.cluster_id
  task_definition = var.task_definition_arn
  desired_count   = 0

  network_configuration {
    subnets          = var.subnet_ids
    assign_public_ip = false
  }
}

resource "aws_ecs_service" "valid_explicit" {
  name             = "example-service"
  launch_type      = "FARGATE"
  platform_version = "LATEST"

  cluster         = var.cluster_id
  task_definition = var.task_definition_arn
  desired_count   = 0

  network_configuration {
    subnets          = var.subnet_ids
    assign_public_ip = false
  }
}
