resource "aws_ecs_service" "invalid" {
  name             = "invalid-service"
  launch_type      = "FARGATE"
  platform_version = "1.4.0"

  cluster         = var.cluster_id
  task_definition = var.task_definition_arn
  desired_count   = 0

  network_configuration {
    subnets          = var.subnet_ids
    assign_public_ip = false
  }
}
