resource "aws_ecs_task_definition" "invalid" {
  family = "invalid-because-missing-memory"
  container_definitions = jsonencode([{
    essential = true
    image     = "nginx:latest"
    name      = "SampleContainer"
  }])
}
