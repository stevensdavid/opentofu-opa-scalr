resource "aws_ecs_task_definition" "valid" {
  family = "valid"
  container_definitions = jsonencode([{
    essential = true
    image     = "nginx:latest"
    name      = "SampleContainer"
    memory    = 256
  }])
}
