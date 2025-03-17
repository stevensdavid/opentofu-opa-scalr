resource "aws_ecs_task_definition" "valid" {
  family = "valid"
  container_definitions = jsonencode([
    {
      name      = "ExampleContainerA"
      image     = "nginx:latest"
      essential = true
    },
    {
      name       = "ExampleContainerB"
      image      = "alpine:latest"
      privileged = false
    }
  ])
}
