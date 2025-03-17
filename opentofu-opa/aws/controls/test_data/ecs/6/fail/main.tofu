resource "aws_ecs_task_definition" "invalid" {
  family = "invalid"
  container_definitions = jsonencode([
    {
      name      = "ExampleContainerA"
      image     = "nginx:latest"
      essential = true
    },
    {
      name                   = "ExampleContainerB"
      image                  = "alpine:latest"
      readonlyRootFilesystem = false
    }
  ])
}
