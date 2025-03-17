resource "aws_ecs_task_definition" "valid" {
  family = "invalid"
  container_definitions = jsonencode([
    {
      name                   = "ExampleContainerA"
      image                  = "nginx:latest"
      essential              = true
      readonlyRootFilesystem = true
    },
    {
      name                   = "ExampleContainerB"
      image                  = "alpine:latest"
      readonlyRootFilesystem = true
    }
  ])
}
