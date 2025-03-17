resource "aws_ecs_task_definition" "valid" {
  memory = 512
  family = "example"
  container_definitions = jsonencode([
    {
      essential = true,
      name      = "ExampleContainerA",
      image     = "nginx:latest",
      user      = "exampleuser",
      memory    = 256
    },
    {
      name  = "ExampleContainerB",
      image = "alpine:latest",
      user  = "exampleuser",
    }
  ])
}
