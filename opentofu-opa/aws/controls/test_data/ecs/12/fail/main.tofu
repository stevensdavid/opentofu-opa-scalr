resource "aws_ecs_task_definition" "invalid" {
  family = "invalid"
  container_definitions = jsonencode([{
    name      = "ExampleContainerA"
    image     = "nginx:latest"
    essential = true
    environment = [
      {
        name  = "AWS_ACCESS_KEY_ID"
        value = "exampleKey"
      },
      {
        name  = "AWS_SECRET_ACCESS_KEY"
        value = "exampleSecret"
      }
    ]
    },
    {
      name  = "ExampleContainerB"
      image = "alpine:latest"
    }
  ])
}
