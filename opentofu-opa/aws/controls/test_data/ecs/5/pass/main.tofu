resource "aws_ecs_task_definition" "valid" {
  family = "valid"
  container_definitions = jsonencode([
    {
      name      = "ExampleContainerA",
      image     = "nginx:latest",
      essential = true
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          "awslogs-group"         = "example",
          "awslogs-region"        = "eu-north-1",
          "awslogs-stream-prefix" = "container-a"
        }
      }
    },
    {
      name  = "ExampleContainerB",
      image = "alpine:latest",
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          "awslogs-group"         = "example",
          "awslogs-region"        = "eu-north-1",
          "awslogs-stream-prefix" = "container-b"
        }
      }
  }])
}
