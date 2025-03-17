resource "aws_ecs_task_definition" "invalid" {
  family = "invalid-because-missing-log-configuration"
  container_definitions = jsonencode([
    {
      name      = "ExampleContainerA",
      image     = "nginx:latest",
      essential = true
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
