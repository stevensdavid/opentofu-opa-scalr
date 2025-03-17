resource "aws_ecs_task_definition" "task" {
  family = "test-task"
  container_definitions = jsonencode([
    {
      name      = "ExampleContainerA"
      image     = "nginx:latest"
      essential = true
      // This is valid because it explicitly sets both privileged and root
      user       = "root"
      privileged = true
    },
    {
      name  = "ExampleContainerB"
      image = "alpine:latest"
      // This is invalid because it does not explicitly set privileged
      user = "root"
    }
  ])
  cpu          = 256
  memory       = 512
  network_mode = "host"
}
