resource "aws_ecs_task_definition" "invalid" {
  family = "invalid-because-missing-network-mode"
  container_definitions = jsonencode([
    {
      name      = "ExampleContainerA",
      image     = "nginx:latest",
      essential = true
  }])
}
