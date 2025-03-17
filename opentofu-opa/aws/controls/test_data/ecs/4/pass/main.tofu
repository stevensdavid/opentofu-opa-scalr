resource "aws_ecs_task_definition" "valid" {
  family       = "valid"
  network_mode = "awsvpc"
  container_definitions = jsonencode([
    {
      name      = "ExampleContainerA",
      image     = "nginx:latest",
      essential = true
  }])
}
