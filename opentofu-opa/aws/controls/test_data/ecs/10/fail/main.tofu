resource "aws_ecs_task_definition" "invalid" {
  memory = 512
  family = "invalid-because-host-pid"
  container_definitions = jsonencode([{
    essential = true
    image     = "nginx:latest"
    name      = "SampleContainer"
  }])
  pid_mode = "host"
}
