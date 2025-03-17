resource "aws_ecs_task_definition" "valid" {
  memory = 512
  family = "valid"
  container_definitions = jsonencode([{
    essential = true
    image     = "nginx:latest"
    name      = "SampleContainer"
  }])
  pid_mode = "task"
}
