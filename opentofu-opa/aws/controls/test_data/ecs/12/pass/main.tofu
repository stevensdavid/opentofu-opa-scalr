resource "aws_ecs_task_definition" "valid" {
  family = "valid"
  container_definitions = jsonencode([
    {
      name      = "ExampleContainerA"
      image     = "nginx:latest"
      essential = true
      secrets = [{
        name      = "AWS_ACCESS_KEY_ID"
        valueFrom = "arn:aws:ssm:eu-north-1:123456789012:parameter/example_parameter"
      }]
    },
    {
      name  = "ExampleContainerB"
      image = "alpine:latest"
    }
  ])
}
