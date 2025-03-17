resource "aws_ecs_cluster" "valid" {
  name = "valid"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}
