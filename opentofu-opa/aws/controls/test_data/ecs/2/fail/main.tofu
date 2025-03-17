resource "aws_ecs_cluster" "invalid" {
  name = "invalid-because-missing-container-insights"
}
