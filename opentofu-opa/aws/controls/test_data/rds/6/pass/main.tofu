resource "aws_rds_cluster" "unsupported_engine" {
  engine = "aurora-postgresql"
}

resource "aws_rds_cluster" "unsupported_engine_mode" {
  engine      = "aurora-mysql"
  engine_mode = "serverless"
}

resource "aws_rds_cluster" "new_serverlessv2" {
  engine         = "aurora-mysql"
  engine_version = "8.0.mysql_aurora.3.03.0"
  serverlessv2_scaling_configuration {
    min_capacity = 1
    max_capacity = 2
  }
}

resource "aws_rds_cluster" "valid_backtrack" {
  engine           = "aurora-mysql"
  backtrack_window = 1
}

resource "aws_rds_cluster" "valid_backtrack_engine_mode" {
  engine           = "aurora-mysql"
  engine_mode      = each.value
  backtrack_window = 1
  for_each         = toset(["provisioned", "parallelquery"])
}
