resource "aws_rds_cluster" "missing_backtrack_window" {
  engine = "aurora-mysql"
}

resource "aws_rds_cluster" "missing_backtrack_window_engine_mode" {
  engine      = "aurora-mysql"
  engine_mode = each.value
  for_each    = toset(["provisioned", "parallelquery"])
}

resource "aws_rds_cluster" "zero_backtrack_window" {
  engine           = "aurora-mysql"
  backtrack_window = 0
}

resource "aws_rds_cluster" "zero_backtrack_window_engine_mode" {
  engine           = "aurora-mysql"
  engine_mode      = each.value
  backtrack_window = 0
  for_each         = toset(["provisioned", "parallelquery"])
}

resource "aws_rds_cluster" "old_serverlessv2_minor" {
  engine = "aurora-mysql"
  # The specification requires  'EngineVersion' provided is '8.0.mysql_aurora.3.02.0' or higher
  engine_version = "8.0.mysql_aurora.3.01.0"
  serverlessv2_scaling_configuration {
    min_capacity = 1
    max_capacity = 2
  }
}

resource "aws_rds_cluster" "old_serverlessv2_major" {
  engine = "aurora-mysql"
  # The specification requires  'EngineVersion' provided is '8.0.mysql_aurora.3.02.0' or higher
  engine_version = "5.7.mysql_aurora.3.02.0"
  serverlessv2_scaling_configuration {
    min_capacity = 1
    max_capacity = 2
  }
}
