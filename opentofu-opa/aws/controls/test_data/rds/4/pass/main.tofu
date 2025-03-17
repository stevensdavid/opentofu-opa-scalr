resource "aws_rds_cluster" "enabled_iam_auth" {
  engine                              = "aurora-mysql"
  iam_database_authentication_enabled = true
}

resource "aws_rds_cluster" "unsupported_engine" {
  engine = "mysql"
}
