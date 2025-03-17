resource "aws_rds_cluster" "missing_argument" {
  engine = "aurora-mysql"
}

resource "aws_rds_cluster" "disabled_iam_auth" {
  engine                              = "aurora-mysql"
  iam_database_authentication_enabled = false
}
