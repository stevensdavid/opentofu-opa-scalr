resource "aws_rds_cluster" "missing_argument" {
  engine = "aurora-mysql"
}

resource "aws_rds_cluster" "disabled" {
  engine                = "aurora-mysql"
  copy_tags_to_snapshot = false
}
