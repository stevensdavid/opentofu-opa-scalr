resource "aws_rds_cluster" "valid" {
  engine                = "aurora-mysql"
  copy_tags_to_snapshot = true
}

resource "aws_rds_cluster" "unsupported_engine" {
  engine = "mysql"
}
