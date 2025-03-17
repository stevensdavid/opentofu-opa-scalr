resource "aws_rds_cluster" "missing_deletion_protection" {
  engine = "aurora-mysql"
}

resource "aws_rds_cluster" "disabled_deletion_protection" {
  engine              = "aurora-mysql"
  deletion_protection = false
}
