resource "aws_rds_cluster" "valid" {
  engine              = "aurora-mysql"
  deletion_protection = true
}
