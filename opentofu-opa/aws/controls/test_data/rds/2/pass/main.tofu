resource "aws_db_instance" "valid" {
  allocated_storage           = 5
  engine                      = "postgres"
  manage_master_user_password = true
  instance_class              = "db.t2.micro"
  username                    = "foo"
  monitoring_interval         = 30
  monitoring_role_arn         = "arn:aws:iam::123456789012:role/monitoring-role"
}

resource "aws_db_instance" "valid_custom" {
  allocated_storage           = 5
  engine                      = "custom-sqlserver-ee"
  manage_master_user_password = true
  instance_class              = "db.t2.micro"
  username                    = "foo"
  # no monitoring_interval but it's fine since this is custom
}
