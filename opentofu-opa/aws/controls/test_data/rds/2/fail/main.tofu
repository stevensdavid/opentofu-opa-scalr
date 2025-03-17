resource "aws_db_instance" "invalid" {
  allocated_storage           = 5
  engine                      = "postgres"
  manage_master_user_password = true
  instance_class              = "db.t2.micro"
  username                    = "foo"
  monitoring_interval         = 0
}

resource "aws_db_instance" "invalid_missing_interval" {
  allocated_storage           = 5
  engine                      = "postgres"
  manage_master_user_password = true
  instance_class              = "db.t2.micro"
  username                    = "foo"
}

resource "aws_db_instance" "invalid_missing_monitoring_role" {
  allocated_storage           = 5
  engine                      = "postgres"
  manage_master_user_password = true
  instance_class              = "db.t2.micro"
  username                    = "foo"
  monitoring_interval         = 15
}

resource "aws_db_instance" "invalid_empty_monitoring_role" {
  allocated_storage           = 5
  engine                      = "postgres"
  manage_master_user_password = true
  instance_class              = "db.t2.micro"
  username                    = "foo"
  monitoring_interval         = 15
  monitoring_role_arn         = ""
}
