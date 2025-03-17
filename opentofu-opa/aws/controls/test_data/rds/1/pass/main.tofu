resource "aws_db_instance" "valid" {
  allocated_storage           = 5
  engine                      = "postgres"
  manage_master_user_password = true
  instance_class              = "db.t2.micro"
  username                    = "foo"
  multi_az                    = true
}

resource "aws_db_instance" "unsupported_engine" {
  allocated_storage           = 5
  engine                      = "custom-oracle-ee"
  manage_master_user_password = true
  instance_class              = "db.t2.micro"
  username                    = "foo"
  multi_az                    = true
}
