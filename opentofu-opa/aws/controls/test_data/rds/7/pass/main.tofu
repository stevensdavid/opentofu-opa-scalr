resource "aws_db_instance" "unsupported_engine" {
  allocated_storage = 5
  engine            = "sqlserver-ee"
  instance_class    = "db.t2.micro"
}

resource "aws_db_instance" "valid" {
  allocated_storage                   = 5
  engine                              = "mysql"
  instance_class                      = "db.t2.micro"
  iam_database_authentication_enabled = true
}
