resource "aws_db_instance" "disabled_iam_database_authentication" {
  allocated_storage                   = 5
  engine                              = "mysql"
  instance_class                      = "db.t2.micro"
  iam_database_authentication_enabled = false
}

resource "aws_db_instance" "missing_argument" {
  allocated_storage = 5
  engine            = "mysql"
  instance_class    = "db.t2.micro"
}
