resource "aws_db_instance" "disabled_backups" {
  engine                  = "mysql"
  instance_class          = "db.t2.micro"
  backup_retention_period = 0
}

resource "aws_db_instance" "missing_backups" {
  engine         = "mysql"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "short_retention" {
  engine                  = "mysql"
  instance_class          = "db.t2.micro"
  backup_retention_period = 6
}
