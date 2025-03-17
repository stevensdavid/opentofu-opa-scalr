resource "aws_db_instance" "enabled_updates" {
  engine                     = "postgresql"
  allocated_storage          = 5
  instance_class             = "db.t2.micro"
  auto_minor_version_upgrade = true
}

resource "aws_db_instance" "default_enabled_updates" {
  engine            = "postgresql"
  allocated_storage = 5
  instance_class    = "db.t2.micro"
}

resource "aws_db_instance" "custom_doesnt_support_auto_updates" {
  engine            = "custom-sqlserver-se"
  allocated_storage = 5
  instance_class    = "db.t2.micro"
}
