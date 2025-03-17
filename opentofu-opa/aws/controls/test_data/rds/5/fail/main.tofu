resource "aws_db_instance" "disabled_updates" {
  engine                     = "mysql"
  allocated_storage          = 5
  instance_class             = "db.t2.micro"
  auto_minor_version_upgrade = false
}
