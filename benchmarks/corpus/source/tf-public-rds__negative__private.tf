resource "aws_db_instance" "postgres" {
  engine              = "postgres"
  publicly_accessible = false
}
