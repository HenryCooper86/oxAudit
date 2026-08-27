resource "aws_s3_bucket" "uploads" {
  bucket = "app-uploads"
  acl    = "public-read"
}
