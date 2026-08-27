data "aws_iam_policy_document" "example" {
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::app-uploads"]
  }
}
