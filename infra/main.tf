# AWS infrastructure for the hosted corpus pipeline (Prefect Cloud + ECS Fargate).
#
# Skeleton — review before `terraform apply`. Provisions: ECR (image), an S3
# bucket (DVC remote + dataset releases, versioned), a least-privilege ECS task
# role, Secrets Manager entries for the API keys, an ECS Fargate cluster, and a
# CloudWatch log group. The Prefect ECS *push work pool* is created in Prefect
# Cloud and pointed at this cluster/role (see docs/deploy.md).

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

locals {
  name = var.project
  tags = { Project = var.project, ManagedBy = "terraform" }
}

# ---------------------------------------------------------------- ECR (image) --
resource "aws_ecr_repository" "app" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true } # supply-chain: scan images
  tags                 = local.tags
}

# ----------------------------------------------------- S3 (DVC remote + data) --
resource "aws_s3_bucket" "data" {
  bucket = var.data_bucket_name
  tags   = local.tags
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" } # granular rollback of releases
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

# ------------------------------------------------------- Secrets Manager keys --
resource "aws_secretsmanager_secret" "keys" {
  for_each = toset(var.secret_keys)
  name     = "${local.name}/${each.value}"
  tags     = local.tags
  # Values are set out of band (CLI/console), never in Terraform state.
}

# ------------------------------------------------------- CloudWatch log group --
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${local.name}"
  retention_in_days = 30
  tags              = local.tags
}

# --------------------------------------------------------------- IAM (Fargate) --
data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Execution role: pull image + write logs (AWS-managed policy).
resource "aws_iam_role" "execution" {
  name               = "${local.name}-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Task role: least privilege — RW only this bucket, read only these secrets.
resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "task" {
  statement {
    sid       = "DataBucketRW"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"]
    resources = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
  }
  statement {
    sid       = "ReadSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [for s in aws_secretsmanager_secret.keys : s.arn]
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "${local.name}-task"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

# ------------------------------------------------------------- ECS (Fargate) --
resource "aws_ecs_cluster" "this" {
  name = local.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = local.tags
}
