output "ecr_repository_url" {
  description = "Push the image here; reference it in the Prefect ECS work pool."
  value       = aws_ecr_repository.app.repository_url
}

output "data_bucket" {
  description = "S3 bucket for the DVC remote (s3://<bucket>/dvc) + dataset releases."
  value       = aws_s3_bucket.data.bucket
}

output "ecs_cluster_arn" {
  description = "Target cluster for the Prefect ECS push work pool."
  value       = aws_ecs_cluster.this.arn
}

output "task_role_arn" {
  description = "Least-privilege task role ARN for the Prefect work pool job template."
  value       = aws_iam_role.task.arn
}

output "execution_role_arn" {
  description = "Task execution role ARN (image pull + logs)."
  value       = aws_iam_role.execution.arn
}

output "secret_arns" {
  description = "Secrets Manager ARNs to wire into prefect-aws AwsSecret blocks."
  value       = { for k, s in aws_secretsmanager_secret.keys : k => s.arn }
}
