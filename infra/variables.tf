variable "project" {
  description = "Name prefix for all resources."
  type        = string
  default     = "cybersec-slm"
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "data_bucket_name" {
  description = "Globally-unique S3 bucket for the DVC remote + dataset releases."
  type        = string
}

variable "secret_keys" {
  description = "API-key secret names created in Secrets Manager (values set out of band)."
  type        = list(string)
  default     = ["nvd-api-key", "kaggle-api-token", "google-search-api-key", "google-search-engine-id"]
}

variable "github_repo" {
  description = "owner/repo allowed to assume the CI deploy role via OIDC."
  type        = string
  default     = ""
}
