variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "asia-northeast1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "db_name_idp" {
  description = "Database name for IdP"
  type        = string
  default     = "idp"
}

variable "db_name_rp" {
  description = "Database name for RP"
  type        = string
  default     = "rp"
}

variable "db_name_rp2" {
  description = "Database name for RP2 (Poll-based)"
  type        = string
  default     = "rp2"
}

variable "db_user" {
  description = "Database user name"
  type        = string
  default     = "ssf-app"
}

variable "image_tag" {
  description = "Docker image tag for Cloud Run"
  type        = string
  default     = "latest"
}

variable "github_repository" {
  description = "GitHub repository (owner/repo format)"
  type        = string
}

# Note: oidc_client_redirect_uri and oidc_issuer_url are now dynamically generated
# using locals in main.tf based on project number. No manual configuration needed.

variable "bastion_iap_users" {
  description = "List of users allowed to access bastion via IAP (format: user:email@example.com)"
  type        = list(string)
  default     = []
}
