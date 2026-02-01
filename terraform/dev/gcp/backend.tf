# =============================================================================
# Terraform Backend Configuration
# =============================================================================
# IMPORTANT: Update the bucket name to match your GCS bucket before running
# terraform init. The bucket must be created manually before initialization.
#
# Alternatively, you can use partial backend configuration:
#   terraform init -backend-config="bucket=your-bucket-name"
# =============================================================================

terraform {
  backend "gcs" {
    bucket = "<your-terraform-state-bucket>"
    prefix = "dev/terraform.tfstate"
  }
}
