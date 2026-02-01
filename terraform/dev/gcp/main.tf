terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Get project information
data "google_project" "current" {
  project_id = var.project_id
}

# =============================================================================
# Locals - Dynamic Cloud Run URLs
# =============================================================================
# Cloud Run URLs are predictable: https://{service-name}-{project-number}.{region}.run.app
# This eliminates the need to manually configure URLs after initial deployment.
locals {
  cloud_run_provider_url       = "https://ssf-oidc-provider-${var.environment}-${data.google_project.current.number}.${var.region}.run.app"
  cloud_run_client_url         = "https://ssf-oidc-client-${var.environment}-${data.google_project.current.number}.${var.region}.run.app"
  cloud_run_client2_url        = "https://ssf-oidc-client2-${var.environment}-${data.google_project.current.number}.${var.region}.run.app"
  cloud_run_bench_receiver_url = "https://ssf-bench-receiver-${var.environment}-${data.google_project.current.number}.${var.region}.run.app"
}

# Enable required APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "compute.googleapis.com",
    "sqladmin.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "vpcaccess.googleapis.com",
    "servicenetworking.googleapis.com",
    "iamcredentials.googleapis.com",
    "iap.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}
