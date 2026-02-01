# Artifact Registry for Docker images
resource "google_artifact_registry_repository" "main" {
  location      = var.region
  repository_id = "ssf-images"
  description   = "Docker repository for SSF OIDC Provider"
  format        = "DOCKER"
  project       = var.project_id

  cleanup_policy_dry_run = false
  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }

  depends_on = [google_project_service.required_apis]
}
