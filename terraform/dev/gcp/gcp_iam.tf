# Service Account for Cloud Run
resource "google_service_account" "cloudrun" {
  account_id   = "ssf-cloudrun-sa-${var.environment}"
  display_name = "SSF Cloud Run Service Account (${var.environment})"
  project      = var.project_id
}

# Cloud SQL Client role
resource "google_project_iam_member" "cloudrun_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.cloudrun.email}"
}

# Secret Manager Secret Accessor role
resource "google_project_iam_member" "cloudrun_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.cloudrun.email}"
}

# Artifact Registry Reader role (for pulling images)
resource "google_project_iam_member" "cloudrun_artifact_reader" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.cloudrun.email}"
}
