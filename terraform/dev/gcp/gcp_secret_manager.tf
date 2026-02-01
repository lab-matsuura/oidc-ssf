# Secret for Database Password
resource "google_secret_manager_secret" "db_password" {
  secret_id = "ssf-db-password-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.required_apis]
}

# Secret Version with the actual password
resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.db_password.result
}

# Secret for Fosite Global Secret (HMAC operations)
resource "google_secret_manager_secret" "fosite_global_secret" {
  secret_id = "ssf-fosite-global-secret-${var.environment}"
  project   = var.project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.required_apis]
}

# Generate random secret for Fosite (32 bytes = 64 hex chars)
resource "random_password" "fosite_global_secret" {
  length  = 64
  special = false
}

# Secret Version with the actual Fosite secret
resource "google_secret_manager_secret_version" "fosite_global_secret" {
  secret      = google_secret_manager_secret.fosite_global_secret.id
  secret_data = random_password.fosite_global_secret.result
}
