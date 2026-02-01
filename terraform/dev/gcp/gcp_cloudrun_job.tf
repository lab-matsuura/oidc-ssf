# Cloud Run Job for Database Migration
# This job runs Atlas migrations for both IdP and RP databases

resource "google_cloud_run_v2_job" "migration" {
  name     = "ssf-db-migration-${var.environment}"
  location = var.region
  project  = var.project_id

  deletion_protection = false

  template {
    template {
      service_account = google_service_account.cloudrun.email

      vpc_access {
        network_interfaces {
          network    = google_compute_network.main.id
          subnetwork = google_compute_subnetwork.main.id
        }
        egress = "PRIVATE_RANGES_ONLY"
      }

      containers {
        image = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}/db-migration:${var.image_tag}"

        env {
          name  = "DB_HOST"
          value = google_sql_database_instance.main.private_ip_address
        }

        env {
          name  = "DB_PORT"
          value = "5432"
        }

        env {
          name  = "DB_USER"
          value = var.db_user
        }

        env {
          name  = "DB_NAME_IDP"
          value = var.db_name_idp
        }

        env {
          name  = "DB_NAME_RP"
          value = var.db_name_rp
        }

        env {
          name  = "DB_NAME_RP2"
          value = var.db_name_rp2
        }

        env {
          name = "DB_PASSWORD"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.db_password.secret_id
              version = "latest"
            }
          }
        }

        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }
      }

      max_retries = 1
      timeout     = "300s"
    }
  }

  depends_on = [
    google_project_service.required_apis,
    google_secret_manager_secret_version.db_password,
  ]
}
