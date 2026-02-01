# Cloud Run Service - OIDC Client 2 (RP2 - Poll-based SSF)
resource "google_cloud_run_v2_service" "client2" {
  name     = "ssf-oidc-client2-${var.environment}"
  location = var.region
  project  = var.project_id

  deletion_protection = false

  template {
    service_account = google_service_account.cloudrun.email

    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }

    # VPC access for Cloud SQL connection
    vpc_access {
      network_interfaces {
        network    = google_compute_network.main.id
        subnetwork = google_compute_subnetwork.main.id
      }
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}/oidc-client2:${var.image_tag}"

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      # Database configuration (RP2)
      env {
        name  = "RP2_DB_HOST"
        value = google_sql_database_instance.main.private_ip_address
      }

      env {
        name  = "RP2_DB_PORT"
        value = "5432"
      }

      env {
        name  = "RP2_DB_USER"
        value = var.db_user
      }

      env {
        name  = "RP2_DB_NAME"
        value = var.db_name_rp2
      }

      env {
        name  = "RP2_DB_SSLMODE"
        value = "disable"
      }

      env {
        name = "RP2_DB_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.db_password.secret_id
            version = "latest"
          }
        }
      }

      # OIDC configuration - Provider URL
      env {
        name  = "OIDC_ISSUER_URL"
        value = google_cloud_run_v2_service.main.uri
      }

      env {
        name  = "RP2_OIDC_CLIENT_ID"
        value = "test-client-2"
      }

      env {
        name  = "RP2_OIDC_CLIENT_SECRET"
        value = "test-secret-2"
      }

      # OIDC_REDIRECT_URI uses the client's own URL (dynamically generated)
      env {
        name  = "RP2_OIDC_REDIRECT_URI"
        value = "${local.cloud_run_client2_url}/callback"
      }

      # SSF Poll configuration
      env {
        name  = "RP2_SSF_POLL_INTERVAL"
        value = "10"
      }

      # Security: Enable secure cookies for HTTPS
      env {
        name  = "SECURE_COOKIES"
        value = "true"
      }
    }
  }

  depends_on = [
    google_project_service.required_apis,
    google_cloud_run_v2_service.main,
    google_secret_manager_secret_version.db_password,
  ]
}

# Allow unauthenticated access (public client)
resource "google_cloud_run_v2_service_iam_member" "client2_public" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.client2.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
