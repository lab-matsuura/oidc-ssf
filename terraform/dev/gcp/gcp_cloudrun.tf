# Cloud Run Service
resource "google_cloud_run_v2_service" "main" {
  name     = "ssf-oidc-provider-${var.environment}"
  location = var.region
  project  = var.project_id

  deletion_protection = false

  template {
    service_account = google_service_account.cloudrun.email

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    # Direct VPC Egress (no VPC Connector needed)
    vpc_access {
      network_interfaces {
        network    = google_compute_network.main.id
        subnetwork = google_compute_subnetwork.main.id
      }
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}/oidc-provider:${var.image_tag}"

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

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
        name  = "DB_NAME"
        value = var.db_name_idp
      }

      env {
        name  = "DB_SSLMODE"
        value = "disable"
      }

      env {
        name  = "SERVER_PORT"
        value = "8080"
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

      # Additional redirect URIs for OIDC clients (comma-separated)
      env {
        name  = "OIDC_ADDITIONAL_REDIRECT_URIS"
        value = "${local.cloud_run_client_url}/callback"
      }

      # Additional redirect URIs for OIDC client 2 (RP2)
      env {
        name  = "OIDC_ADDITIONAL_REDIRECT_URIS_2"
        value = "${local.cloud_run_client2_url}/callback"
      }

      # OIDC Issuer URL (Cloud Run URL)
      env {
        name  = "OIDC_ISSUER_URL"
        value = local.cloud_run_provider_url
      }

      # SSF Client URL (for SSF receiver endpoint)
      env {
        name  = "SSF_CLIENT_URL"
        value = local.cloud_run_client_url
      }

      # Fosite Global Secret (for HMAC operations)
      env {
        name = "FOSITE_GLOBAL_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.fosite_global_secret.secret_id
            version = "latest"
          }
        }
      }

      # Test client seeding (enabled for dev environment)
      env {
        name  = "SEED_TEST_CLIENTS"
        value = "true"
      }

      # Conformance clients (disabled by default)
      env {
        name  = "SEED_CONFORMANCE_CLIENTS"
        value = "false"
      }
    }
  }

  depends_on = [
    google_project_service.required_apis,
    google_secret_manager_secret_version.db_password,
    google_secret_manager_secret_version.fosite_global_secret,
  ]
}

# Allow unauthenticated access (public OIDC provider)
resource "google_cloud_run_v2_service_iam_member" "public" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.main.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
