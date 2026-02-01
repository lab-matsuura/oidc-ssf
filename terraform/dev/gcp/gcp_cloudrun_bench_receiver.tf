# Cloud Run Service - Benchmark Receiver
resource "google_cloud_run_v2_service" "bench_receiver" {
  name     = "ssf-bench-receiver-${var.environment}"
  location = var.region
  project  = var.project_id

  deletion_protection = false

  template {
    service_account = google_service_account.cloudrun.email

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}/bench-receiver:${var.image_tag}"

      ports {
        container_port = 9090
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      # Cloud mode: no -log flag, outputs to stdout
    }
  }

  depends_on = [
    google_project_service.required_apis,
  ]
}

# Allow unauthenticated access (IdP pushes events here)
resource "google_cloud_run_v2_service_iam_member" "bench_receiver_public" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.bench_receiver.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
