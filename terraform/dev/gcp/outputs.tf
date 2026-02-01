# Cloud Run URL - OIDC Provider
output "cloud_run_url" {
  description = "URL of the Cloud Run OIDC Provider service"
  value       = google_cloud_run_v2_service.main.uri
}

# Cloud Run URL - OIDC Client
output "cloud_run_client_url" {
  description = "URL of the Cloud Run OIDC Client service"
  value       = google_cloud_run_v2_service.client.uri
}

# Cloud Run URL - OIDC Client 2 (Poll-based)
output "cloud_run_client2_url" {
  description = "URL of the Cloud Run OIDC Client 2 service (Poll-based SSF)"
  value       = google_cloud_run_v2_service.client2.uri
}

# Cloud SQL Connection Name
output "cloud_sql_connection_name" {
  description = "Cloud SQL instance connection name"
  value       = google_sql_database_instance.main.connection_name
}

# Cloud SQL Private IP
output "cloud_sql_private_ip" {
  description = "Cloud SQL instance private IP address"
  value       = google_sql_database_instance.main.private_ip_address
}

# Cloud SQL IdP Database
output "cloud_sql_database_idp" {
  description = "IdP database name"
  value       = google_sql_database.idp.name
}

# Cloud SQL RP Database
output "cloud_sql_database_rp" {
  description = "RP database name"
  value       = google_sql_database.rp.name
}

# Cloud SQL RP2 Database
output "cloud_sql_database_rp2" {
  description = "RP2 database name (Poll-based SSF)"
  value       = google_sql_database.rp2.name
}

# Artifact Registry URL
output "artifact_registry_url" {
  description = "Artifact Registry repository URL"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}"
}

# Service Account Email
output "cloudrun_service_account" {
  description = "Cloud Run service account email"
  value       = google_service_account.cloudrun.email
}

# GitHub Actions - Workload Identity Provider
output "github_actions_workload_identity_provider" {
  description = "Workload Identity Provider for GitHub Actions"
  value       = google_iam_workload_identity_pool_provider.github.name
}

# GitHub Actions - Service Account
output "github_actions_service_account" {
  description = "Service account for GitHub Actions"
  value       = google_service_account.github_actions.email
}

# GCP Project Number (needed for Workload Identity)
output "project_number" {
  description = "GCP Project Number"
  value       = data.google_project.current.number
}

# =============================================================================
# Bastion Host
# =============================================================================

# Bastion Instance Name
output "bastion_name" {
  description = "Bastion host instance name"
  value       = google_compute_instance.bastion.name
}

# Bastion Zone
output "bastion_zone" {
  description = "Bastion host zone"
  value       = google_compute_instance.bastion.zone
}

# SSH Tunnel Command
output "bastion_ssh_tunnel_command" {
  description = "Command to start SSH tunnel via IAP for database access"
  value       = "gcloud compute ssh ${google_compute_instance.bastion.name} --zone=${google_compute_instance.bastion.zone} --tunnel-through-iap -- -L 5432:${google_sql_database_instance.main.private_ip_address}:5432 -N"
}

# Cloud Run URL - Benchmark Receiver
output "cloud_run_bench_receiver_url" {
  description = "URL of the Cloud Run Benchmark Receiver service"
  value       = google_cloud_run_v2_service.bench_receiver.uri
}
