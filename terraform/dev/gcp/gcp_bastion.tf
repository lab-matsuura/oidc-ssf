# =============================================================================
# Bastion Host with IAP (Identity-Aware Proxy)
# =============================================================================
# This bastion allows secure access to Cloud SQL via IAP tunnel.
# No public IP - all access goes through IAP.
#
# Usage:
#   1. Start IAP tunnel:
#      gcloud compute ssh ssf-bastion-dev --zone=asia-northeast1-a \
#        --tunnel-through-iap \
#        -- -L 5432:<cloud-sql-private-ip>:5432 -N
#
#   2. Connect with TablePlus/psql to localhost:5432
# =============================================================================

# Service Account for Bastion
resource "google_service_account" "bastion" {
  account_id   = "ssf-bastion-sa-${var.environment}"
  display_name = "SSF Bastion Service Account"
  project      = var.project_id
}

# Bastion Host VM (Private IP only)
resource "google_compute_instance" "bastion" {
  name         = "ssf-bastion-${var.environment}"
  machine_type = "e2-micro" # Smallest instance, sufficient for SSH tunneling
  zone         = "${var.region}-a"
  project      = var.project_id

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 10 # GB
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = google_compute_network.main.id
    subnetwork = google_compute_subnetwork.main.id
    # No access_config = No public IP
  }

  # Enable OS Login for IAM-based SSH authentication
  metadata = {
    enable-oslogin = "TRUE"
  }

  # Use dedicated service account
  service_account {
    email  = google_service_account.bastion.email
    scopes = ["cloud-platform"]
  }

  tags = ["bastion", "iap-ssh"]

  # Allow Terraform to replace if needed
  allow_stopping_for_update = true

  depends_on = [google_project_service.required_apis]
}

# =============================================================================
# Firewall Rules
# =============================================================================

# Allow SSH from IAP IP range only
resource "google_compute_firewall" "iap_ssh" {
  name    = "ssf-allow-iap-ssh-${var.environment}"
  network = google_compute_network.main.id
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # IAP's IP range - this is the only source that can reach the bastion
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["iap-ssh"]

  description = "Allow SSH access via IAP tunnel"
}

# Allow bastion to connect to Cloud SQL (internal VPC traffic)
resource "google_compute_firewall" "bastion_to_cloudsql" {
  name    = "ssf-allow-bastion-cloudsql-${var.environment}"
  network = google_compute_network.main.id
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }

  source_tags        = ["bastion"]
  destination_ranges = [google_compute_global_address.private_ip_range.address]

  description = "Allow bastion to connect to Cloud SQL"
}

# =============================================================================
# IAM - IAP Tunnel Access
# =============================================================================

# Grant IAP tunnel access to specified users
# Add your Google account email to the bastion_iap_users variable
resource "google_iap_tunnel_instance_iam_binding" "bastion" {
  project  = var.project_id
  zone     = "${var.region}-a"
  instance = google_compute_instance.bastion.name
  role     = "roles/iap.tunnelResourceAccessor"
  members  = var.bastion_iap_users
}

# Grant OS Login access to bastion users
resource "google_project_iam_member" "bastion_os_login" {
  for_each = toset(var.bastion_iap_users)

  project = var.project_id
  role    = "roles/compute.osLogin"
  member  = each.value
}
