# VPC Network
resource "google_compute_network" "main" {
  name                    = "ssf-vpc-${var.environment}"
  auto_create_subnetworks = false
  project                 = var.project_id

  depends_on = [google_project_service.required_apis]
}

# Subnet for VPC Connector
resource "google_compute_subnetwork" "main" {
  name          = "ssf-subnet-${var.environment}"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.main.id
  project       = var.project_id
}

# Private IP range for Cloud SQL
resource "google_compute_global_address" "private_ip_range" {
  name          = "ssf-private-ip-range-${var.environment}"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
  project       = var.project_id
}

# Private Service Connection for Cloud SQL
resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]

  depends_on = [google_project_service.required_apis]
}

# Note: Using Direct VPC Egress instead of VPC Access Connector
# This eliminates the need for a dedicated connector and reduces costs
