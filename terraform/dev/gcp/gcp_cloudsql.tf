# Cloud SQL PostgreSQL Instance
resource "google_sql_database_instance" "main" {
  name             = "ssf-postgres-${var.environment}"
  database_version = "POSTGRES_15"
  region           = var.region
  project          = var.project_id

  deletion_protection = false # Set to true in production

  settings {
    tier = "db-f1-micro" # Smallest instance for dev

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.main.id
      enable_private_path_for_google_cloud_services = true
    }

    backup_configuration {
      enabled = false # Enable in production
    }

    database_flags {
      name  = "max_connections"
      value = "100"
    }
  }

  depends_on = [google_service_networking_connection.private_vpc_connection]
}

# IdP Database
resource "google_sql_database" "idp" {
  name     = var.db_name_idp
  instance = google_sql_database_instance.main.name
  project  = var.project_id
}

# RP Database
resource "google_sql_database" "rp" {
  name     = var.db_name_rp
  instance = google_sql_database_instance.main.name
  project  = var.project_id
}

# RP2 Database (Poll-based SSF)
resource "google_sql_database" "rp2" {
  name     = var.db_name_rp2
  instance = google_sql_database_instance.main.name
  project  = var.project_id
}

# Database User
resource "google_sql_user" "main" {
  name     = var.db_user
  instance = google_sql_database_instance.main.name
  password = random_password.db_password.result
  project  = var.project_id
}

# Generate random password for database
resource "random_password" "db_password" {
  length  = 32
  special = false # Cloud SQL has restrictions on special characters
}
