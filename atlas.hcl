// Atlas configuration for PostgreSQL schema management
// See: https://atlasgo.io/atlas-schema/sql-resources

variable "target" {
  type    = string
  default = "idp"
}

env "local" {
  src = "file://${var.target}/db/postgres/schema.sql"
  url = "postgres://postgres:postgres@localhost:5432/${var.target}?search_path=public&sslmode=disable"
  dev = "docker://postgres/17/dev?search_path=public"

  migration {
    dir = "file://${var.target}/db/postgres/migrations"
  }
}

env "prod" {
  src = "file://${var.target}/db/postgres/schema.sql"
  url = getenv("DATABASE_URL")
  dev = getenv("DATABASE_URL")

  migration {
    dir = "file://${var.target}/db/postgres/migrations"
  }

  diff {
    skip {
      drop_schema = true
      drop_table  = true
    }
  }
}
