# Migration Dockerfile
# Runs Atlas migrations for IdP, RP, and RP2 databases

FROM alpine:3.19

WORKDIR /app

# Install Atlas
RUN apk add --no-cache curl \
    && curl -sSf https://atlasgo.sh | sh

# Copy migration files and schema for IdP, RP, and RP2
COPY idp/db/postgres/schema.sql ./idp/db/postgres/
COPY idp/db/postgres/migrations/ ./idp/db/postgres/migrations/
COPY rp/db/postgres/schema.sql ./rp/db/postgres/
COPY rp/db/postgres/migrations/ ./rp/db/postgres/migrations/
COPY rp2/db/postgres/schema.sql ./rp2/db/postgres/
COPY rp2/db/postgres/migrations/ ./rp2/db/postgres/migrations/
COPY atlas.hcl ./

# Migration script
COPY <<'EOF' /migrate.sh
#!/bin/sh
set -e

echo "=== Migration Job Started ==="
echo "DB_HOST: ${DB_HOST}"
echo "DB_PORT: ${DB_PORT}"
echo "DB_USER: ${DB_USER}"
echo "DB_NAME_IDP: ${DB_NAME_IDP}"
echo "DB_NAME_RP: ${DB_NAME_RP}"
echo "DB_NAME_RP2: ${DB_NAME_RP2}"

echo "Atlas version:"
atlas version

# Run IdP migration
echo ""
echo "=========================================="
echo "=== Running IdP Database Migration ==="
echo "=========================================="
export DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME_IDP}?sslmode=disable"

echo "Checking IdP migration status..."
atlas migrate status --env prod --var target=idp 2>&1 || true

echo "Applying IdP migrations..."
atlas migrate apply --env prod --var target=idp

echo "IdP migration completed!"

# Run RP migration
echo ""
echo "=========================================="
echo "=== Running RP Database Migration ==="
echo "=========================================="
export DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME_RP}?sslmode=disable"

echo "Checking RP migration status..."
atlas migrate status --env prod --var target=rp 2>&1 || true

echo "Applying RP migrations..."
atlas migrate apply --env prod --var target=rp

echo "RP migration completed!"

# Run RP2 migration
echo ""
echo "=========================================="
echo "=== Running RP2 Database Migration ==="
echo "=========================================="
export DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME_RP2}?sslmode=disable"

echo "Checking RP2 migration status..."
atlas migrate status --env prod --var target=rp2 2>&1 || true

echo "Applying RP2 migrations..."
atlas migrate apply --env prod --var target=rp2

echo "RP2 migration completed!"

echo ""
echo "=========================================="
echo "=== All Migrations Completed Successfully! ==="
echo "=========================================="
EOF

RUN chmod +x /migrate.sh

ENTRYPOINT ["/migrate.sh"]
