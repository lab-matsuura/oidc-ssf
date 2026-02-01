#!/bin/bash
# =============================================================================
# Database SSH Tunnel via IAP
# =============================================================================
# This script starts an SSH tunnel through IAP to access Cloud SQL from local.
#
# Usage:
#   ./scripts/db-tunnel.sh
#
# Then connect with TablePlus/psql:
#   Host: 127.0.0.1
#   Port: 5432
#   User: ssf-app
#   Database: idp or rp
#
# To get the password:
#   gcloud secrets versions access latest --secret=ssf-db-password-dev
# =============================================================================

set -e

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-shared-signals}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
ZONE="${GCP_ZONE:-asia-northeast1-a}"
LOCAL_PORT="${LOCAL_PORT:-5432}"

BASTION_NAME="ssf-bastion-${ENVIRONMENT}"

# Get Cloud SQL private IP from terraform output or gcloud
echo "Fetching Cloud SQL private IP..."
CLOUDSQL_IP=$(gcloud sql instances describe "ssf-postgres-${ENVIRONMENT}" \
  --project="${PROJECT_ID}" \
  --format="value(ipAddresses[0].ipAddress)" 2>/dev/null)

if [ -z "$CLOUDSQL_IP" ]; then
  echo "Error: Could not fetch Cloud SQL private IP"
  echo "Make sure the Cloud SQL instance exists and you have access."
  exit 1
fi

echo ""
echo "============================================="
echo "  Database SSH Tunnel via IAP"
echo "============================================="
echo ""
echo "Bastion:     ${BASTION_NAME}"
echo "Zone:        ${ZONE}"
echo "Cloud SQL:   ${CLOUDSQL_IP}:5432"
echo "Local:       127.0.0.1:${LOCAL_PORT}"
echo ""
echo "---------------------------------------------"
echo "Connect with TablePlus/psql:"
echo "  Host:     127.0.0.1"
echo "  Port:     ${LOCAL_PORT}"
echo "  User:     ssf-app"
echo "  Database: idp (or rp)"
echo ""
echo "Get password:"
echo "  gcloud secrets versions access latest --secret=ssf-db-password-${ENVIRONMENT}"
echo "---------------------------------------------"
echo ""
echo "Starting tunnel... (Ctrl+C to stop)"
echo ""

# Start SSH tunnel via IAP
gcloud compute ssh "${BASTION_NAME}" \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --tunnel-through-iap \
  -- -L "${LOCAL_PORT}:${CLOUDSQL_IP}:5432" -N
