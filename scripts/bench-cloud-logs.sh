#!/bin/bash
# =============================================================================
# Download Benchmark Results from Cloud Logging
# =============================================================================
# Usage:
#   ./scripts/bench-cloud-logs.sh [output_file] [since]
#
# Examples:
#   ./scripts/bench-cloud-logs.sh                          # Default: receive.jsonl, 1h
#   ./scripts/bench-cloud-logs.sh results.jsonl 2h         # Custom file, last 2 hours
# =============================================================================

set -e

PROJECT_ID="${GCP_PROJECT_ID:-shared-signals}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
SERVICE_NAME="ssf-bench-receiver-${ENVIRONMENT}"
OUTPUT_FILE="${1:-benchmark/results/receive.jsonl}"
SINCE="${2:-1h}"

echo "============================================="
echo "  Download Benchmark Logs from Cloud Logging"
echo "============================================="
echo ""
echo "Project:     ${PROJECT_ID}"
echo "Service:     ${SERVICE_NAME}"
echo "Since:       ${SINCE}"
echo "Output:      ${OUTPUT_FILE}"
echo ""

# Ensure output directory exists
mkdir -p "$(dirname "${OUTPUT_FILE}")"

echo "Downloading logs..."

gcloud logging read \
  "resource.type=cloud_run_revision AND resource.labels.service_name=${SERVICE_NAME} AND jsonPayload.message=SET_RECEIVED" \
  --project="${PROJECT_ID}" \
  --format="json" \
  --freshness="${SINCE}" \
| jq -c '.[] | .jsonPayload.data' > "${OUTPUT_FILE}"

COUNT=$(wc -l < "${OUTPUT_FILE}" | tr -d ' ')
echo ""
echo "Downloaded ${COUNT} entries to ${OUTPUT_FILE}"
