#!/usr/bin/env bash
# ==============================================================================
# Deploy WhyYouKnow Backend (FastAPI) to Google Cloud Run
# ==============================================================================
set -e

# Base directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure gcloud is in PATH
if ! command -v gcloud &> /dev/null && [ -f "$HOME/google-cloud-sdk/bin/gcloud" ]; then
    export PATH="$HOME/google-cloud-sdk/bin:$PATH"
fi

# Load .env if present
if [ -f "$ROOT_DIR/.env" ]; then
    set -a
    source "$ROOT_DIR/.env"
    set +a
fi

# Google Cloud Configuration
PROJECT_ID="${GCP_PROJECT:-whyyouknow}"
REGION="${GCP_REGION:-asia-southeast1}"
SERVICE_NAME="${GCP_API_SERVICE:-tiered-web-app-api}"
INSTANCE_CONNECTION_NAME="${INSTANCE_CONNECTION_NAME:-${PROJECT_ID}:${REGION}:tiered-web-app-db-fa31}"
VPC_CONNECTOR="${VPC_CONNECTOR:-tiered-web-app-vpc-cx}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-tiered-web-app-run-sa@${PROJECT_ID}.iam.gserviceaccount.com}"

# Database and App Configuration
DB_NAME="${DB_NAME:-kno}"
DB_USER="${DB_USER:-root}"
DB_PASS="${DB_PASS:-}"
GOOGLE_CLIENT_ID="${GOOGLE_CLIENT_ID:-}"
IP_HMAC_SECRET="${IP_HMAC_SECRET:-dev-insecure-change-me}"
ADMIN_EMAILS="${ADMIN_EMAILS:-}"
# Automatically discover and include Cloud Run Frontend in ALLOWED_ORIGINS
GCP_FE_SERVICE="${GCP_FE_SERVICE:-tiered-web-app-fe}"
FE_URL=$(gcloud run services describe "$GCP_FE_SERVICE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --format 'value(status.url)' 2>/dev/null || true)

AUTO_ORIGINS="http://localhost:5173,https://tiered-web-app-fe-e7mkoeotya-as.a.run.app,https://tiered-web-app-fe-15965476821.asia-southeast1.run.app"
if [ -n "$FE_URL" ]; then
    AUTO_ORIGINS="$AUTO_ORIGINS,$FE_URL"
fi
ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:5173},$AUTO_ORIGINS"

echo "============================================================"
echo " Deploying Backend to Google Cloud Run"
echo "============================================================"
echo " Project:            $PROJECT_ID"
echo " Region:             $REGION"
echo " Service:            $SERVICE_NAME"
echo " Cloud SQL:          $INSTANCE_CONNECTION_NAME"
echo " VPC Connector:      $VPC_CONNECTOR"
echo " Service Account:    $SERVICE_ACCOUNT"
echo " Database:           $DB_NAME (User: $DB_USER)"
echo "============================================================"

# Deploy to Cloud Run using server/Dockerfile
gcloud run deploy "$SERVICE_NAME" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --source "$ROOT_DIR/server" \
  --allow-unauthenticated \
  --service-account "$SERVICE_ACCOUNT" \
  --add-cloudsql-instances "$INSTANCE_CONNECTION_NAME" \
  --vpc-connector "$VPC_CONNECTOR" \
  --set-env-vars "^|^ENVIRONMENT=production|INSTANCE_CONNECTION_NAME=$INSTANCE_CONNECTION_NAME|DB_NAME=$DB_NAME|DB_USER=$DB_USER|DB_PASS=$DB_PASS|GOOGLE_CLIENT_ID=$GOOGLE_CLIENT_ID|IP_HMAC_SECRET=$IP_HMAC_SECRET|ADMIN_EMAILS=$ADMIN_EMAILS|ALLOWED_ORIGINS=$ALLOWED_ORIGINS|COOKIE_SECURE=true"

echo ""
echo "✅ Backend deployed successfully to Cloud Run!"

