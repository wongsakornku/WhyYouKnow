#!/usr/bin/env bash
# ==============================================================================
# Deploy WhyYouKnow Frontend (React / Vite) to Google Cloud Run
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
SERVICE_NAME="${GCP_FE_SERVICE:-tiered-web-app-fe}"
API_SERVICE_NAME="${GCP_API_SERVICE:-tiered-web-app-api}"

echo "============================================================"
echo " Resolving Backend URL from Cloud Run..."
echo "============================================================"

# Try to automatically discover backend URL from Cloud Run
DISCOVERED_BACKEND_URL=$(gcloud run services describe "$API_SERVICE_NAME" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --format 'value(status.url)' 2>/dev/null || true)

if [ -n "$DISCOVERED_BACKEND_URL" ]; then
    BACKEND_URL="$DISCOVERED_BACKEND_URL"
    echo " [OK] Found Backend URL: $BACKEND_URL"
else
    BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
    echo " [WARN] Could not auto-detect '$API_SERVICE_NAME'. Using fallback: $BACKEND_URL"
fi

echo "============================================================"
echo " Deploying Frontend to Google Cloud Run"
echo "============================================================"
echo " Project:            $PROJECT_ID"
echo " Region:             $REGION"
echo " Service:            $SERVICE_NAME"
echo " Backend Reverse:    $BACKEND_URL"
echo "============================================================"

# Deploy to Cloud Run using Google Cloud Buildpacks (Builds Vite & runs server.js)
gcloud run deploy "$SERVICE_NAME" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --source "$ROOT_DIR" \
  --allow-unauthenticated \
  --set-env-vars "BACKEND_URL=$BACKEND_URL"

echo ""
echo "============================================================"
FE_URL=$(gcloud run services describe "$SERVICE_NAME" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --format 'value(status.url)' 2>/dev/null || true)

if [ -n "$FE_URL" ]; then
    echo "✅ Frontend deployed successfully! URL: $FE_URL"
else
    echo "✅ Frontend deployed successfully!"
fi
echo "============================================================"

