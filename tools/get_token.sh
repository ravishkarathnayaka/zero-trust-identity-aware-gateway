#!/usr/bin/env bash
# ==============================================================================
# Shell Helper: Quick Token Issuance for Alice, Bob, Charlie, and Eve
# ==============================================================================
set -euo pipefail

USER_NAME="${1:-alice}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="ztna-realm"
CLIENT_ID="ztna-gateway"
CLIENT_SECRET="ztna-gateway-secret-dev-key"

case "$USER_NAME" in
  alice)   PASSWORD="password123" ;;
  bob)     PASSWORD="password123" ;;
  charlie) PASSWORD="password123" ;;
  eve)     PASSWORD="password123" ;;
  *)       PASSWORD="${2:-password123}" ;;
esac

echo "[*] Requesting token for '$USER_NAME' from $KEYCLOAK_URL..." >&2

curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "grant_type=password" \
  -d "username=${USER_NAME}" \
  -d "password=${PASSWORD}" | jq -r .access_token
