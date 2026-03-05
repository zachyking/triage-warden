#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

ENV_FILE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --env-file PATH         Source environment variables from a shell env file
  --help                  Show this help
EOF
}

load_env_file() {
  local env_file="$1"
  if [[ ! -f "$env_file" ]]; then
    log_error "Env file not found: $env_file"
    exit 1
  fi

  set -a
  # shellcheck disable=SC1090
  source "$env_file"
  set +a
}

resolve_path() {
  local input_path="$1"
  if [[ "$input_path" = /* ]]; then
    echo "$input_path"
  else
    echo "$PROJECT_ROOT/$input_path"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      if [[ $# -lt 2 ]]; then
        log_error "--env-file requires a path"
        exit 1
      fi
      ENV_FILE="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      log_error "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -n "$ENV_FILE" ]]; then
  ENV_FILE="$(resolve_path "$ENV_FILE")"
  load_env_file "$ENV_FILE"
fi

if ! command -v curl >/dev/null 2>&1; then
  log_error "curl is required"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  log_error "python3 is required"
  exit 1
fi

API_URL="${TW_E2E_API_URL:-http://localhost:${TW_E2E_API_PORT:-8081}}"
ADMIN_USER="${TW_E2E_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${TW_E2E_ADMIN_PASSWORD:-tw_e2e_admin_password}"
TENANT_ID="${TW_E2E_TENANT_ID:-00000000-0000-0000-0000-000000000001}"
EMAIL_DOMAIN="${TW_E2E_USER_EMAIL_DOMAIN:-tw-fakeco.local}"

cookie_jar="$(mktemp)"
login_html="$(mktemp)"
login_resp="$(mktemp)"
users_resp="$(mktemp)"
create_resp="$(mktemp)"

trap 'rm -f "$cookie_jar" "$login_html" "$login_resp" "$users_resp" "$create_resp"' EXIT

curl -fsS -c "$cookie_jar" -H "X-Tenant-ID: $TENANT_ID" "$API_URL/login" -o "$login_html"

csrf_token=$(grep -o 'name="csrf_token" value="[^"]*"' "$login_html" | head -n 1 | sed 's/.*value="//;s/"$//')
if [[ -z "$csrf_token" ]]; then
  log_error "Could not extract CSRF token from $API_URL/login"
  exit 1
fi

login_status=$(curl -sS -o "$login_resp" -w "%{http_code}" \
  -b "$cookie_jar" -c "$cookie_jar" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -H "content-type: application/x-www-form-urlencoded" \
  -X POST "$API_URL/login" \
  --data-urlencode "username=$ADMIN_USER" \
  --data-urlencode "password=$ADMIN_PASSWORD" \
  --data-urlencode "csrf_token=$csrf_token")

if [[ "$login_status" != "302" && "$login_status" != "303" ]]; then
  log_error "Login failed for '$ADMIN_USER' (HTTP $login_status)"
  cat "$login_resp"
  exit 1
fi

users_status=$(curl -sS -o "$users_resp" -w "%{http_code}" \
  -b "$cookie_jar" \
  -H "X-Tenant-ID: $TENANT_ID" \
  "$API_URL/api/admin/users?page=1&per_page=100")

if [[ "$users_status" != "200" ]]; then
  log_error "Failed to list existing users (HTTP $users_status)"
  cat "$users_resp"
  exit 1
fi

existing_users="$(python3 - "$users_resp" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for user in payload.get("users", []):
    print(user["username"])
PY
)"

seed_persona() {
  local username="$1"
  local role="$2"
  local display_name="$3"
  local email_local_part="$4"
  local password_var="$5"
  local default_password="$6"
  local email="${email_local_part}@${EMAIL_DOMAIN}"
  local password="${!password_var:-$default_password}"

  if grep -Fxq "$username" <<<"$existing_users"; then
    log_info "User already exists: $username"
    return 0
  fi

  local payload
  payload=$(python3 - "$email" "$username" "$password" "$role" "$display_name" <<'PY'
from __future__ import annotations

import json
import sys

print(
    json.dumps(
        {
            "email": sys.argv[1],
            "username": sys.argv[2],
            "password": sys.argv[3],
            "role": sys.argv[4],
            "display_name": sys.argv[5],
        },
        separators=(",", ":"),
    )
)
PY
)

  local status
  status=$(curl -sS -o "$create_resp" -w "%{http_code}" \
    -b "$cookie_jar" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -H "content-type: application/json" \
    -X POST "$API_URL/api/admin/users" \
    -d "$payload")

  if [[ "$status" == "201" ]]; then
    log_info "Created persona: $username ($role)"
    existing_users="${existing_users}"$'\n'"${username}"
    return 0
  fi

  log_error "Failed to create persona '$username' (HTTP $status)"
  cat "$create_resp"
  exit 1
}

seed_persona "incident_manager" "admin" "Incident Manager" "incident.manager" "TW_E2E_INCIDENT_MANAGER_PASSWORD" "IncidentMgr!E2E2026"
seed_persona "approver_security" "admin" "Security Approver" "approver.security" "TW_E2E_APPROVER_SECURITY_PASSWORD" "ApproverSec!E2E2026"
seed_persona "analyst_level1" "analyst" "Analyst Level 1" "analyst.level1" "TW_E2E_ANALYST_LEVEL1_PASSWORD" "AnalystL1!E2E2026"
seed_persona "analyst_level2" "analyst" "Analyst Level 2" "analyst.level2" "TW_E2E_ANALYST_LEVEL2_PASSWORD" "AnalystL2!E2E2026"
seed_persona "viewer_exec" "viewer" "Executive Viewer" "viewer.exec" "TW_E2E_VIEWER_EXEC_PASSWORD" "ViewerExec!E2E2026"

log_info "Persona seeding complete"
