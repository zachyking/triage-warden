#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

ENV_FILE=""
REQUIRE_CONNECTED=true

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
  --allow-unhealthy       Do not fail when connector status is not connected
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
    --allow-unhealthy)
      REQUIRE_CONNECTED=false
      shift
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
TRIAGE_URL="${TW_E2E_TRIAGE_URL:-http://localhost:${TW_E2E_TRIAGE_PORT:-8092}}"
ADMIN_USER="${TW_E2E_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${TW_E2E_ADMIN_PASSWORD:-tw_e2e_admin_password}"
TENANT_ID="${TW_E2E_TENANT_ID:-00000000-0000-0000-0000-000000000001}"

curl -fsS "$API_URL/health" >/dev/null
log_info "API health check passed: $API_URL/health"

triage_status="$(curl -fsS "$TRIAGE_URL/api/triage/status")"
if [[ "$triage_status" != *'"ready":true'* ]]; then
  log_error "Triage service is not ready: $TRIAGE_URL/api/triage/status"
  echo "$triage_status"
  exit 1
fi
log_info "Triage service ready: $TRIAGE_URL/api/triage/status"

cookie_jar="$(mktemp)"
login_html="$(mktemp)"
login_resp="$(mktemp)"
connectors_resp="$(mktemp)"

trap 'rm -f "$cookie_jar" "$login_html" "$login_resp" "$connectors_resp"' EXIT

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

connectors_status=$(curl -sS -o "$connectors_resp" -w "%{http_code}" \
  -b "$cookie_jar" \
  -H "X-Tenant-ID: $TENANT_ID" \
  "$API_URL/api/connectors")

if [[ "$connectors_status" != "200" ]]; then
  log_error "Failed to fetch connectors (HTTP $connectors_status)"
  cat "$connectors_resp"
  exit 1
fi

python3 - "$connectors_resp" "$REQUIRE_CONNECTED" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

connectors_path = Path(sys.argv[1])
require_connected = sys.argv[2].lower() == "true"
required_types = ("virustotal", "jira", "splunk", "crowdstrike", "m365")

connectors = json.loads(connectors_path.read_text(encoding="utf-8"))
by_type = {connector["connector_type"]: connector for connector in connectors}

errors: list[str] = []
for connector_type in required_types:
    connector = by_type.get(connector_type)
    if connector is None:
        errors.append(f"missing connector: {connector_type}")
        continue

    status = connector.get("status", "unknown")
    name = connector.get("name", connector_type)
    print(f"{connector_type}\t{name}\t{status}")

    if require_connected and status != "connected":
        errors.append(f"{connector_type} status is {status}, expected connected")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)
PY

log_info "Manual E2E readiness checks passed"
