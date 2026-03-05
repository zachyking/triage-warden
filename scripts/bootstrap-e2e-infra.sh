#!/usr/bin/env bash
#
# Bootstrap a local E2E environment for Triage Warden.
#
# What it does:
# 1) Starts a compose stack for either baseline test mode or persistent real mode
# 2) Waits for all services to be healthy
# 3) Optionally seeds connectors via API login
#
# Usage:
#   ./scripts/bootstrap-e2e-infra.sh
#   ./scripts/bootstrap-e2e-infra.sh --recreate
#   ./scripts/bootstrap-e2e-infra.sh --mode real --env-file config/local/e2e-real.env --connector-config config/examples/e2e-real-connectors.json
#   ./scripts/bootstrap-e2e-infra.sh --no-seed
#   ./scripts/bootstrap-e2e-infra.sh --no-build
#
# Environment variables:
#   TW_E2E_API_URL         Default: http://localhost:8081
#   TW_E2E_API_PORT        Default: 8081 (used for docker compose port mapping)
#   TW_E2E_TRIAGE_URL      Default: http://localhost:8092
#   TW_E2E_TRIAGE_PORT     Default: 8092 (used for docker compose port mapping)
#   TW_E2E_ADMIN_USER      Default: admin
#   TW_E2E_ADMIN_PASSWORD  Default: tw_e2e_admin_password
#   TW_E2E_TENANT_ID       Default: 00000000-0000-0000-0000-000000000001

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

extract_url_port() {
  local url="$1"
  local fallback="$2"
  local hostport="${url#*://}"
  hostport="${hostport%%/*}"
  if [[ "$hostport" == *:* ]]; then
    echo "${hostport##*:}"
  else
    echo "$fallback"
  fi
}

RECREATE=false
NO_BUILD=false
NO_SEED=false
MODE="baseline"
ENV_FILE=""
CONNECTOR_CONFIG=""

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
  --mode MODE  Bootstrap mode: baseline (default) or real
  --env-file PATH
               Source environment variables from a shell env file
  --connector-config PATH
               JSON connector seed config for --mode real
  --recreate   Tear down and recreate containers/volumes before bootstrap
  --no-build   Skip image builds during compose up
  --no-seed    Skip connector seeding
  --help       Show this help
EOF
}

load_env_file() {
  local env_file="$1"
  if [[ ! -f "$env_file" ]]; then
    log_error "Env file not found: $env_file"
    exit 1
  fi

  log_info "Loading environment overrides from: $env_file"
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
    --mode)
      if [[ $# -lt 2 ]]; then
        log_error "--mode requires a value"
        exit 1
      fi
      MODE="$2"
      shift 2
      ;;
    --env-file)
      if [[ $# -lt 2 ]]; then
        log_error "--env-file requires a path"
        exit 1
      fi
      ENV_FILE="$2"
      shift 2
      ;;
    --connector-config)
      if [[ $# -lt 2 ]]; then
        log_error "--connector-config requires a path"
        exit 1
      fi
      CONNECTOR_CONFIG="$2"
      shift 2
      ;;
    --recreate)
      RECREATE=true
      shift
      ;;
    --no-build)
      NO_BUILD=true
      shift
      ;;
    --no-seed)
      NO_SEED=true
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

if [[ "$MODE" != "baseline" && "$MODE" != "real" ]]; then
  log_error "Unsupported mode: $MODE"
  usage
  exit 1
fi

if [[ -n "$ENV_FILE" ]]; then
  ENV_FILE="$(resolve_path "$ENV_FILE")"
  load_env_file "$ENV_FILE"
fi

if [[ -n "$CONNECTOR_CONFIG" ]]; then
  CONNECTOR_CONFIG="$(resolve_path "$CONNECTOR_CONFIG")"
fi

if [[ "$MODE" == "real" ]]; then
  COMPOSE_FILE="$PROJECT_ROOT/deploy/docker/docker-compose.manual-e2e.yml"
else
  COMPOSE_FILE="$PROJECT_ROOT/deploy/docker/docker-compose.test.yml"
fi

if [[ -n "${TW_E2E_API_URL:-}" ]]; then
  API_URL="$TW_E2E_API_URL"
else
  API_URL="http://localhost:${TW_E2E_API_PORT:-8081}"
fi

if [[ -n "${TW_E2E_TRIAGE_URL:-}" ]]; then
  TRIAGE_URL="$TW_E2E_TRIAGE_URL"
else
  TRIAGE_URL="http://localhost:${TW_E2E_TRIAGE_PORT:-8092}"
fi

export TW_E2E_API_PORT="${TW_E2E_API_PORT:-$(extract_url_port "$API_URL" "8081")}"
export TW_E2E_TRIAGE_PORT="${TW_E2E_TRIAGE_PORT:-$(extract_url_port "$TRIAGE_URL" "8092")}"
ADMIN_USER="${TW_E2E_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${TW_E2E_ADMIN_PASSWORD:-tw_e2e_admin_password}"
TENANT_ID="${TW_E2E_TENANT_ID:-00000000-0000-0000-0000-000000000001}"

if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD="docker-compose"
else
  log_error "Docker Compose is required"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  log_error "curl is required"
  exit 1
fi

if [[ "$MODE" == "real" ]] && ! command -v python3 >/dev/null 2>&1; then
  log_error "python3 is required for --mode real"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  log_error "Docker daemon is not running. Start Docker Desktop (or docker service) and retry."
  exit 1
fi

compose() {
  # shellcheck disable=SC2086
  $COMPOSE_CMD -f "$COMPOSE_FILE" "$@"
}

wait_for_service_healthy() {
  local service="$1"
  local max_attempts=90
  local attempt=1

  while [[ $attempt -le $max_attempts ]]; do
    if compose ps "$service" 2>/dev/null | grep -q "healthy"; then
      log_info "Service healthy: $service"
      return 0
    fi
    sleep 2
    attempt=$((attempt + 1))
  done

  log_error "Service did not become healthy: $service"
  compose logs "$service" | tail -n 120 || true
  exit 1
}

wait_for_http() {
  local url="$1"
  local name="$2"
  local max_attempts=60
  local attempt=1

  while [[ $attempt -le $max_attempts ]]; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      log_info "Endpoint ready: $name ($url)"
      return 0
    fi
    sleep 2
    attempt=$((attempt + 1))
  done

  log_error "Endpoint did not become ready: $name ($url)"
  exit 1
}

wait_for_triage_ready() {
  local url="$1/api/triage/status"
  local max_attempts=60
  local attempt=1
  local response=""

  while [[ $attempt -le $max_attempts ]]; do
    response="$(curl -fsS "$url" 2>/dev/null || true)"
    if [[ "$response" == *'"ready":true'* ]]; then
      log_info "Triage service ready for live LLM usage ($url)"
      return 0
    fi
    sleep 2
    attempt=$((attempt + 1))
  done

  log_error "Triage service did not report ready=true: $url"
  if [[ -n "$response" ]]; then
    echo "$response"
  fi
  exit 1
}

run_real_mode_preflight() {
  local args=(validate)
  if [[ -n "$ENV_FILE" ]]; then
    args+=(--env-file "$ENV_FILE")
  fi
  if [[ -n "$CONNECTOR_CONFIG" ]]; then
    args+=(--connector-config "$CONNECTOR_CONFIG")
  fi
  if [[ "$NO_SEED" == "false" ]]; then
    args+=(--require-connectors)
  fi

  python3 "$PROJECT_ROOT/scripts/e2e_real_config.py" "${args[@]}"
}

create_connector() {
  local cookie_jar="$1"
  local name="$2"
  local connector_type="$3"
  local config_json="$4"
  local verify_connector="${5:-false}"
  local response_file
  response_file="$(mktemp)"

  local payload
  payload=$(
    cat <<JSON
{"name":"$name","connector_type":"$connector_type","config":$config_json,"enabled":true}
JSON
  )

  local status
  status=$(curl -sS -o "$response_file" -w "%{http_code}" \
    -b "$cookie_jar" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -H "content-type: application/json" \
    -X POST "$API_URL/api/connectors" \
    -d "$payload")

  if [[ "$status" == "201" ]]; then
    local connector_id
    connector_id=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$response_file" | head -n 1)
    log_info "Created connector: $name ($connector_type)"

    if [[ "$verify_connector" == "true" && -n "$connector_id" ]]; then
      local test_file
      test_file="$(mktemp)"
      local test_status
      test_status=$(curl -sS -o "$test_file" -w "%{http_code}" \
        -b "$cookie_jar" \
        -H "X-Tenant-ID: $TENANT_ID" \
        -X POST "$API_URL/api/connectors/$connector_id/test")
      if [[ "$test_status" == "200" ]]; then
        if grep -Eq '"success"[[:space:]]*:[[:space:]]*true' "$test_file"; then
          log_info "Connector test passed: $name"
        else
          local test_message
          test_message=$(sed -n 's/.*"message":"\([^"]*\)".*/\1/p' "$test_file" | head -n 1)
          if [[ -n "$test_message" ]]; then
            log_warn "Connector test failed for $name: $test_message"
          else
            log_warn "Connector test failed for $name"
          fi
        fi
      else
        log_warn "Connector test returned HTTP $test_status for: $name"
      fi
      rm -f "$test_file"
    elif [[ "$verify_connector" != "true" ]]; then
      log_info "Seeded placeholder connector without live verification: $name"
    fi
  elif [[ "$status" == "409" ]]; then
    if [[ "$MODE" == "real" ]]; then
      log_warn "Connector already exists, reconciling config: $name"
      update_existing_connector "$cookie_jar" "$name" "$config_json" "$verify_connector"
    else
      log_warn "Connector already exists: $name"
    fi
  else
    log_error "Failed to create connector '$name' (HTTP $status)"
    cat "$response_file"
    rm -f "$response_file"
    exit 1
  fi

  rm -f "$response_file"
}

find_connector_id_by_name() {
  local cookie_jar="$1"
  local name="$2"
  local connectors_file
  connectors_file="$(mktemp)"

  local status
  status=$(curl -sS -o "$connectors_file" -w "%{http_code}" \
    -b "$cookie_jar" \
    -H "X-Tenant-ID: $TENANT_ID" \
    "$API_URL/api/connectors")

  if [[ "$status" != "200" ]]; then
    log_error "Failed to list connectors while reconciling '$name' (HTTP $status)"
    cat "$connectors_file"
    rm -f "$connectors_file"
    exit 1
  fi

  local connector_id
  connector_id=$(python3 - "$connectors_file" "$name" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

connectors = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
name = sys.argv[2]

for connector in connectors:
    if connector.get("name") == name:
        print(connector.get("id", ""))
        break
PY
)

  rm -f "$connectors_file"
  echo "$connector_id"
}

test_connector_by_id() {
  local cookie_jar="$1"
  local connector_id="$2"
  local name="$3"
  local test_file
  test_file="$(mktemp)"

  local test_status
  test_status=$(curl -sS -o "$test_file" -w "%{http_code}" \
    -b "$cookie_jar" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -X POST "$API_URL/api/connectors/$connector_id/test")

  if [[ "$test_status" == "200" ]]; then
    if grep -Eq '"success"[[:space:]]*:[[:space:]]*true' "$test_file"; then
      log_info "Connector test passed: $name"
    else
      local test_message
      test_message=$(sed -n 's/.*"message":"\([^"]*\)".*/\1/p' "$test_file" | head -n 1)
      if [[ -n "$test_message" ]]; then
        log_warn "Connector test failed for $name: $test_message"
      else
        log_warn "Connector test failed for $name"
      fi
    fi
  else
    log_warn "Connector test returned HTTP $test_status for: $name"
  fi

  rm -f "$test_file"
}

update_existing_connector() {
  local cookie_jar="$1"
  local name="$2"
  local config_json="$3"
  local verify_connector="${4:-false}"
  local connector_id
  connector_id="$(find_connector_id_by_name "$cookie_jar" "$name")"

  if [[ -z "$connector_id" ]]; then
    log_error "Could not find existing connector id for '$name'"
    exit 1
  fi

  local payload
  payload=$(
    cat <<JSON
{"name":"$name","config":$config_json,"enabled":true}
JSON
  )

  local response_file
  response_file="$(mktemp)"
  local status
  status=$(curl -sS -o "$response_file" -w "%{http_code}" \
    -b "$cookie_jar" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -H "content-type: application/json" \
    -X PUT "$API_URL/api/connectors/$connector_id" \
    -d "$payload")

  if [[ "$status" != "200" ]]; then
    log_error "Failed to update connector '$name' (HTTP $status)"
    cat "$response_file"
    rm -f "$response_file"
    exit 1
  fi

  log_info "Updated connector: $name"
  rm -f "$response_file"

  if [[ "$verify_connector" == "true" ]]; then
    test_connector_by_id "$cookie_jar" "$connector_id" "$name"
  fi
}

seed_connectors_from_config() {
  local cookie_jar="$1"
  local rendered_connectors
  rendered_connectors="$(mktemp)"

  local render_args=(render-connectors --connector-config "$CONNECTOR_CONFIG")
  if [[ -n "$ENV_FILE" ]]; then
    render_args+=(--env-file "$ENV_FILE")
  fi

  python3 "$PROJECT_ROOT/scripts/e2e_real_config.py" "${render_args[@]}" >"$rendered_connectors"

  while IFS=$'\t' read -r name connector_type verify_connector config_json; do
    [[ -z "$name" ]] && continue
    create_connector "$cookie_jar" "$name" "$connector_type" "$config_json" "$verify_connector"
  done <"$rendered_connectors"

  rm -f "$rendered_connectors"
}

seed_connectors() {
  local cookie_jar login_html login_resp
  cookie_jar="$(mktemp)"
  login_html="$(mktemp)"
  login_resp="$(mktemp)"

  curl -fsS -c "$cookie_jar" -H "X-Tenant-ID: $TENANT_ID" "$API_URL/login" -o "$login_html"

  local csrf_token
  csrf_token=$(grep -o 'name="csrf_token" value="[^"]*"' "$login_html" | head -n 1 | sed 's/.*value="//;s/"$//')

  if [[ -z "$csrf_token" ]]; then
    log_error "Could not extract login CSRF token from $API_URL/login"
    rm -f "$cookie_jar" "$login_html" "$login_resp"
    exit 1
  fi

  local login_status
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
    log_warn "If first bootstrap, ensure docker-compose.test uses TW_E2E_ADMIN_PASSWORD."
    cat "$login_resp"
    rm -f "$cookie_jar" "$login_html" "$login_resp"
    exit 1
  fi

  log_info "Authenticated as '$ADMIN_USER', seeding connectors"

  if [[ "$MODE" == "real" ]]; then
    seed_connectors_from_config "$cookie_jar"
  else
    create_connector "$cookie_jar" "E2E VirusTotal" "virustotal" '{"api_key":"vt_e2e_dummy_key","requests_per_minute":4}'
    create_connector "$cookie_jar" "E2E Jira" "jira" '{"base_url":"https://jira.example.local","project_key":"SEC","api_token":"jira_e2e_dummy_token","username":"soc@example.local"}'
    create_connector "$cookie_jar" "E2E Splunk" "splunk" '{"base_url":"https://splunk.example.local:8089","username":"soc_service","password":"splunk_e2e_dummy_password","app":"search"}'
    create_connector "$cookie_jar" "E2E CrowdStrike" "crowdstrike" '{"client_id":"cs_e2e_client","client_secret":"cs_e2e_secret"}'
    create_connector "$cookie_jar" "E2E M365" "m365" '{"tenant_id":"11111111-1111-1111-1111-111111111111","client_id":"22222222-2222-2222-2222-222222222222","client_secret":"m365_e2e_secret"}'
  fi

  log_info "Connector seeding complete"
  rm -f "$cookie_jar" "$login_html" "$login_resp"
}

log_info "Bootstrapping E2E infrastructure"
log_info "Mode: $MODE"
log_info "Compose file: $COMPOSE_FILE"
log_info "API URL: $API_URL (host port ${TW_E2E_API_PORT})"
log_info "Triage URL: $TRIAGE_URL (host port ${TW_E2E_TRIAGE_PORT})"

if [[ "$MODE" == "real" ]]; then
  if [[ "$NO_SEED" == "false" && -z "$CONNECTOR_CONFIG" ]]; then
    log_error "--mode real requires --connector-config unless --no-seed is used"
    exit 1
  fi

  run_real_mode_preflight
fi

if [[ "$RECREATE" == true ]]; then
  log_info "Recreating stack (--recreate)"
  compose down -v --remove-orphans || true
fi

if [[ "$NO_BUILD" == true ]]; then
  compose up -d
else
  compose up -d --build
fi

wait_for_service_healthy "postgres-test"
wait_for_service_healthy "qdrant-test"
wait_for_service_healthy "redis-test"
wait_for_service_healthy "tw-triage-test"
wait_for_service_healthy "tw-api-test"

wait_for_http "$API_URL/health" "tw-api-test"
wait_for_http "$TRIAGE_URL/health" "tw-triage-test"

if [[ "$MODE" == "real" ]]; then
  wait_for_triage_ready "$TRIAGE_URL"
fi

if [[ "$NO_SEED" == false ]]; then
  seed_connectors
else
  log_info "Skipping connector seeding (--no-seed)"
fi

log_info "E2E bootstrap complete"
echo ""
echo "API URL:             $API_URL"
echo "Triage Service URL:  $TRIAGE_URL"
echo "Admin user:          $ADMIN_USER"
echo "Admin password:      [from TW_E2E_ADMIN_PASSWORD or default]"
echo ""
echo "Next:"
if [[ "$MODE" == "real" ]]; then
  echo "  1) Verify triage:  curl -fsS $TRIAGE_URL/api/triage/status"
  echo "  2) Manual checks:  open $API_URL in a browser and validate connector health"
  echo "  3) Tear down:      $COMPOSE_CMD -f \"$COMPOSE_FILE\" down --remove-orphans"
else
  echo "  1) Run tests:   ./scripts/run-integration-tests.sh --preserve-state"
  echo "  2) Tear down:   $COMPOSE_CMD -f \"$COMPOSE_FILE\" down -v --remove-orphans"
fi
