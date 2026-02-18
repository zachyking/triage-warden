#!/usr/bin/env bash
#
# Bootstrap a local E2E environment for Triage Warden.
#
# What it does:
# 1) Starts deploy/docker/docker-compose.test.yml
# 2) Waits for all services to be healthy
# 3) Optionally seeds baseline connectors via API login
#
# Usage:
#   ./scripts/bootstrap-e2e-infra.sh
#   ./scripts/bootstrap-e2e-infra.sh --recreate
#   ./scripts/bootstrap-e2e-infra.sh --no-seed
#   ./scripts/bootstrap-e2e-infra.sh --no-build
#
# Environment variables:
#   TW_E2E_API_URL         Default: http://localhost:8081
#   TW_E2E_TRIAGE_URL      Default: http://localhost:8092
#   TW_E2E_ADMIN_USER      Default: admin
#   TW_E2E_ADMIN_PASSWORD  Default: tw_e2e_admin_password

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_ROOT/deploy/docker/docker-compose.test.yml"

API_URL="${TW_E2E_API_URL:-http://localhost:8081}"
TRIAGE_URL="${TW_E2E_TRIAGE_URL:-http://localhost:8092}"
ADMIN_USER="${TW_E2E_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${TW_E2E_ADMIN_PASSWORD:-tw_e2e_admin_password}"

RECREATE=false
NO_BUILD=false
NO_SEED=false

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
  --recreate   Tear down and recreate containers/volumes before bootstrap
  --no-build   Skip image builds during compose up
  --no-seed    Skip connector seeding
  --help       Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

create_connector() {
  local cookie_jar="$1"
  local name="$2"
  local connector_type="$3"
  local config_json="$4"
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
    -H "content-type: application/json" \
    -X POST "$API_URL/api/connectors" \
    -d "$payload")

  if [[ "$status" == "201" ]]; then
    local connector_id
    connector_id=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$response_file" | head -n 1)
    log_info "Created connector: $name ($connector_type)"

    if [[ -n "$connector_id" ]]; then
      local test_file
      test_file="$(mktemp)"
      local test_status
      test_status=$(curl -sS -o "$test_file" -w "%{http_code}" \
        -b "$cookie_jar" \
        -X POST "$API_URL/api/connectors/$connector_id/test")
      if [[ "$test_status" == "200" ]]; then
        log_info "Tested connector: $name"
      else
        log_warn "Connector test returned HTTP $test_status for: $name"
      fi
      rm -f "$test_file"
    fi
  elif [[ "$status" == "409" ]]; then
    log_warn "Connector already exists: $name"
  else
    log_error "Failed to create connector '$name' (HTTP $status)"
    cat "$response_file"
    rm -f "$response_file"
    exit 1
  fi

  rm -f "$response_file"
}

seed_connectors() {
  local cookie_jar login_html login_resp
  cookie_jar="$(mktemp)"
  login_html="$(mktemp)"
  login_resp="$(mktemp)"

  curl -fsS -c "$cookie_jar" "$API_URL/login" -o "$login_html"

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

  create_connector "$cookie_jar" "E2E VirusTotal" "virustotal" '{"api_key":"vt_e2e_dummy_key"}'
  create_connector "$cookie_jar" "E2E Jira" "jira" '{"url":"https://jira.example.local","project_key":"SEC","api_token":"jira_e2e_dummy_token","email":"soc@example.local"}'
  create_connector "$cookie_jar" "E2E Splunk" "splunk" '{"url":"https://splunk.example.local:8089","token":"splunk_e2e_dummy_token","index":"security"}'
  create_connector "$cookie_jar" "E2E CrowdStrike" "crowdstrike" '{"client_id":"cs_e2e_client","client_secret":"cs_e2e_secret"}'
  create_connector "$cookie_jar" "E2E M365" "m365" '{"tenant_id":"11111111-1111-1111-1111-111111111111","client_id":"22222222-2222-2222-2222-222222222222","client_secret":"m365_e2e_secret"}'
  create_connector "$cookie_jar" "E2E Google Workspace" "googleworkspace" '{"service_account_json":"{}","admin_email":"admin@example.local"}'

  log_info "Connector seeding complete"
  rm -f "$cookie_jar" "$login_html" "$login_resp"
}

log_info "Bootstrapping E2E infrastructure"
log_info "Compose file: $COMPOSE_FILE"

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
echo "  1) Run tests:   ./scripts/run-integration-tests.sh --keep-containers"
echo "  2) Tear down:   $COMPOSE_CMD -f \"$COMPOSE_FILE\" down -v --remove-orphans"
