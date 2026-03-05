#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

ENV_FILE=""
CONNECTOR_CONFIG=""
SKIP_PERSONAS=false
SKIP_READINESS=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --env-file PATH         Source environment variables from a shell env file
  --connector-config PATH JSON connector seed config for real mode
  --skip-personas         Do not reseed fake-org personas after bootstrap
  --skip-readiness        Do not run readiness checks after reseed
  --help                  Show this help
EOF
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
        echo "--env-file requires a path" >&2
        exit 1
      fi
      ENV_FILE="$2"
      shift 2
      ;;
    --connector-config)
      if [[ $# -lt 2 ]]; then
        echo "--connector-config requires a path" >&2
        exit 1
      fi
      CONNECTOR_CONFIG="$2"
      shift 2
      ;;
    --skip-personas)
      SKIP_PERSONAS=true
      shift
      ;;
    --skip-readiness)
      SKIP_READINESS=true
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$ENV_FILE" || -z "$CONNECTOR_CONFIG" ]]; then
  echo "--env-file and --connector-config are required" >&2
  exit 1
fi

ENV_FILE="$(resolve_path "$ENV_FILE")"
CONNECTOR_CONFIG="$(resolve_path "$CONNECTOR_CONFIG")"

"$SCRIPT_DIR/bootstrap-e2e-infra.sh" \
  --mode real \
  --recreate \
  --env-file "$ENV_FILE" \
  --connector-config "$CONNECTOR_CONFIG"

if [[ "$SKIP_PERSONAS" == "false" ]]; then
  "$SCRIPT_DIR/seed-e2e-personas.sh" --env-file "$ENV_FILE"
fi

if [[ "$SKIP_READINESS" == "false" ]]; then
  "$SCRIPT_DIR/check-e2e-real-readiness.sh" --env-file "$ENV_FILE"
fi
