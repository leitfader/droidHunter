#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="${VENV_PATH:-$ROOT_DIR/.venv}"
API_HOST="${API_HOST:-0.0.0.0}"
API_PORT="${API_PORT:-8000}"
UI_PORT="${UI_PORT:-3000}"

if [ ! -d "$VENV_PATH" ]; then
  python -m venv "$VENV_PATH"
fi

# shellcheck disable=SC1090
source "$VENV_PATH/bin/activate"
pip install -r "$ROOT_DIR/backend/requirements.txt"

if [ ! -d "$ROOT_DIR/web/node_modules" ]; then
  (cd "$ROOT_DIR/web" && npm install)
fi

uvicorn backend.api:app --host "$API_HOST" --port "$API_PORT" &
API_PID=$!

cleanup() {
  if kill -0 "$API_PID" >/dev/null 2>&1; then
    kill "$API_PID"
  fi
}
trap cleanup EXIT

echo "API running on http://$API_HOST:$API_PORT"
echo "Web UI running on http://localhost:$UI_PORT"

(cd "$ROOT_DIR/web" && PORT="$UI_PORT" npm start)
