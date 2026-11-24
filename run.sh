#!/usr/bin/env bash
# Start the PII Unmasking Proxy API and the Streamlit UI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

STREAMLIT_PORT="${PII_PROXY_UI_PORT:-8506}"
API_PORT="${PII_PROXY_PORT:-8006}"
API_HOST="${PII_PROXY_HOST:-127.0.0.1}"
DATA="$ROOT/data"
mkdir -p "$DATA"

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt

wait_port() {
  local port="$1"
  local tries=80
  local i=0
  while ! python3 -c "import socket; s=socket.create_connection(('127.0.0.1', $port), 0.4); s.close()" 2>/dev/null; do
    i=$((i + 1))
    if (( i >= tries )); then
      echo "Timed out waiting for port $port" >&2
      exit 1
    fi
    sleep 0.25
  done
}

cleanup() {
  if [[ -n "${API_PID:-}" ]] && kill -0 "$API_PID" 2>/dev/null; then
    kill "$API_PID" 2>/dev/null || true
  fi
  rm -f "$DATA/api.pid"
}
trap cleanup EXIT INT TERM

export PII_PROXY_PORT="$API_PORT"
export PII_PROXY_HOST="$API_HOST"
export PII_PROXY_URL="http://${API_HOST}:${API_PORT}"
export PII_PROXY_UI_PORT="$STREAMLIT_PORT"

if [[ ! -f "$DATA/demo.keys" ]]; then
  echo
  echo "=============================================================="
  echo " DEMO KEY FILE will be created at data/demo.keys"
  echo " This is a local demo key, not production key management."
  echo " The file is gitignored. Do not reuse it outside this demo."
  echo "=============================================================="
  echo
fi

echo "Starting PII proxy API on http://${API_HOST}:${API_PORT} …"
.venv/bin/python -m pii_proxy serve --host "$API_HOST" --port "$API_PORT" \
  >"$DATA/api.log" 2>&1 &
API_PID=$!
echo "$API_PID" >"$DATA/api.pid"
wait_port "$API_PORT"
if ! kill -0 "$API_PID" 2>/dev/null; then
  echo "API failed to start. Tail of data/api.log:" >&2
  tail -n 40 "$DATA/api.log" >&2
  exit 1
fi

echo
echo "PII Unmasking Proxy is ready."
echo "  UI:    http://127.0.0.1:${STREAMLIT_PORT}"
echo "  API:   http://${API_HOST}:${API_PORT}/docs"
echo "  Chain: .venv/bin/python -m pii_proxy verify-chain"
echo

exec .venv/bin/streamlit run app.py --server.headless true --server.port "$STREAMLIT_PORT" --server.address 127.0.0.1
