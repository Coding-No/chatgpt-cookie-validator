#!/usr/bin/env bash
# ChatGPT Cookie Validator — launcher
# Usage: ./run.sh [--host 0.0.0.0] [--port 8787]
set -euo pipefail
cd "$(dirname "$0")"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8787}"

# parse args sederhana
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    *) echo "arg tak dikenal: $1"; exit 2;;
  esac
done

PY="${PYTHON:-python3}"

echo "[*] ChatGPT Cookie Validator"
echo "[*] python: $($PY --version 2>&1)"

# venv opsional
if [[ ! -d .venv ]]; then
  echo "[*] membuat venv .venv ..."
  $PY -m venv .venv >/dev/null 2>&1 || true
fi
if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
  PY=python
fi

echo "[*] cek dependencies ..."
$PY - <<'PYEOF' || $PY -m pip install -q -r requirements.txt
import importlib, sys
for m in ("fastapi","uvicorn","requests","pydantic"):
    try: importlib.import_module(m)
    except ImportError: sys.exit(1)
PYEOF

echo ""
echo "=================================================="
echo "  UI  ->  http://${HOST}:${PORT}"
echo "  API ->  http://${HOST}:${PORT}/docs"
echo "=================================================="
echo ""

exec $PY -m uvicorn main:app --host "$HOST" --port "$PORT" "$@"
