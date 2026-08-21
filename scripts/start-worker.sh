#!/usr/bin/env bash
set -euo pipefail
PORT="${1:-18000}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  echo "找不到 Kali Worker Python：$PYTHON" >&2
  exit 1
fi
cd "$ROOT"
exec "$PYTHON" -m uvicorn kali_worker.app:app --host 127.0.0.1 --port "$PORT"
