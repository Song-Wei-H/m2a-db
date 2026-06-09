#!/usr/bin/env bash
# Run one poll cycle on Kali/Linux.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"
$PYTHON -c "import asyncio; from worker.task_poller import poll_once; n=asyncio.run(poll_once()); print(f'processed={n}')"
