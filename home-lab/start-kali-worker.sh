#!/bin/sh
set -eu
cd /home/kali/m2a-worker-home
umask 077
export KALI_WORKER_REPLAY_DB_PATH=/home/kali/.local/state/m2a-worker/execution-replay.sqlite3
mkdir -p "$(dirname "$KALI_WORKER_REPLAY_DB_PATH")"
set -a
. ./worker-secrets.env
set +a
export GADE_HOME_LAB_EXPLORATORY=1
export KALI_WORKER_PROFILE=gade-experiment
export KALI_WORKER_ENFORCE_TARGET_SCOPE=true
export KALI_WORKER_ALLOWED_SCOPES=127.0.0.1/32
export GADE_NUCLEI_ACTION_ENABLED=true
export GADE_NUCLEI_TEMPLATE_MANIFEST=/home/kali/gade-approved-nuclei/approved-nuclei-templates.json
export GADE_NUCLEI_TEMPLATES_DIR=/home/kali/gade-approved-nuclei
export PATH=/home/kali/m2a-worker-home/bin:$PATH
exec .venv/bin/uvicorn kali_worker.app:app --host 127.0.0.1 --port 8000
