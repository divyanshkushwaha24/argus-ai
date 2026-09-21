#!/usr/bin/env bash
#
# Argus AI — Real-Time Streaming Detection & Live SOC Dashboard Launcher (Bash Entrypoint)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -f ".venv/bin/python" ]]; then
    PYTHON_EXEC=".venv/bin/python"
else
    PYTHON_EXEC="python3"
fi

exec "$PYTHON_EXEC" run_realtime.py "$@"

