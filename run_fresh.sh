#!/usr/bin/env bash
# Argus AI — Fresh Pipeline Runner & Dashboard Launcher

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"

# Use .venv python if available
if [[ -f "$REPO/.venv/bin/python" ]]; then
    PYTHON="$REPO/.venv/bin/python"
    STREAMLIT="$REPO/.venv/bin/streamlit"
else
    PYTHON="python3"
    STREAMLIT="streamlit"
fi

echo "======================================================================"
echo "🛡️  Argus AI — Automated End-to-End Fresh Pipeline & Dashboard"
echo "======================================================================"

echo ""
echo "[Step 1/3] Generating fresh synthetic PCAPs and randomized flow telemetry..."
"$PYTHON" ingest/generate_fresh_dataset.py

echo ""
echo "[Step 2/3] Running full ML detection & risk scoring pipeline on fresh flows..."
"$PYTHON" pipeline.py data/synthetic/fresh_flows.csv

echo ""
echo "[Step 3/3] Launching Streamlit Threat Intelligence Dashboard..."
echo "🌐 URL: http://localhost:8501"

(sleep 2 && (cmd.exe /c start http://localhost:8501 2>/dev/null || xdg-open http://localhost:8501 2>/dev/null || sensible-browser http://localhost:8501 2>/dev/null || true)) &

"$STREAMLIT" run dashboard/app.py --server.port=8501

