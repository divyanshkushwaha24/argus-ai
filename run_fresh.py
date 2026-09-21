#!/usr/bin/env python3
"""
Argus AI — Fresh Pipeline Runner & Dashboard Launcher.

One-click automated workflow:
1. Generates fresh synthetic PCAP captures across all 6 threat vectors.
2. Generates fresh synthetic flow telemetry with randomized, realistic parameters
   (attack rates, botnet IPs, domain entropy, beacon intervals, exfil volumes).
3. Executes the full ML & rule-based detection pipeline (pipeline.py) on this fresh data:
   - Evaluates all 6 specialized threat detectors
   - Computes calibrated risk scores and Isolation Forest anomaly baselines
   - Generates SHAP explainability summaries
   - Correlates multi-stage alerts into incident graphs
   - Writes the new findings and threat scores to PostgreSQL
4. Automatically opens the Streamlit Dashboard in the default browser at http://localhost:8501
5. Starts the Streamlit dashboard server.

Usage:
    python3 run_fresh.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Ensure project's .venv python is used if available
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
if VENV_PYTHON.exists() and sys.executable != str(VENV_PYTHON):
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), __file__] + sys.argv[1:])


def main():
    print("=" * 70)
    print("🛡️  Argus AI — Automated End-to-End Fresh Pipeline & Dashboard")
    print("=" * 70)

    # Step 1: Generate fresh synthetic PCAP captures and flow dataset
    print("\n[Step 1/3] Generating fresh synthetic PCAPs and randomized flow telemetry...")
    fresh_dataset_script = ROOT / "ingest" / "generate_fresh_dataset.py"
    res = subprocess.run([sys.executable, str(fresh_dataset_script)], cwd=str(ROOT))
    if res.returncode != 0:
        print("❌ Error generating fresh synthetic dataset.", file=sys.stderr)
        sys.exit(res.returncode)

    # Step 2: Run the full detection pipeline on the fresh dataset
    fresh_csv = ROOT / "data" / "synthetic" / "fresh_flows.csv"
    print(f"\n[Step 2/3] Running full ML detection & risk scoring pipeline on {fresh_csv.name}...")
    pipeline_script = ROOT / "pipeline.py"
    res = subprocess.run([sys.executable, str(pipeline_script), str(fresh_csv)], cwd=str(ROOT))
    if res.returncode != 0:
        print("❌ Error running detection pipeline.", file=sys.stderr)
        sys.exit(res.returncode)

    # Step 3: Launch dashboard and trigger browser open
    print("\n[Step 3/3] Opening Streamlit Threat Intelligence Dashboard...")
    print("🌐 URL: http://localhost:8501")

    # Launch browser open in background after 2 seconds
    browser_cmd = """
    (sleep 2 && (cmd.exe /c start http://localhost:8501 2>/dev/null || xdg-open http://localhost:8501 2>/dev/null || sensible-browser http://localhost:8501 2>/dev/null)) &
    """
    subprocess.Popen(browser_cmd, shell=True, cwd=str(ROOT))

    # Run Streamlit
    streamlit_bin = ROOT / ".venv" / "bin" / "streamlit"
    cmd = [str(streamlit_bin) if streamlit_bin.exists() else "streamlit", "run", "dashboard/app.py", "--server.port=8501"]
    try:
        subprocess.run(cmd, cwd=str(ROOT))
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped.")


if __name__ == "__main__":
    main()

