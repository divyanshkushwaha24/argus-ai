"""
Argus AI — Streaming pipeline runner.

Reads dataset rows (simulating streaming from Zeek/Suricata),
routes each flow to relevant detectors, fuses, explains, correlates,
and writes alerts to the database.

Usage:
    python pipeline.py                   # run on test dataset
    python pipeline.py dataset/train_dataset.csv  # run on specific file
"""

from __future__ import annotations

from pathlib import Path
import os
import sys
import time

__path__ = [str(Path(__file__).resolve().parent / "pipeline")]
_repo_root = Path(__file__).resolve().parent
_candidate_sites = [
    _repo_root / ".venv" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages",
    Path(os.path.expanduser(f"~/.local/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")),
]
for _s in _candidate_sites:
    if _s.is_dir() and str(_s) not in sys.path:
        sys.path.insert(0, str(_s))

from typing import List

import pandas as pd

from features.dns_features import add_ngram_score_column
from models.ddos_detector import DDoSDetector
from models.beacon_detector import BeaconDetector
from models.scan_detector import ScanDetector
from models.exfil_detector import ExfilDetector
from models.dga_model import DGAModel
from models.tls_malware_model import TLSMalwareModel
from models.fusion import fuse
from models.explain import explain_detection
from models.correlation import correlate_alerts, get_incident_summary
from models.alert_schema import Alert
from db import create_alerts_table, insert_alerts_batch, clear_alerts


def run_pipeline(csv_path: str = "dataset/test_dataset.csv"):
    """Run the full detection pipeline on a dataset CSV."""

    print(f"Argus AI — Pipeline Runner")
    print(f"{'=' * 60}")
    print(f"Input: {csv_path}")

    # ── Load data ────────────────────────────────────────────────────
    df = pd.read_csv(csv_path)
    if "source_file" in df.columns:
        df = df.drop(columns=["source_file"])
    df = add_ngram_score_column(df)
    print(f"Loaded {len(df)} flow records")

    # ── Initialize detectors ─────────────────────────────────────────
    ddos_det = DDoSDetector()
    beacon_det = BeaconDetector()
    scan_det = ScanDetector()
    exfil_det = ExfilDetector()
    dga_model = DGAModel()
    dga_model.load()
    tls_model = TLSMalwareModel()
    tls_model.load()

    print("All detectors initialized")

    # ── Process flows ────────────────────────────────────────────────
    alerts: List[Alert] = []
    detections_by_class = {}
    start_time = time.time()

    for idx, row in df.iterrows():
        # Route to all relevant detectors
        detections = []

        det = ddos_det.detect(row)
        if det:
            detections.append(det)

        det = beacon_det.detect(row)
        if det:
            detections.append(det)

        det = scan_det.detect(row)
        if det:
            detections.append(det)

        det = exfil_det.detect(row)
        if det:
            detections.append(det)

        det = dga_model.predict(row)
        if det:
            detections.append(det)

        det = tls_model.predict(row)
        if det:
            detections.append(det)

        # Fuse each detection into an alert
        for detection in detections:
            alert = fuse(detection, row)
            alert.explanation = explain_detection(alert)
            alerts.append(alert)

            tc = detection.threat_class
            detections_by_class[tc] = detections_by_class.get(tc, 0) + 1

    elapsed = time.time() - start_time
    flows_per_sec = len(df) / elapsed if elapsed > 0 else 0

    print(f"\nProcessed {len(df)} flows in {elapsed:.2f}s ({flows_per_sec:.0f} flows/sec)")
    print(f"Detections raised: {len(alerts)}")
    print(f"By class: {detections_by_class}")

    # ── Correlate into incidents ─────────────────────────────────────
    alerts = correlate_alerts(alerts)
    incidents = get_incident_summary(alerts)

    print(f"\nIncidents: {len(incidents)}")
    for inc in incidents[:5]:
        print(f"  [{inc['risk_level']}] {inc['src_ip']}: "
              f"{inc['alert_count']} alerts, risk={inc['combined_risk']}, "
              f"threats={inc['threat_classes']}")

    # ── Write to database ────────────────────────────────────────────
    create_alerts_table()
    clear_alerts()  # fresh run
    insert_alerts_batch(alerts)
    print(f"\n{len(alerts)} alerts written to database")

    # ── Throughput report ────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"THROUGHPUT: {flows_per_sec:.0f} flows/sec sustained")
    print(f"LATENCY: {elapsed / max(1, len(df)) * 1000:.2f} ms/flow average")
    print(f"{'=' * 60}")

    return alerts


if __name__ == "__main__":
    csv = sys.argv[1] if len(sys.argv) > 1 else "dataset/test_dataset.csv"
    run_pipeline(csv)
