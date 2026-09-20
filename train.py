"""
Argus AI — Training pipeline.

Trains all models on train_dataset.csv (80%), evaluates on test_dataset.csv (20%).
Saves trained models to models/saved/.

Usage:
    python train.py
"""

from __future__ import annotations

import os
import sys
import json
import time

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

import config
from features.dns_features import DGA_FEATURE_COLS, add_ngram_score_column
from features.tls_features import TLS_FEATURE_COLS, save_blocklist
from models.dga_model import DGAModel
from models.tls_malware_model import TLSMalwareModel
from models.anomaly import AnomalyModel, ANOMALY_FEATURE_COLS
from models.ddos_detector import DDoSDetector
from models.beacon_detector import BeaconDetector
from models.scan_detector import ScanDetector
from models.exfil_detector import ExfilDetector
from models.fusion import fuse
from models.explain import explain_detection
from models.correlation import correlate_alerts
from models.alert_schema import Detection


def load_dataset(path: str) -> pd.DataFrame:
    """Load and preprocess a dataset CSV."""
    df = pd.read_csv(path)
    # Drop source_file if present (label leakage prevention)
    if "source_file" in df.columns:
        df = df.drop(columns=["source_file"])
    return df


def train_dga_model(df_train: pd.DataFrame) -> dict:
    """Train the DGA/DNS-tunnel XGBoost model."""
    print("\n" + "=" * 60)
    print("TRAINING: DGA / DNS-tunnel XGBoost model")
    print("=" * 60)

    # Add engineered ngram_score feature
    df = add_ngram_score_column(df_train)

    # Binary target: dns_tunnel = 1, everything else = 0
    # Only use rows that have DNS data (dns_event_count > 0) or are benign
    mask = (df["dns_event_count"] > 0) | (df["label"] == "benign")
    df_dns = df[mask].copy()

    y = (df_dns["label"] == "dns_tunnel").astype(int)
    X = df_dns[DGA_FEATURE_COLS].fillna(0)

    print(f"  Samples: {len(X)} (positive={y.sum()}, negative={(y==0).sum()})")
    print(f"  Features: {list(DGA_FEATURE_COLS)}")

    model = DGAModel()
    metrics = model.train(X, y)

    print(f"  ROC-AUC (train): {metrics['roc_auc']:.4f}")
    report = metrics["classification_report"]
    if "1" in report:
        p = report["1"]
        print(f"  Class 1 (dns_tunnel): precision={p['precision']:.3f}, "
              f"recall={p['recall']:.3f}, f1={p['f1-score']:.3f}")

    return metrics


def train_tls_model(df_train: pd.DataFrame) -> dict:
    """Train the TLS malware RandomForest model."""
    print("\n" + "=" * 60)
    print("TRAINING: TLS malware RandomForest model")
    print("=" * 60)

    # Binary target: ja3_malware = 1, everything else with TLS or benign = 0
    # Use all rows — the model should distinguish malware TLS from normal traffic
    y = (df_train["label"] == "ja3_malware").astype(int)
    X = df_train[TLS_FEATURE_COLS].fillna(0)

    print(f"  Samples: {len(X)} (positive={y.sum()}, negative={(y==0).sum()})")
    print(f"  Features: {list(TLS_FEATURE_COLS)}")

    # Collect JA3 hashes from malware rows for the blocklist
    malware_rows = df_train[df_train["label"] == "ja3_malware"]
    ja3_hashes = set()
    for _, row in malware_rows.iterrows():
        h = row.get("ja3_hash", "")
        if isinstance(h, str) and h:
            ja3_hashes.add(h)
    print(f"  JA3 blocklist entries: {len(ja3_hashes)}")

    model = TLSMalwareModel()
    metrics = model.train(X, y, malware_ja3_hashes=ja3_hashes)

    print(f"  ROC-AUC (train): {metrics['roc_auc']:.4f}")
    report = metrics["classification_report"]
    if "1" in report:
        p = report["1"]
        print(f"  Class 1 (ja3_malware): precision={p['precision']:.3f}, "
              f"recall={p['recall']:.3f}, f1={p['f1-score']:.3f}")

    return metrics


def train_anomaly_model(df_train: pd.DataFrame) -> dict:
    """Train the Isolation Forest on benign traffic only."""
    print("\n" + "=" * 60)
    print("TRAINING: Isolation Forest anomaly baseline")
    print("=" * 60)

    benign = df_train[df_train["label"] == "benign"]
    X = benign[ANOMALY_FEATURE_COLS].fillna(0)

    print(f"  Benign samples: {len(X)}")
    print(f"  Features: {list(ANOMALY_FEATURE_COLS)}")

    model = AnomalyModel()
    metrics = model.train(X)

    print(f"  Mean anomaly score (benign): {metrics['mean_score']:.4f}")
    print(f"  Std anomaly score (benign):  {metrics['std_score']:.4f}")

    return metrics


def evaluate_on_test(df_test: pd.DataFrame) -> dict:
    """Run all detectors on test data and report per-class metrics."""
    print("\n" + "=" * 60)
    print("EVALUATION on test_dataset.csv")
    print("=" * 60)

    # Load ML models
    dga = DGAModel()
    dga.load()
    tls = TLSMalwareModel()
    tls.load()

    # Rule-based detectors
    ddos_det = DDoSDetector()
    beacon_det = BeaconDetector()
    scan_det = ScanDetector()
    exfil_det = ExfilDetector()

    # Add ngram_score for DGA
    df_test = add_ngram_score_column(df_test)

    y_true = []
    y_pred = []
    alerts = []
    detection_count = 0

    for idx, row in df_test.iterrows():
        true_label = row["label"]
        detected_class = "benign"  # default

        # Run all detectors and pick the highest-confidence detection
        detections = []

        # DDoS
        det = ddos_det.detect(row)
        if det:
            detections.append(det)

        # Beacon
        det = beacon_det.detect(row)
        if det:
            detections.append(det)

        # Port scan
        det = scan_det.detect(row)
        if det:
            detections.append(det)

        # Exfil
        det = exfil_det.detect(row)
        if det:
            detections.append(det)

        # DGA (ML)
        det = dga.predict(row)
        if det:
            detections.append(det)

        # TLS malware (ML)
        det = tls.predict(row)
        if det:
            detections.append(det)

        if detections:
            # When multiple detectors fire, prefer specific over generic.
            # ML models are most specific, then threat-specific rules,
            # then generic DDoS (which can match many flow patterns).
            _SPECIFICITY = {
                "dns_tunnel": 3, "ja3_malware": 3,  # ML — highest
                "beacon": 2, "portscan": 2, "exfil": 2,  # specific rules
                "ddos": 1,  # generic — lowest priority in ties
            }
            best = max(detections,
                       key=lambda d: (d.confidence, _SPECIFICITY.get(d.threat_class, 0)))
            detected_class = best.threat_class
            detection_count += 1

            # Run fusion
            alert = fuse(best, row)
            alert.explanation = explain_detection(alert)
            alerts.append(alert)

        y_true.append(true_label)
        y_pred.append(detected_class)

    # Correlate
    alerts = correlate_alerts(alerts)

    print(f"\n  Total test samples: {len(df_test)}")
    print(f"  Detections raised: {detection_count}")
    print(f"  Alerts after fusion: {len(alerts)}")

    # Classification report
    all_labels = sorted(set(y_true + y_pred))
    print("\n  Classification Report:")
    print("-" * 60)
    report_str = classification_report(y_true, y_pred, labels=all_labels, zero_division=0)
    print(report_str)

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=all_labels)
    print("  Confusion Matrix:")
    print(f"  Labels: {all_labels}")
    print(cm)

    # Per-class report as dict
    report_dict = classification_report(y_true, y_pred, labels=all_labels,
                                        output_dict=True, zero_division=0)

    # Risk score distribution
    if alerts:
        risk_scores = [a.risk_score for a in alerts]
        print(f"\n  Risk scores: min={min(risk_scores)}, max={max(risk_scores)}, "
              f"mean={np.mean(risk_scores):.1f}")
        level_counts = {}
        for a in alerts:
            level_counts[a.risk_level] = level_counts.get(a.risk_level, 0) + 1
        print(f"  Risk levels: {level_counts}")

    return {
        "classification_report": report_dict,
        "detection_count": detection_count,
        "alert_count": len(alerts),
        "alerts_sample": [a.to_dict() for a in alerts[:5]],
    }


def main():
    start = time.time()

    print("Argus AI — Training Pipeline")
    print("=" * 60)

    # Load data
    df_train = load_dataset("dataset/train_dataset.csv")
    df_test = load_dataset("dataset/test_dataset.csv")
    print(f"Train: {len(df_train)} rows, Test: {len(df_test)} rows")

    # ── Train models ─────────────────────────────────────────────────
    dga_metrics = train_dga_model(df_train)
    tls_metrics = train_tls_model(df_train)
    anomaly_metrics = train_anomaly_model(df_train)

    # ── Evaluate on test set ─────────────────────────────────────────
    eval_metrics = evaluate_on_test(df_test)

    # ── Save metrics summary ─────────────────────────────────────────
    os.makedirs(config.MODEL_SAVE_DIR, exist_ok=True)
    metrics_summary = {
        "dga_model": dga_metrics,
        "tls_model": tls_metrics,
        "anomaly_model": anomaly_metrics,
        "evaluation": {k: v for k, v in eval_metrics.items() if k != "alerts_sample"},
    }
    with open(os.path.join(config.MODEL_SAVE_DIR, "training_metrics.json"), "w") as f:
        json.dump(metrics_summary, f, indent=2, default=str)

    elapsed = time.time() - start
    print(f"\n{'=' * 60}")
    print(f"Training complete in {elapsed:.1f}s")
    print(f"Models saved to {config.MODEL_SAVE_DIR}/")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
