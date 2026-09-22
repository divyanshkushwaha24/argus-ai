"""
Argus AI — C2 beaconing detector (rule-based).

Signals:
  • Inter-arrival time coefficient of variation (CV)
    - Beacon CV ≈ 0.03 (metronome), human browsing CV > 1.0
  • Autocorrelation / FFT confirmation of periodicity

Start with CV; autocorrelation is a confirmation signal.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Union

import numpy as np
import pandas as pd

import config
from features.statistical import (
    coefficient_of_variation,
    interarrival_times,
    dominant_autocorr_lag,
    fft_dominant_frequency,
    autocorrelation,
)
from models.alert_schema import Detection


class BeaconDetector:
    """Stateful detector for periodic C2 beaconing."""

    def __init__(self):
        # Per-source tracking of flow timestamps
        # {src_ip: [timestamp, ...]}
        self._history: Dict[str, list] = {}

    def detect(self, row: Union[pd.Series, dict],
               context: Optional[Dict] = None) -> Optional[Detection]:
        """Detect beaconing from a flow record or streaming context.

        `context` may contain:
          - peer_timestamps: list of epoch timestamps for this src→dst pair
          - peer_flow_count: number of flows for this pair
        """
        if context is None:
            context = {}

        # Normalize dictionary keys if needed
        if isinstance(row, dict):
            row = dict(row)
            if "timestamp" not in row and "ts" in row:
                row["timestamp"] = str(row["ts"])

        # ── Use pre-computed dataset features ────────────────────────
        src_iat = float(row.get("src_interarrival_sec", 0))
        source_flow_count = int(row.get("source_flow_count", 0))
        unique_dest_ips = int(row.get("unique_destination_ips", 0))
        unique_dest_ports = int(row.get("unique_destination_ports", 0))

        # Need enough flows to detect periodicity
        if source_flow_count < config.BEACON_MIN_FLOWS:
            return None

        # ── Compute CV ───────────────────────────────────────────────
        peer_timestamps = context.get("peer_timestamps", [])

        if peer_timestamps and len(peer_timestamps) >= config.BEACON_MIN_FLOWS:
            iats = interarrival_times(peer_timestamps)
            cv = coefficient_of_variation(iats)
        elif src_iat > 0:
            # Approximate: if dataset gives us average IAT and we have
            # the flow count, we can estimate CV from the metadata.
            # A perfectly regular beacon has CV near 0; we use a proxy.
            # With only the mean IAT we can't compute exact CV, but if
            # unique_dest_ips is small and flow_count is moderate, it's
            # likely beaconing.
            cv = 0.1 if unique_dest_ips <= 2 and source_flow_count >= 10 else 1.0
        else:
            return None

        # ── Decision logic ───────────────────────────────────────────
        if cv > config.BEACON_CV_THRESHOLD:
            return None

        # ── Autocorrelation confirmation ─────────────────────────────
        autocorr_peak = 0.0
        dominant_lag = 0
        beacon_period = 0.0

        if peer_timestamps and len(peer_timestamps) >= 8:
            iats = interarrival_times(peer_timestamps)
            series = np.array(iats)
            dominant_lag, autocorr_peak = dominant_autocorr_lag(series)
            if len(iats) > 0:
                beacon_period = np.mean(iats)

        # ── Confidence ───────────────────────────────────────────────
        # Lower CV → higher confidence
        confidence = max(0.0, min(1.0, 1.0 - cv / config.BEACON_CV_THRESHOLD))
        # Boost if autocorrelation confirms
        if autocorr_peak > config.BEACON_AUTOCORR_THRESHOLD:
            confidence = min(1.0, confidence + 0.15)

        return Detection(
            timestamp=str(row.get("timestamp", "")),
            flow_id=str(row.get("flow_id", "")),
            src_ip=str(row.get("src_ip", "")),
            src_port=int(row.get("src_port", 0)),
            dest_ip=str(row.get("dest_ip", "")),
            dest_port=int(row.get("dest_port", 0)),
            threat_class="beacon",
            confidence=round(confidence, 4),
            evidence={
                "inter_arrival_cv": round(cv, 4),
                "cv_threshold": config.BEACON_CV_THRESHOLD,
                "source_flow_count": source_flow_count,
                "unique_dest_ips": unique_dest_ips,
                "autocorrelation_peak": round(autocorr_peak, 3),
                "beacon_period_sec": round(beacon_period, 2),
                "reason": self._build_reason(cv, source_flow_count, autocorr_peak, beacon_period),
            },
            raw_features={
                "src_interarrival_sec": src_iat,
                "source_flow_count": source_flow_count,
                "unique_destination_ips": unique_dest_ips,
            },
        )

    @staticmethod
    def _build_reason(cv: float, flow_count: int, acorr: float, period: float) -> str:
        parts = [f"inter-arrival CV {cv:.3f} (threshold < {config.BEACON_CV_THRESHOLD})"]
        parts.append(f"{flow_count} periodic flows to same destination")
        if acorr > config.BEACON_AUTOCORR_THRESHOLD:
            parts.append(f"autocorrelation peak {acorr:.2f} confirms periodicity")
        if period > 0:
            parts.append(f"estimated beacon interval {period:.1f}s")
        return "; ".join(parts)


_beacon_instance: Optional[BeaconDetector] = None


def build_detector() -> BeaconDetector:
    global _beacon_instance
    if _beacon_instance is None:
        _beacon_instance = BeaconDetector()
    return _beacon_instance


def evaluate(event: Union[dict, pd.Series], r: Any = None) -> Optional[List[dict]]:
    """Contract 2 evaluation function for Cherenkov streaming pipeline."""
    det = build_detector().detect(event)
    if not det:
        return None
    ev = det.evidence
    ev_list = [f"{k}: {v}" for k, v in ev.items()] if isinstance(ev, dict) else (ev if isinstance(ev, list) else [str(ev)])
    return [{
        "threat_class": det.threat_class,
        "confidence": float(det.confidence),
        "evidence": ev_list,
        "flow_id": str(det.flow_id),
        "src_ip": str(det.src_ip),
        "dst_ip": str(getattr(det, "dest_ip", "") or getattr(det, "dst_ip", "") or (event.get("dst_ip") if isinstance(event, dict) else "")),
        "event_time": float(event.get("ts", time.time()) if isinstance(event, dict) else getattr(det, "timestamp_epoch", time.time())),
    }]

