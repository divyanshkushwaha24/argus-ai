"""
Argus AI — Recon / port-scan detector (rule-based).

Signals:
  • Fan-out: unique destination ports from one source in a time window
  • Connection state: many S0/new/REJ (incomplete handshakes)
  • Confidence = min(1.0, fanout / 100)
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Union

import pandas as pd

import config
from features.statistical import zscore_to_confidence
from models.alert_schema import Detection


class ScanDetector:
    """Detects reconnaissance / port scanning from fan-out patterns."""

    def detect(self, row: Union[pd.Series, dict], context: Optional[Dict] = None) -> Optional[Detection]:
        """Evaluate one flow record for port-scan indicators.

        Uses pre-computed dataset features:
          - unique_destination_ports
          - destination_fanout
          - source_flow_count
          - flow_state
        """
        if isinstance(row, dict):
            row = dict(row)
            if "timestamp" not in row and "ts" in row:
                row["timestamp"] = str(row["ts"])

        # ── Extract features from dataset row ────────────────────────
        unique_ports = int(row.get("unique_destination_ports", 0))
        fanout = int(row.get("destination_fanout", 0))
        source_flow_count = int(row.get("source_flow_count", 0))
        flow_state = str(row.get("flow_state", ""))

        # ── Decision logic ───────────────────────────────────────────
        # Port scan = high fan-out across ports + incomplete connections
        if unique_ports < config.SCAN_FANOUT_THRESHOLD:
            return None

        # Most scan flows are SYN-only (state = "new" or S0)
        is_incomplete = flow_state in ("new", "S0", "REJ", "RSTO")

        # ── Confidence ───────────────────────────────────────────────
        confidence = min(1.0, unique_ports / config.SCAN_FANOUT_NORMALIZE)
        # Boost if connections are consistently incomplete
        if is_incomplete:
            confidence = min(1.0, confidence + 0.10)

        return Detection(
            timestamp=str(row.get("timestamp", "")),
            flow_id=str(row.get("flow_id", "")),
            src_ip=str(row.get("src_ip", "")),
            src_port=int(row.get("src_port", 0)),
            dest_ip=str(row.get("dest_ip", "")),
            dest_port=int(row.get("dest_port", 0)),
            threat_class="portscan",
            confidence=round(confidence, 4),
            evidence={
                "unique_destination_ports": unique_ports,
                "destination_fanout": fanout,
                "source_flow_count": source_flow_count,
                "flow_state": flow_state,
                "reason": self._build_reason(unique_ports, source_flow_count, flow_state),
            },
            raw_features={
                "unique_destination_ports": unique_ports,
                "destination_fanout": fanout,
                "source_flow_count": source_flow_count,
            },
        )

    @staticmethod
    def _build_reason(ports: int, flows: int, state: str) -> str:
        parts = [
            f"{ports} unique destination ports probed (threshold {config.SCAN_FANOUT_THRESHOLD})",
            f"{flows} total flows from this source",
        ]
        if state in ("new", "S0", "REJ"):
            parts.append(f"connection state '{state}' (incomplete handshake)")
        return "; ".join(parts)


_scan_instance: Optional[ScanDetector] = None


def build_detector() -> ScanDetector:
    global _scan_instance
    if _scan_instance is None:
        _scan_instance = ScanDetector()
    return _scan_instance


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

