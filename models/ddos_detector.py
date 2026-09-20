"""
Argus AI — DDoS detector (rule-based).

Signals:
  • Flow rate z-score (rolling window over recent history)
  • Source-IP entropy (high = many spoofed/botnet sources)

No training data needed.  The "model" is the recent past.
"""

from __future__ import annotations

from typing import Dict, List, Optional

import pandas as pd

import config
from features.statistical import shannon_entropy, rolling_zscore, zscore_to_confidence
from models.alert_schema import Detection


class DDoSDetector:
    """Stateful detector that tracks flow-rate history per window."""

    def __init__(self):
        # Rolling window of flow counts per second
        self._flow_history: List[float] = []
        self._window_size = config.DDOS_FLOW_RATE_WINDOW

    def detect(self, row: pd.Series, context: Optional[Dict] = None) -> Optional[Detection]:
        """Evaluate one flow record for DDoS indicators.

        `context` may contain:
          - flow_rate:        current flows/sec in this time window
          - window_mean:      mean flow rate over recent history
          - window_std:       std of flow rate over recent history
          - src_ips_in_window: list of source IPs in the current window
        """
        if context is None:
            context = {}

        # ── Use pre-computed dataset features ────────────────────────
        src_entropy = float(row.get("source_ip_entropy_in_file", 0))
        src_ip_count = int(row.get("source_ip_count_in_file", 1))
        flow_state = str(row.get("flow_state", ""))
        packet_rate = float(row.get("packet_rate", 0))
        source_flow_count = int(row.get("source_flow_count", 1))

        # ── Compute z-score from context or dataset features ─────────
        # For DDoS with spoofed sources, each src IP generates 1 flow,
        # so source_flow_count=1.  Use the file-level source_ip_count as
        # a better proxy for "how much traffic is hitting the target".
        flow_rate = context.get("flow_rate", max(source_flow_count, src_ip_count))
        window_mean = context.get("window_mean", 10.0)  # default baseline
        window_std = context.get("window_std", 5.0)

        z = rolling_zscore(flow_rate, window_mean, window_std)

        # ── Decision logic ───────────────────────────────────────────
        # DDoS = high source diversity (entropy or count).
        # The source-diversity check is what separates DDoS from
        # portscan / beacon / tunnel, which all have high flow counts
        # but few source IPs.
        is_high_rate = z > config.DDOS_ZSCORE_THRESHOLD
        is_high_entropy = src_entropy > config.DDOS_SRC_ENTROPY_HIGH
        is_many_sources = src_ip_count > 50

        # Must have source-diversity signal — this IS what makes it DDoS
        if not (is_high_entropy or is_many_sources):
            return None

        # Must also have either high rate or many sources
        if not (is_high_rate or is_many_sources):
            return None

        # ── Confidence ───────────────────────────────────────────────
        confidence = zscore_to_confidence(z, config.Z_CONFIDENCE_CEILING)
        # Boost confidence if multiple signals agree
        if is_high_entropy and is_many_sources:
            confidence = min(1.0, confidence + 0.15)

        return Detection(
            timestamp=str(row.get("timestamp", "")),
            flow_id=str(row.get("flow_id", "")),
            src_ip=str(row.get("src_ip", "")),
            src_port=int(row.get("src_port", 0)),
            dest_ip=str(row.get("dest_ip", "")),
            dest_port=int(row.get("dest_port", 0)),
            threat_class="ddos",
            confidence=round(confidence, 4),
            evidence={
                "flow_rate_zscore": round(z, 2),
                "source_ip_entropy": round(src_entropy, 2),
                "source_ip_count": src_ip_count,
                "flow_state": flow_state,
                "reason": self._build_reason(z, src_entropy, src_ip_count),
            },
            raw_features={
                "source_ip_entropy_in_file": src_entropy,
                "source_ip_count_in_file": src_ip_count,
                "packet_rate": packet_rate,
                "source_flow_count": source_flow_count,
            },
        )

    @staticmethod
    def _build_reason(z: float, entropy: float, count: int) -> str:
        parts = []
        if z > config.DDOS_ZSCORE_THRESHOLD:
            parts.append(f"flow rate z-score {z:.1f} (threshold {config.DDOS_ZSCORE_THRESHOLD})")
        if entropy > config.DDOS_SRC_ENTROPY_HIGH:
            parts.append(f"source IP entropy {entropy:.2f} (high = many distinct sources)")
        if count > 50:
            parts.append(f"{count} unique source IPs in window")
        return "; ".join(parts) if parts else "DDoS indicators detected"
