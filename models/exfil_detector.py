"""
Argus AI — Data exfiltration detector (rule-based).

Signals:
  • upload_download_ratio per internal host (outbound:inbound bytes)
  • Rolling z-score on outbound byte volume
  • Internal subnet check (must be from an internal source)
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Dict, List, Optional

import pandas as pd

import config
from features.statistical import rolling_zscore, zscore_to_confidence
from models.alert_schema import Detection


def _is_internal(ip_str: str) -> bool:
    """Check if an IP address belongs to any configured internal subnet."""
    try:
        addr = ip_address(ip_str)
        return any(addr in net for net in config.INTERNAL_SUBNETS)
    except (ValueError, TypeError):
        return False


class ExfilDetector:
    """Detects data exfiltration from asymmetric byte ratios."""

    def detect(self, row: pd.Series, context: Optional[Dict] = None) -> Optional[Detection]:
        """Evaluate one flow record for exfiltration indicators.

        Uses pre-computed dataset features:
          - upload_download_ratio
          - bytes_to_server, bytes_to_client
          - total_bytes
        """
        if context is None:
            context = {}

        # ── Extract features ─────────────────────────────────────────
        src_ip = str(row.get("src_ip", ""))
        ratio = float(row.get("upload_download_ratio", 0))
        bytes_out = float(row.get("bytes_to_server", 0))
        bytes_in = float(row.get("bytes_to_client", 0))
        total_bytes = float(row.get("total_bytes", 0))

        # ── Direction check ──────────────────────────────────────────
        # Exfiltration = large outbound from an INTERNAL host
        if not _is_internal(src_ip):
            return None

        # ── Decision logic ───────────────────────────────────────────
        if ratio < config.EXFIL_RATIO_THRESHOLD:
            return None

        if bytes_out < config.EXFIL_MIN_OUTBOUND_BYTES:
            return None

        # ── Z-score on ratio ─────────────────────────────────────────
        # Use context if available; otherwise fall back to dataset-level stats
        window_mean = context.get("ratio_mean", 2.0)   # normal ratio baseline
        window_std = context.get("ratio_std", 1.5)
        z = rolling_zscore(ratio, window_mean, window_std)

        # ── Confidence ───────────────────────────────────────────────
        confidence = zscore_to_confidence(z, config.Z_CONFIDENCE_CEILING)
        # Boost for extreme ratios
        if ratio > 100:
            confidence = min(1.0, confidence + 0.20)
        if ratio > 1000:
            confidence = min(1.0, confidence + 0.20)

        return Detection(
            timestamp=str(row.get("timestamp", "")),
            flow_id=str(row.get("flow_id", "")),
            src_ip=src_ip,
            src_port=int(row.get("src_port", 0)),
            dest_ip=str(row.get("dest_ip", "")),
            dest_port=int(row.get("dest_port", 0)),
            threat_class="exfil",
            confidence=round(confidence, 4),
            evidence={
                "upload_download_ratio": round(ratio, 2),
                "bytes_outbound": int(bytes_out),
                "bytes_inbound": int(bytes_in),
                "total_bytes": int(total_bytes),
                "ratio_zscore": round(z, 2),
                "reason": self._build_reason(ratio, bytes_out, z),
            },
            raw_features={
                "upload_download_ratio": ratio,
                "bytes_to_server": bytes_out,
                "bytes_to_client": bytes_in,
                "total_bytes": total_bytes,
            },
        )

    @staticmethod
    def _build_reason(ratio: float, bytes_out: float, z: float) -> str:
        parts = [
            f"outbound:inbound ratio {ratio:.1f} (threshold {config.EXFIL_RATIO_THRESHOLD})",
            f"{bytes_out / 1024:.0f} KB outbound (min {config.EXFIL_MIN_OUTBOUND_BYTES / 1024:.0f} KB)",
        ]
        if z > config.EXFIL_ZSCORE_THRESHOLD:
            parts.append(f"ratio z-score {z:.1f} (well above normal)")
        return "; ".join(parts)
