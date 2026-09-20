"""
Argus AI — TLS / encrypted-session feature extraction.

Two layers:
  1. JA3 blocklist lookup (instant, rule-based baseline)
  2. RandomForest classifier on flow-level features (stretch)
"""

from __future__ import annotations

import json
import os
from typing import Dict, Optional, Set

import numpy as np
import pandas as pd

import config

# ── JA3 blocklist ────────────────────────────────────────────────────
# Loaded from a JSON file (list of known-bad JA3 hashes).
# Source: abuse.ch SSLBL + custom lab fingerprints.
_JA3_BLOCKLIST: Optional[Set[str]] = None


def _load_blocklist() -> Set[str]:
    """Load the JA3 blocklist from disk, or return an empty set."""
    global _JA3_BLOCKLIST
    if _JA3_BLOCKLIST is not None:
        return _JA3_BLOCKLIST

    path = os.path.join(config.MODEL_SAVE_DIR, "ja3_blocklist.json")
    if os.path.exists(path):
        with open(path) as f:
            _JA3_BLOCKLIST = set(json.load(f))
    else:
        # Start with an empty set — will be populated during training
        _JA3_BLOCKLIST = set()
    return _JA3_BLOCKLIST


def is_ja3_blocked(ja3_hash: str) -> bool:
    """Check if a JA3 hash is on the blocklist."""
    if not ja3_hash or not isinstance(ja3_hash, str):
        return False
    blocklist = _load_blocklist()
    return ja3_hash in blocklist


def save_blocklist(hashes: Set[str]):
    """Persist the JA3 blocklist to disk."""
    os.makedirs(config.MODEL_SAVE_DIR, exist_ok=True)
    path = os.path.join(config.MODEL_SAVE_DIR, "ja3_blocklist.json")
    with open(path, "w") as f:
        json.dump(sorted(hashes), f, indent=2)


# ── Feature columns for the TLS RF classifier ───────────────────────
TLS_FEATURE_COLS = [
    "packets_to_server",
    "packets_to_client",
    "bytes_to_server",
    "bytes_to_client",
    "total_packets",
    "total_bytes",
    "average_packet_size",
    "upload_download_ratio",
    "tls_event_count",
    "source_flow_count",
    "flow_duration",
    "packet_rate",
    "byte_rate",
]


def extract_tls_features(row: pd.Series) -> Dict[str, float]:
    """Extract feature vector for the TLS malware classifier."""
    features = {}
    for col in TLS_FEATURE_COLS:
        val = row.get(col, 0)
        features[col] = float(val) if pd.notna(val) else 0.0
    return features
