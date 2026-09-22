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
DEFAULT_JA3_BLOCKLIST: Set[str] = {
    "e7d705a3286e19ea42f587b344ee6865",  # Argus synthetic malware ClientHello
    "a0e9f5d64349fb13191bc781f81f42e1",  # Cobalt Strike Malleable C2
    "6734f37431670ce18779794dd34f4aa0",  # TrickBot / Emotet
    "72a589da586844d7f0818ce684948eea",  # Metasploit Meterpreter
    "51c64c77e60f3980eea90869b68c58a8",  # AsyncRAT
    "b32309a26951912be7dba376398abc3b",  # Sliver C2
    "154c1640a0294193563914a1a36423a8",  # QakBot
    "7048a1c97a89e924b162ecd2c5a93a6b",  # Dridex
}

_JA3_BLOCKLIST: Optional[Set[str]] = None


def _load_blocklist() -> Set[str]:
    """Load the JA3 blocklist from disk, falling back to built-in known malware hashes."""
    global _JA3_BLOCKLIST
    if _JA3_BLOCKLIST is not None:
        return _JA3_BLOCKLIST

    _JA3_BLOCKLIST = set(DEFAULT_JA3_BLOCKLIST)
    path = os.path.join(config.MODEL_SAVE_DIR, "ja3_blocklist.json")
    if os.path.exists(path):
        try:
            with open(path) as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    _JA3_BLOCKLIST.update(str(h).strip().lower() for h in loaded if h)
        except Exception:
            pass

    # Also check data/ja3_blacklist/blacklist.csv if present
    csv_path = "data/ja3_blacklist/blacklist.csv"
    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        _JA3_BLOCKLIST.add(line.split(",")[0].strip().lower())
        except Exception:
            pass

    try:
        save_blocklist(_JA3_BLOCKLIST)
    except Exception:
        pass

    return _JA3_BLOCKLIST


def is_ja3_blocked(ja3_hash: str) -> bool:
    """Check if a JA3 hash is on the blocklist."""
    if not ja3_hash or not isinstance(ja3_hash, str):
        return False
    h = ja3_hash.strip().lower()
    if not h or h in ("nan", "none", "null"):
        return False
    blocklist = _load_blocklist()
    return h in blocklist


def save_blocklist(hashes: Set[str]):
    """Persist the JA3 blocklist to disk."""
    os.makedirs(config.MODEL_SAVE_DIR, exist_ok=True)
    path = os.path.join(config.MODEL_SAVE_DIR, "ja3_blocklist.json")
    all_hashes = set(hashes) | DEFAULT_JA3_BLOCKLIST
    with open(path, "w") as f:
        json.dump(sorted(all_hashes), f, indent=2)


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
