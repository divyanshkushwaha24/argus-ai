"""
features/fingerprint.py -- JA3 fingerprint matching against known malware hashes.
"""
from __future__ import annotations

import csv
import os
from typing import Any, Set

from features.tls_features import _load_blocklist


def load_blacklist(path: str = "data/ja3_blacklist/blacklist.csv") -> Set[str]:
    """Load JA3 hashes from CSV file, falling back to built-in JA3 blocklist."""
    hashes: Set[str] = set(_load_blocklist())
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    if row and not row[0].startswith("#"):
                        h = row[0].strip().lower()
                        if h:
                            hashes.add(h)
        except Exception:
            pass
    return hashes


def check_ja3(store: Any, src_ip: str, ja3: str, blacklist: Set[str], ts: float) -> bool:
    """Check whether a JA3 hash is in the blacklist and record event."""
    h = str(ja3).strip().lower()
    is_malicious = h in blacklist
    if is_malicious:
        store.record_set_add(f"fingerprint:malicious:{src_ip}", h)
        store.record_ts(f"fingerprint:hits:{src_ip}", float(ts or 0.0), h)
    return is_malicious
