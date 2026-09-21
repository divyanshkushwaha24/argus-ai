"""
features/periodicity.py -- C2 beacon periodicity tracking.
"""
from __future__ import annotations

from typing import Any


def record_connection(store: Any, src_ip: str, dst_ip: str, ts: float) -> None:
    """Record timestamp of connection from src_ip to dst_ip for inter-arrival regularity analysis."""
    ts_f = float(ts or 0.0)
    store.record_ts(f"periodicity:{src_ip}:{dst_ip}", ts_f, f"{ts_f}")

