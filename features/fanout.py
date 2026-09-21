"""
features/fanout.py -- Port scan and destination fan-out tracking.
"""
from __future__ import annotations

from typing import Any


def record_connection_attempt(store: Any, src_ip: str, dst_ip: str, dst_port: int, ts: float) -> None:
    """Record outbound connection attempt from src_ip to dst_ip:dst_port."""
    store.record_set_add(f"fanout:dst_ips:{src_ip}", dst_ip)
    store.record_set_add(f"fanout:dst_ports:{src_ip}", str(dst_port))
    store.record_ts(f"fanout:attempts:{src_ip}", float(ts or 0.0), f"{dst_ip}:{dst_port}")

