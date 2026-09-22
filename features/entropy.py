"""
features/entropy.py -- Shannon entropy and diversity tracking.
"""
from __future__ import annotations

from typing import Any
from features.statistical import shannon_entropy


def record_destination_hit(store: Any, dst_ip: str, src_ip: str, ts: float) -> None:
    """Track source IPs hitting a destination IP (used for DDoS source entropy)."""
    store.record_hit_count(f"entropy:dst_sources:{dst_ip}", src_ip)
    store.record_ts(f"entropy:hits:{dst_ip}", float(ts or 0.0), src_ip)


def record_dns_query(store: Any, src_ip: str, query: str, ts: float) -> None:
    """Track DNS queries made by src_ip (used for DGA/tunneling detection)."""
    store.record_set_add(f"entropy:dns_queries:{src_ip}", query)
    store.record_ts(f"entropy:dns_events:{src_ip}", float(ts or 0.0), query)

