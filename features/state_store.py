"""
features/state_store.py -- Redis-backed sliding window state store.
Provides persistent and in-memory storage for real-time feature extraction.
"""
from __future__ import annotations

import time
from typing import Any, Optional


class StateStore:
    """Wraps Redis connection or falls back to in-memory store for sliding windows."""

    def __init__(self, r: Optional[Any] = None, prefix: str = "cherenkov:state"):
        self.r = r
        self.prefix = prefix
        self._mem: dict[str, Any] = {}

    def key(self, name: str) -> str:
        return f"{self.prefix}:{name}"

    def record_set_add(self, key: str, member: str, expire_s: int = 3600) -> None:
        k = self.key(key)
        if self.r is not None:
            try:
                self.r.sadd(k, member)
                if expire_s > 0:
                    self.r.expire(k, expire_s)
                return
            except Exception:
                pass
        s = self._mem.setdefault(k, set())
        s.add(member)

    def record_ts(self, key: str, ts: float, member: str, window_s: float = 600.0) -> None:
        k = self.key(key)
        if self.r is not None:
            try:
                pipe = self.r.pipeline(transaction=False)
                pipe.zadd(k, {member: ts})
                pipe.zremrangebyscore(k, 0, ts - window_s)
                pipe.expire(k, int(window_s * 2))
                pipe.execute()
                return
            except Exception:
                pass
        lst = self._mem.setdefault(k, [])
        lst.append((ts, member))
        self._mem[k] = [(t, m) for t, m in lst if t >= ts - window_s]

    def record_hit_count(self, key: str, member: str, expire_s: int = 3600) -> None:
        """
        Increment a counter for `member` under `key`.
        Use Redis Hash so we can later read {ip: count} and compute real entropy.
        """
        k = self.key(key)
        if self.r is not None:
            try:
                self.r.hincrby(k, member, 1)
                if expire_s > 0:
                    self.r.expire(k, expire_s)
                return
            except Exception:
                pass
        # In-memory fallback
        d = self._mem.setdefault(k, {})
        d[member] = d.get(member, 0) + 1

    def get_hit_counts(self, key: str) -> dict[str, int]:
        """
        Return {member: count} dictionary for entropy computation.
        """
        k = self.key(key)
        if self.r is not None:
            try:
                raw = self.r.hgetall(k)
                return {
                    (m.decode("utf-8", errors="ignore") if isinstance(m, bytes) else str(m)): int(c)
                    for m, c in raw.items()
                }
            except Exception:
                pass
        return dict(self._mem.get(k, {}))

    def set_cardinality(self, key: str) -> int:
        """Return distinct member count for a set."""
        k = self.key(key)
        if self.r is not None:
            try:
                return int(self.r.scard(k))
            except Exception:
                pass
        return len(self._mem.get(k, set()))

    def set_members(self, key: str) -> set[str]:
        """Return all members of a set."""
        k = self.key(key)
        if self.r is not None:
            try:
                raw = self.r.smembers(k)
                return {
                    m.decode("utf-8", errors="ignore") if isinstance(m, bytes) else str(m)
                    for m in raw
                }
            except Exception:
                pass
        return set(self._mem.get(k, set()))

    def ts_count(self, key: str, window_s: float = 600.0) -> int:
        """Count events within sliding window."""
        k = self.key(key)
        now = time.time()
        if self.r is not None:
            try:
                return int(self.r.zcount(k, now - window_s, "+inf"))
            except Exception:
                pass
        lst = self._mem.get(k, [])
        return sum(1 for t, _ in lst if t >= now - window_s)

    def ts_timestamps(self, key: str, window_s: float = 600.0) -> list[float]:
        """Return timestamp list for events within sliding window."""
        k = self.key(key)
        now = time.time()
        if self.r is not None:
            try:
                raw = self.r.zrangebyscore(k, now - window_s, "+inf", withscores=True)
                return [float(score) for _, score in raw]
            except Exception:
                pass
        lst = self._mem.get(k, [])
        return sorted([float(t) for t, _ in lst if t >= now - window_s])

