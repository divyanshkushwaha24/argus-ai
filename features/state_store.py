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

