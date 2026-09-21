#!/usr/bin/env python3
"""
pipeline/consumer.py -- Cherenkov pipeline orchestrator + detection worker
===========================================================================

One file, two roles, one entry point.

ROLE 1 - ORCHESTRATOR  (`python3 -m pipeline.consumer up`)
    Brings the whole prototype up in dependency order, waits for a single manual
    trigger ("start simulation"), then lets the data flow through every stage on
    its own until you stop it:

        preflight -> docker compose (Redis/Postgres) -> veth "virtual tap" +
        read-only enforcement -> detection workers -> event processor -> sensor
        -> READY -> [ trigger ] -> tcpreplay -> ... -> drain -> IDLE

ROLE 2 - DETECTION WORKER  (`python3 -m pipeline.consumer worker`, spawned by `up`)
    Consumes normalized events from a Redis Stream (consumer group, at-least-once),
    runs every detector, fuses risk, correlates incidents, and writes alerts to
    the sink (Postgres via `alerting.writer`, JSONL fallback).

DATA FLOW (who does what)
    tcpreplay -> veth0 => veth1 (listen-only) -> Zeek/Suricata -> JSON logs
      -> streaming/event_processor.py  : parse + normalize + update Redis windows,
                                         THEN XADD the event to STREAM (contract 1)
      -> this file (worker)            : detectors -> fusion -> incidents -> sink
      -> Postgres -> dashboard/app.py  : the dashboard only ever reads Postgres

INTEGRATION CONTRACTS (the only things teammates must honour)
  1. Event (event_processor -> stream)   XADD <stream> * data '<json>'
       required : ts (event time, epoch seconds), flow_id, src_ip, event_type
       optional : dst_ip, src_port, dst_port, proto, bytes_out, bytes_in,
                  pkts_out, pkts_in, conn_state, dns_query, dns_qtype, dns_rcode,
                  tls_sni, ja3, ja3s ...  (detectors read what they need)
       ORDER MATTERS: update the Redis windows first, publish to the stream after,
       so detectors always see state that already includes the event.
       NEVER use wall-clock time in place of `ts` (breaks offline replays).
  2. Detector (models/*_detector.py, models/dga_model.py, ...)
       module-level  evaluate(event: dict, r: redis.Redis) -> list[dict] | None
       (or a `Detector` class / `build_detector()` exposing .evaluate(event, r))
       each returned dict: threat_class, confidence (0-1), evidence (list[str],
       plain language), flow_id, src_ip; optional: dst_ip, anomaly (0-1), detector.
  3. Fusion (models/fusion.py)           fuse(threat_class, p, a, recency) -> 0..100
       optional; a built-in reference implementation is used until it exists.
  4. Correlation (models/correlation.py) correlate(alert: dict, r) -> incident dict
       optional; a built-in Redis-backed correlator is used until it exists.
  5. Sink (alerting/writer.py)           write_alert(alert: dict),
                                         upsert_incident(incident: dict)
       both must be idempotent on alert_id / incident_id.

Every contract degrades gracefully: a missing or crashing module is logged, isolated
and reported in `status`; it never takes the pipeline down.

CONFIGURATION: environment variables, see `Config.from_env` (all have defaults).
EXIT CODES: 0 clean, 1 runtime failure, 2 preflight failed.
Linux only for `up` (veth, tc, tcpreplay); `worker`, `status`, tests run anywhere.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import logging
import math
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # lets `python3 pipeline/consumer.py` import models.*, alerting.*
    sys.path.insert(0, str(ROOT))

# When executed via sudo or directly, ensure project's .venv and user's site-packages are found
_candidate_sites = [
    ROOT / ".venv" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages",
    Path(os.path.expanduser(f"~/.local/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")),
]
_sudo_user = os.environ.get("SUDO_USER")
if _sudo_user:
    try:
        import pwd
        _u_home = pwd.getpwnam(_sudo_user).pw_dir
        _candidate_sites.insert(0, Path(_u_home) / ".local" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages")
        _candidate_sites.insert(0, ROOT / ".venv" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages")
    except Exception:
        pass

for _s in _candidate_sites:
    if _s.is_dir() and str(_s) not in sys.path:
        sys.path.insert(0, str(_s))
        existing_pp = os.environ.get("PYTHONPATH", "")
        os.environ["PYTHONPATH"] = f"{_s}:{ROOT}:{existing_pp}" if existing_pp else f"{_s}:{ROOT}"

import redis

log = logging.getLogger("cherenkov")

SCHEMA_VERSION = "1.1"

# ---------------------------------------------------------------------------
# Domain constants (single source of truth: docs/alert_schema.md, docs/model_notes.md)
# ---------------------------------------------------------------------------
THREAT_CLASSES = (
    "DDOS",
    "C2_BEACONING",
    "DGA_DNS_TUNNELING",
    "ENCRYPTED_MALWARE",
    "RECON_PORT_SCAN",
    "DATA_EXFILTRATION",
)
_ALIASES = {
    "ddos": "DDOS", "volumetric_ddos": "DDOS", "dos": "DDOS", "flood": "DDOS",
    "beacon": "C2_BEACONING", "beaconing": "C2_BEACONING", "c2": "C2_BEACONING",
    "botnet_c2": "C2_BEACONING",
    "dga": "DGA_DNS_TUNNELING", "dns_tunnel": "DGA_DNS_TUNNELING",
    "dns_tunneling": "DGA_DNS_TUNNELING", "dns_tunnelling": "DGA_DNS_TUNNELING",
    "tls_malware": "ENCRYPTED_MALWARE", "encrypted_session_malware": "ENCRYPTED_MALWARE",
    "scan": "RECON_PORT_SCAN", "port_scan": "RECON_PORT_SCAN", "portscan": "RECON_PORT_SCAN",
    "recon": "RECON_PORT_SCAN",
    "exfil": "DATA_EXFILTRATION", "exfiltration": "DATA_EXFILTRATION",
}
_ALIASES.update({c.lower(): c for c in THREAT_CLASSES})

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Fusion parameters: weights (w1..w4 = P_detector, A_anomaly, S_severity_prior, R_recency)
# and severity prior S. PROVISIONAL engineering defaults, see docs/model_notes.md s4.
# models/fusion.py, once it exists, becomes the single owner of these numbers.
FUSION_PARAMS: dict[str, tuple[tuple[float, float, float, float], float]] = {
    "DDOS":              ((0.45, 0.25, 0.20, 0.10), 0.75),
    "C2_BEACONING":      ((0.45, 0.20, 0.25, 0.10), 0.85),
    "DGA_DNS_TUNNELING": ((0.50, 0.15, 0.25, 0.10), 0.65),
    "ENCRYPTED_MALWARE": ((0.50, 0.15, 0.25, 0.10), 0.70),
    "RECON_PORT_SCAN":   ((0.40, 0.20, 0.30, 0.10), 0.30),
    "DATA_EXFILTRATION": ((0.40, 0.20, 0.30, 0.10), 0.90),
}

MODE_CHOICES = ("original", "pps", "mbps", "multiplier", "topspeed")


def canonical_threat_class(value: Any) -> str:
    key = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    try:
        return _ALIASES[key]
    except KeyError:
        raise ValueError(f"unknown threat_class {value!r}; expected one of {THREAT_CLASSES}") from None


def severity_for(risk_score: int) -> str:
    if risk_score <= 30:
        return "LOW"
    if risk_score <= 60:
        return "MEDIUM"
    if risk_score <= 80:
        return "HIGH"
    return "CRITICAL"


def utc_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="milliseconds")


def parse_iso(text: str) -> float:
    return datetime.fromisoformat(text).timestamp()


def _clip01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _round_half_up(x: float) -> int:
    return int(math.floor(x + 0.5))


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def _as_bool(text: str) -> bool:
    return text.strip().lower() in ("1", "true", "yes", "on")


def _env(name: str, default: Any, cast: Callable[[str], Any] = str) -> Any:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return cast(raw)
    except (TypeError, ValueError):
        raise SystemExit(f"[config] invalid value for {name}: {raw!r}") from None


DEFAULT_DETECTOR_MODULES = (
    "models.ddos_detector",
    "models.beacon_detector",
    "models.dga_model",
    "models.tls_malware_model",
    "models.scan_detector",
    "models.exfil_detector",
)


@dataclass(frozen=True)
class Config:
    redis_url: str = "redis://localhost:6379/0"
    prefix: str = "cherenkov"
    stream: str = "cherenkov:events"
    dlq: str = "cherenkov:dlq"
    group: str = "cherenkov-detect"
    batch: int = 200
    block_ms: int = 1000
    stream_maxlen: int = 200_000
    cooldown_s: float = 30.0
    recency_window_s: float = 600.0
    recency_half_life_s: float = 120.0
    incident_gap_s: float = 600.0
    detectors: tuple[str, ...] = DEFAULT_DETECTOR_MODULES
    sink: str = "auto"                       # auto | postgres | jsonl
    jsonl_path: Path = ROOT / "data" / "raw" / "alerts.jsonl"
    dead_letter_path: Path = ROOT / "data" / "raw" / "dead_letter.jsonl"
    log_dir: Path = ROOT / "data" / "raw" / "logs"
    tx_iface: str = "veth0"                  # "production side" of the virtual tap
    rx_iface: str = "veth1"                  # monitor side: listen-only
    pcap: Path = ROOT / "data" / "replay" / "sample.pcap"
    replay_bin: str = "tcpreplay"
    replay_extra: str = ""
    priv_prefix: str = "sudo -n"
    processor_cmd: str = f"{sys.executable} -m streaming.event_processor"
    sensor_cmd: str = ""
    pg_host: str = "localhost"
    pg_port: int = 5432
    workers: int = 1
    drain_quiet_s: float = 3.0
    drain_timeout_s: float = 120.0
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Config":
        prefix = _env("CHERENKOV_PREFIX", "cherenkov")
        dets = _env("CHERENKOV_DETECTORS", None)
        return cls(
            redis_url=_env("REDIS_URL", cls.redis_url),
            prefix=prefix,
            stream=_env("CHERENKOV_STREAM", f"{prefix}:events"),
            dlq=_env("CHERENKOV_DLQ", f"{prefix}:dlq"),
            group=_env("CHERENKOV_GROUP", cls.group),
            batch=_env("CHERENKOV_BATCH", cls.batch, int),
            block_ms=_env("CHERENKOV_BLOCK_MS", cls.block_ms, int),
            stream_maxlen=_env("CHERENKOV_STREAM_MAXLEN", cls.stream_maxlen, int),
            cooldown_s=_env("CHERENKOV_COOLDOWN_S", cls.cooldown_s, float),
            recency_window_s=_env("CHERENKOV_RECENCY_WINDOW_S", cls.recency_window_s, float),
            recency_half_life_s=_env("CHERENKOV_RECENCY_HALF_LIFE_S", cls.recency_half_life_s, float),
            incident_gap_s=_env("CHERENKOV_INCIDENT_GAP_S", cls.incident_gap_s, float),
            detectors=tuple(m.strip() for m in dets.split(",") if m.strip()) if dets else DEFAULT_DETECTOR_MODULES,
            sink=_env("CHERENKOV_SINK", cls.sink).lower(),
            jsonl_path=_env("CHERENKOV_JSONL_PATH", cls.jsonl_path, Path),
            dead_letter_path=_env("CHERENKOV_DEAD_LETTER_PATH", cls.dead_letter_path, Path),
            log_dir=_env("CHERENKOV_LOG_DIR", cls.log_dir, Path),
            tx_iface=_env("CHERENKOV_TX_IFACE", cls.tx_iface),
            rx_iface=_env("CHERENKOV_RX_IFACE", cls.rx_iface),
            pcap=_env("CHERENKOV_PCAP", cls.pcap, Path),
            replay_bin=_env("CHERENKOV_REPLAY_BIN", cls.replay_bin),
            replay_extra=_env("CHERENKOV_REPLAY_EXTRA", cls.replay_extra),
            priv_prefix=_env("CHERENKOV_PRIV_PREFIX", cls.priv_prefix),
            processor_cmd=_env("CHERENKOV_PROCESSOR_CMD", cls.processor_cmd),
            sensor_cmd=_env("CHERENKOV_SENSOR_CMD", cls.sensor_cmd),
            pg_host=_env("CHERENKOV_PG_HOST", cls.pg_host),
            pg_port=_env("CHERENKOV_PG_PORT", cls.pg_port, int),
            workers=max(1, _env("CHERENKOV_WORKERS", cls.workers, int)),
            drain_quiet_s=_env("CHERENKOV_DRAIN_QUIET_S", cls.drain_quiet_s, float),
            drain_timeout_s=_env("CHERENKOV_DRAIN_TIMEOUT_S", cls.drain_timeout_s, float),
            log_level=_env("CHERENKOV_LOG_LEVEL", cls.log_level).upper(),
        )


class Keys:
    """Every Redis key the pipeline owns, in one place."""

    def __init__(self, prefix: str):
        self.p = prefix
        self.state = f"{prefix}:state"
        self.ctl = f"{prefix}:ctl"
        self.metrics = f"{prefix}:metrics"
        self.metrics_reset = f"{prefix}:metrics_reset"
        self.incident_seq = f"{prefix}:incident_seq"

    def hb(self, name: str) -> str:
        return f"{self.p}:hb:{name}"

    def lat(self, name: str) -> str:
        return f"{self.p}:metrics:lat:{name}"

    def cooldown(self, src: str, cls: str) -> str:
        return f"{self.p}:cd:{src}:{cls}"

    def hist(self, src: str) -> str:
        return f"{self.p}:hist:{src}"

    def incident_open(self, src: str) -> str:
        return f"{self.p}:inc_open:{src}"

    def incident(self, incident_id: str) -> str:
        return f"{self.p}:inc:{incident_id}"


def connect_redis(cfg: Config) -> redis.Redis:
    return redis.Redis.from_url(
        cfg.redis_url,
        decode_responses=True,
        socket_keepalive=True,
        health_check_interval=30,
        socket_connect_timeout=5,
        retry_on_timeout=True,
    )


# ---------------------------------------------------------------------------
# Detection object + validation (contract 2)
# ---------------------------------------------------------------------------
@dataclass
class Detection:
    threat_class: str
    confidence: float
    evidence: list[str]
    flow_id: str
    src_ip: str
    dst_ip: Optional[str] = None
    anomaly: float = 0.0
    detector: str = ""
    event_time: float = 0.0


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _finite(value: Any, name: str) -> float:
    try:
        x = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} is not a number: {value!r}") from None
    if not math.isfinite(x):
        raise ValueError(f"{name} is not finite: {value!r}")
    return x


def coerce_detection(item: Any, event: Mapping[str, Any], detector_name: str) -> Detection:
    """Turn whatever a detector returned into a validated Detection (or raise ValueError)."""
    threat_class = canonical_threat_class(_field(item, "threat_class"))
    confidence = _clip01(_finite(_field(item, "confidence"), "confidence"))
    anomaly = _clip01(_finite(_field(item, "anomaly", 0.0) or 0.0, "anomaly"))
    ev = _field(item, "evidence")
    if isinstance(ev, str):
        ev = [ev]
    elif isinstance(ev, Mapping):
        ev = [f"{k}: {v}" for k, v in ev.items()]
    if not isinstance(ev, (list, tuple)) or not ev or not all(isinstance(s, str) and s.strip() for s in ev):
        raise ValueError("evidence must be a non-empty list of plain-language strings")
    flow_id = str(_field(item, "flow_id") or event.get("flow_id") or "")
    src_ip = str(_field(item, "src_ip") or event.get("src_ip") or "")
    if not flow_id or not src_ip:
        raise ValueError("flow_id and src_ip are required (detector or event must supply them)")
    dst = _field(item, "dst_ip") or event.get("dst_ip")
    et = _finite(_field(item, "event_time") or event.get("ts"), "event_time")
    return Detection(
        threat_class=threat_class, confidence=confidence, evidence=[s.strip() for s in ev],
        flow_id=flow_id, src_ip=src_ip, dst_ip=str(dst) if dst else None, anomaly=anomaly,
        detector=str(_field(item, "detector") or detector_name), event_time=et,
    )


def normalize_event(fields: Mapping[str, str], msg_id: str) -> dict[str, Any]:
    """Validate a stream entry against contract 1. Raises ValueError on a bad event."""
    raw = fields.get("data")
    if raw is None:
        raise ValueError("stream entry has no 'data' field")
    try:
        ev = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"data is not valid JSON: {exc}") from None
    if not isinstance(ev, dict):
        raise ValueError("data must be a JSON object")
    for key in ("ts", "flow_id", "src_ip", "event_type"):
        if ev.get(key) in (None, ""):
            raise ValueError(f"missing required field {key!r}")
    ev["ts"] = _finite(ev["ts"], "ts")
    ev["flow_id"] = str(ev["flow_id"])
    ev["src_ip"] = str(ev["src_ip"])
    ev["_stream_id"] = msg_id
    ev["_ingest_ms"] = int(msg_id.split("-")[0])
    return ev


class ManagedDetector:
    """Wraps one detector callable with error isolation and a circuit breaker."""

    TRIP_AFTER = 5
    COOLDOWN_S = 30.0

    def __init__(self, name: str, fn: Callable[[dict, Any], Any]):
        self.name = name
        self.fn = fn
        self.consecutive_failures = 0
        self.disabled_until = 0.0
        self.errors = 0
        self.calls = 0

    def run(self, event: dict, r: Any) -> tuple[list[Detection], int, int]:
        """Returns (detections, error_count, contract_violation_count)."""
        now = time.monotonic()
        if now < self.disabled_until:
            return [], 0, 0
        self.calls += 1
        try:
            out = self.fn(event, r)
            self.consecutive_failures = 0
        except redis.RedisError:
            raise  # infrastructure problem, not a detector bug: let the worker back off + retry
        except Exception as exc:  # noqa: BLE001 - detectors are untrusted plugins
            self.errors += 1
            self.consecutive_failures += 1
            if self.errors <= 3 or self.errors % 100 == 0:
                log.warning("detector %s raised %s: %s (total errors %d)", self.name, type(exc).__name__, exc, self.errors)
            if self.consecutive_failures >= self.TRIP_AFTER:
                self.disabled_until = now + self.COOLDOWN_S
                self.consecutive_failures = 0
                log.error("detector %s tripped its circuit breaker; disabled for %.0fs", self.name, self.COOLDOWN_S)
            return [], 1, 0
        if out is None:
            return [], 0, 0
        if isinstance(out, Mapping) or hasattr(out, "threat_class"):
            out = [out]
        detections: list[Detection] = []
        violations = 0
        for item in out:
            try:
                detections.append(coerce_detection(item, event, self.name))
            except ValueError as exc:
                violations += 1
                if violations <= 3:
                    log.warning("detector %s broke the detection contract: %s", self.name, exc)
        return detections, 0, violations


def load_detector(module_name: str) -> Optional[ManagedDetector]:
    try:
        mod = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001
        log.warning("detector module %s not loaded (%s: %s)", module_name, type(exc).__name__, exc)
        return None
    fn = None
    try:
        if callable(getattr(mod, "evaluate", None)):
            fn = mod.evaluate
        elif callable(getattr(mod, "build_detector", None)):
            fn = mod.build_detector().evaluate
        elif isinstance(getattr(mod, "Detector", None), type):
            fn = mod.Detector().evaluate
    except Exception as exc:  # noqa: BLE001
        log.error("detector module %s failed to initialise: %s: %s", module_name, type(exc).__name__, exc)
        return None
    if fn is None:
        log.warning("detector module %s exposes no evaluate()/Detector/build_detector(); skipped", module_name)
        return None
    log.info("detector loaded: %s", module_name)
    return ManagedDetector(module_name, fn)


def load_detectors(cfg: Config) -> list[ManagedDetector]:
    loaded = [d for d in (load_detector(m) for m in cfg.detectors) if d]
    if not loaded:
        log.warning("NO detectors loaded: the pipeline will run but can raise no alerts")
    return loaded


# ---------------------------------------------------------------------------
# Fusion (contract 3): reference implementation of docs/model_notes.md s4
# ---------------------------------------------------------------------------
def fuse_builtin(threat_class: str, p_detector: float, a_anomaly: float, recency: float) -> int:
    weights, prior = FUSION_PARAMS[threat_class]
    x = weights[0] * _clip01(p_detector) + weights[1] * _clip01(a_anomaly) + weights[2] * prior + weights[3] * _clip01(recency)
    return _round_half_up(100.0 * _clip01(x))


def resolve_fusion() -> tuple[Callable[[str, float, float, float], int], str]:
    try:
        mod = importlib.import_module("models.fusion")
        fn = getattr(mod, "fuse", None)
        if callable(fn):
            return fn, "models.fusion"
        log.warning("models.fusion has no fuse(); using the built-in reference fusion")
    except Exception as exc:  # noqa: BLE001
        log.warning("models.fusion unavailable (%s); using the built-in reference fusion", exc)
    return fuse_builtin, "builtin"


def recency_score(prior_event_times: Iterable[float], now_event_time: float, half_life_s: float) -> float:
    """R = 1 - exp(-m),  m = sum_i 2^(-dt_i / half_life)  over prior alerts from the same source."""
    m = 0.0
    for t in prior_event_times:
        dt = now_event_time - t
        if dt >= 0:
            m += 2.0 ** (-dt / half_life_s)
    return _clip01(1.0 - math.exp(-m))


# ---------------------------------------------------------------------------
# Alert building + strict validation (docs/alert_schema.md)
# ---------------------------------------------------------------------------
def make_alert_id(flow_id: str, threat_class: str, detector: str) -> str:
    return hashlib.sha1(f"{flow_id}|{threat_class}|{detector}".encode()).hexdigest()[:32]


_ALERT_REQUIRED = (
    "alert_id", "timestamp", "event_time", "flow_id", "threat_class", "confidence", "risk_score",
    "severity", "evidence", "incident_id", "src_ip", "dst_ip", "detector", "schema_version",
)


def validate_alert(a: Mapping[str, Any]) -> None:
    missing = [k for k in _ALERT_REQUIRED if k not in a]
    if missing:
        raise ValueError(f"alert missing fields: {missing}")
    extra = [k for k in a if k not in _ALERT_REQUIRED]
    if extra:
        raise ValueError(f"alert has unknown fields: {extra}")
    if a["threat_class"] not in THREAT_CLASSES:
        raise ValueError(f"bad threat_class {a['threat_class']!r}")
    if not (isinstance(a["confidence"], (int, float)) and 0.0 <= a["confidence"] <= 1.0):
        raise ValueError("confidence must be within [0, 1]")
    if not (isinstance(a["risk_score"], int) and not isinstance(a["risk_score"], bool) and 0 <= a["risk_score"] <= 100):
        raise ValueError("risk_score must be an int within [0, 100]")
    if a["severity"] not in SEVERITIES or a["severity"] != severity_for(a["risk_score"]):
        raise ValueError("severity inconsistent with risk_score")
    ev = a["evidence"]
    if not (isinstance(ev, list) and ev and all(isinstance(s, str) and s for s in ev)):
        raise ValueError("evidence must be a non-empty list of strings")
    if not (isinstance(a["flow_id"], str) and a["flow_id"] and isinstance(a["src_ip"], str) and a["src_ip"]):
        raise ValueError("flow_id and src_ip must be non-empty strings")
    if a["incident_id"] is not None and not isinstance(a["incident_id"], str):
        raise ValueError("incident_id must be a string or null")
    for k in ("timestamp", "event_time"):
        parse_iso(a[k])  # raises ValueError if malformed
    if a["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")


# ---------------------------------------------------------------------------
# Metrics (feeds `status` and docs/throughput_benchmark.md)
# ---------------------------------------------------------------------------
def percentile(sorted_values: Sequence[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    idx = min(len(sorted_values) - 1, max(0, math.ceil(q / 100.0 * len(sorted_values)) - 1))
    return float(sorted_values[idx])


class Metrics:
    def __init__(self, keys: Keys, name: str, window: int = 5000):
        self.keys = keys
        self.name = name
        self.counters: defaultdict[str, int] = defaultdict(int)
        self._flushed: dict[str, int] = {}
        self.alert_latency_ms: deque[float] = deque(maxlen=window)
        self.proc_ms: deque[float] = deque(maxlen=window)
        self._samples: deque[tuple[float, int]] = deque(maxlen=12)
        self._reset_epoch: Optional[str] = None
        self._last_flush = 0.0

    def inc(self, name: str, n: int = 1) -> None:
        self.counters[name] += n

    def flush(self, r: redis.Redis, force: bool = False, interval: float = 2.0) -> None:
        now = time.time()
        epoch = r.get(self.keys.metrics_reset)
        reset_happened = False
        if epoch != self._reset_epoch:
            if epoch is not None or self._reset_epoch is not None:  # a reset happened
                self.alert_latency_ms.clear()
                self.proc_ms.clear()
                self._samples.clear()
                self._flushed = dict(self.counters)
            self._reset_epoch = epoch
            reset_happened = True
        if not force and not reset_happened and now - self._last_flush < interval:
            return
        self._last_flush = now
        self._samples.append((now, self.counters["events_in"]))
        eps = 0.0
        if len(self._samples) >= 2 and self._samples[-1][0] > self._samples[0][0]:
            eps = (self._samples[-1][1] - self._samples[0][1]) / (self._samples[-1][0] - self._samples[0][0])
        lat = sorted(self.alert_latency_ms)
        proc = sorted(self.proc_ms)
        mapping = {
            "updated": f"{now:.3f}", "eps": f"{eps:.1f}",
            "alert_latency_n": str(len(lat)),
            "alert_latency_p50_ms": f"{percentile(lat, 50):.1f}",
            "alert_latency_p95_ms": f"{percentile(lat, 95):.1f}",
            "alert_latency_p99_ms": f"{percentile(lat, 99):.1f}",
            "alert_latency_max_ms": f"{(lat[-1] if lat else 0.0):.1f}",
            "proc_p50_ms": f"{percentile(proc, 50):.3f}",
            "proc_p95_ms": f"{percentile(proc, 95):.3f}",
            "proc_p99_ms": f"{percentile(proc, 99):.3f}",
        }
        if self._reset_epoch is not None:
            mapping["reset_epoch"] = str(self._reset_epoch)
        pipe = r.pipeline(transaction=False)
        snapshot = dict(self.counters)
        for k, v in snapshot.items():
            delta = v - self._flushed.get(k, 0)
            if delta:
                pipe.hincrby(self.keys.metrics, k, delta)
        pipe.hset(self.keys.lat(self.name), mapping=mapping)
        pipe.execute()
        self._flushed = snapshot


# ---------------------------------------------------------------------------
# Sinks (contract 5)
# ---------------------------------------------------------------------------
class JsonlSink:
    """Fallback sink until Postgres is wired in. At-least-once, append-only."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _append(self, kind: str, payload: Mapping[str, Any]) -> None:
        line = json.dumps({"kind": kind, **payload}, separators=(",", ":"), default=str)
        with self._lock, open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def write_alert(self, alert: Mapping[str, Any]) -> None:
        self._append("alert", alert)

    def upsert_incident(self, incident: Mapping[str, Any]) -> None:
        self._append("incident", incident)


class ModuleSink:
    def __init__(self, module: Any):
        self.module = module

    def write_alert(self, alert: Mapping[str, Any]) -> None:
        self.module.write_alert(dict(alert))

    def upsert_incident(self, incident: Mapping[str, Any]) -> None:
        self.module.upsert_incident(dict(incident))


def resolve_sink(cfg: Config) -> tuple[Any, str]:
    if cfg.sink in ("auto", "postgres"):
        problem = ""
        try:
            mod = importlib.import_module("alerting.writer")
            if callable(getattr(mod, "write_alert", None)) and callable(getattr(mod, "upsert_incident", None)):
                return ModuleSink(mod), "alerting.writer"
            problem = "alerting.writer lacks write_alert()/upsert_incident()"
        except Exception as exc:  # noqa: BLE001
            problem = f"alerting.writer unavailable ({type(exc).__name__}: {exc})"
        if cfg.sink == "postgres":
            raise RuntimeError(problem)
        log.warning("%s; falling back to the JSONL sink at %s", problem, cfg.jsonl_path)
    return JsonlSink(cfg.jsonl_path), "jsonl"


class ReliableSink:
    """Retries with backoff; anything that still fails goes to the dead-letter stream."""

    def __init__(self, sink: Any, r: redis.Redis, cfg: Config, metrics: Metrics, retries: int = 3, backoff_s: float = 0.2):
        self.sink, self.r, self.cfg, self.metrics = sink, r, cfg, metrics
        self.retries, self.backoff_s = retries, backoff_s

    def _attempt(self, fn: Callable[[Mapping[str, Any]], None], payload: Mapping[str, Any], kind: str) -> bool:
        last: Optional[Exception] = None
        for i in range(self.retries):
            try:
                fn(payload)
                return True
            except Exception as exc:  # noqa: BLE001
                last = exc
                self.metrics.inc("sink_failures")
                log.warning("sink %s failed (attempt %d/%d): %s: %s", kind, i + 1, self.retries, type(exc).__name__, exc)
                time.sleep(self.backoff_s * (2 ** i))
        dead_letter(self.r, self.cfg, kind, payload, str(last))
        self.metrics.inc("dead_lettered")
        return False

    def alert(self, alert: Mapping[str, Any]) -> bool:
        return self._attempt(self.sink.write_alert, alert, "alert")

    def incident(self, incident: Mapping[str, Any]) -> bool:
        return self._attempt(self.sink.upsert_incident, incident, "incident")


def dead_letter(r: redis.Redis, cfg: Config, kind: str, payload: Any, error: str) -> None:
    record = {"kind": kind, "data": json.dumps(payload, default=str), "error": error[:500], "at": f"{time.time():.3f}"}
    try:
        r.xadd(cfg.dlq, record, maxlen=100_000, approximate=True)
    except redis.RedisError:
        cfg.dead_letter_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cfg.dead_letter_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")


def replay_dead_letters(cfg: Config, r: Optional[redis.Redis] = None, sink: Any = None, limit: int = 100_000) -> tuple[int, int]:
    """Re-drive dead-lettered alerts/incidents through the sink. Returns (replayed, remaining)."""
    r = r or connect_redis(cfg)
    if sink is None:
        sink, _ = resolve_sink(cfg)
    replayed = remaining = 0
    for entry_id, rec in r.xrange(cfg.dlq, count=limit):
        kind = rec.get("kind")
        try:
            payload = json.loads(rec["data"])
            if kind == "alert":
                sink.write_alert(payload)
            elif kind == "incident":
                sink.upsert_incident(payload)
            else:
                remaining += 1  # 'event' entries are poison messages: kept for inspection
                continue
            r.xdel(cfg.dlq, entry_id)
            replayed += 1
        except Exception as exc:  # noqa: BLE001
            remaining += 1
            log.warning("dlq entry %s still failing: %s", entry_id, exc)
    return replayed, remaining


# ---------------------------------------------------------------------------
# Incident correlation (contract 4): reference implementation of docs/model_notes.md s6
# ---------------------------------------------------------------------------
class IncidentCorrelator:
    """Groups alerts by source host in *event time*. Incident risk is the noisy-OR of the
    highest risk seen per distinct threat class:  1 - prod(1 - r_class/100).
    Repeats of one class never inflate the score; a multi-stage kill chain does."""

    def __init__(self, cfg: Config, r: redis.Redis, keys: Keys):
        self.cfg, self.r, self.keys = cfg, r, keys

    def attach(self, alert: Mapping[str, Any]) -> dict[str, Any]:
        src = alert["src_ip"]
        et = parse_iso(alert["event_time"])
        risk = int(alert["risk_score"])
        cls = alert["threat_class"]
        open_key = self.keys.incident_open(src)
        for _ in range(12):
            cur_id = self.r.get(open_key)
            inc_key = self.keys.incident(cur_id) if cur_id else None
            with self.r.pipeline() as pipe:
                try:
                    pipe.watch(*[k for k in (open_key, inc_key) if k])
                    if pipe.get(open_key) != cur_id:
                        continue
                    inc = pipe.hgetall(inc_key) if inc_key else {}
                    reuse = bool(inc) and abs(et - float(inc["last_seen"])) <= self.cfg.incident_gap_s
                    if reuse:
                        incident_id = inc["incident_id"]
                        class_risks = json.loads(inc["class_risks"])
                        first_seen = min(float(inc["first_seen"]), et)
                        last_seen = max(float(inc["last_seen"]), et)
                        count = int(inc["alert_count"]) + 1
                    else:
                        incident_id = f"INC-{self.r.incr(self.keys.incident_seq):06d}"
                        class_risks, first_seen, last_seen, count = {}, et, et, 1
                    class_risks[cls] = max(int(class_risks.get(cls, 0)), risk)
                    survive = 1.0
                    for v in class_risks.values():
                        survive *= 1.0 - _clip01(v / 100.0)
                    combined = min(100, _round_half_up(100.0 * (1.0 - survive)))
                    fields = {
                        "incident_id": incident_id, "src_ip": src, "first_seen": f"{first_seen:.6f}",
                        "last_seen": f"{last_seen:.6f}", "alert_count": count,
                        "class_risks": json.dumps(class_risks), "risk_score": combined,
                        "severity": severity_for(combined), "status": "OPEN",
                    }
                    new_key = self.keys.incident(incident_id)
                    pipe.multi()
                    pipe.hset(new_key, mapping=fields)
                    pipe.expire(new_key, 86400)
                    pipe.set(open_key, incident_id, ex=86400)
                    pipe.execute()
                    return {
                        "incident_id": incident_id, "src_ip": src, "first_seen": utc_iso(first_seen),
                        "last_seen": utc_iso(last_seen), "alert_count": count,
                        "threat_classes": list(class_risks), "risk_score": combined,
                        "severity": severity_for(combined), "status": "OPEN",
                    }
                except redis.WatchError:
                    continue
        raise RuntimeError("incident correlation kept conflicting; giving up for this alert")


def resolve_correlator(cfg: Config, r: redis.Redis, keys: Keys) -> tuple[Callable[[Mapping[str, Any]], dict], str]:
    builtin = IncidentCorrelator(cfg, r, keys).attach
    try:
        mod = importlib.import_module("models.correlation")
        fn = getattr(mod, "correlate", None)
        if callable(fn):
            required = {"incident_id", "src_ip", "first_seen", "last_seen", "alert_count", "threat_classes", "risk_score", "severity", "status"}

            def wrapped(alert: Mapping[str, Any]) -> dict:
                try:
                    inc = fn(dict(alert), r)
                    if isinstance(inc, dict) and required <= set(inc):
                        return inc
                    log.warning("models.correlation.correlate returned an invalid incident; using built-in")
                except redis.RedisError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    log.warning("models.correlation.correlate failed (%s); using built-in", exc)
                return builtin(alert)

            return wrapped, "models.correlation"
    except Exception as exc:  # noqa: BLE001
        log.warning("models.correlation unavailable (%s); using the built-in correlator", exc)
    return builtin, "builtin"


# ---------------------------------------------------------------------------
# Alert engine: cooldown -> recency -> fusion -> incident -> validate -> sink
# ---------------------------------------------------------------------------
class AlertEngine:
    def __init__(self, cfg: Config, r: redis.Redis, keys: Keys, sink: ReliableSink, metrics: Metrics,
                 fusion: Optional[Callable[[str, float, float, float], int]] = None,
                 correlate: Optional[Callable[[Mapping[str, Any]], dict]] = None):
        self.cfg, self.r, self.keys, self.sink, self.metrics = cfg, r, keys, sink, metrics
        self.fusion = fusion or fuse_builtin
        self.correlate = correlate or IncidentCorrelator(cfg, r, keys).attach

    def _risk(self, det: Detection, recency: float) -> int:
        try:
            value = self.fusion(det.threat_class, det.confidence, det.anomaly, recency)
            risk = int(round(float(value)))
            if not 0 <= risk <= 100:
                raise ValueError(f"fusion returned {value!r}")
            return risk
        except redis.RedisError:
            raise
        except Exception as exc:  # noqa: BLE001
            self.metrics.inc("fusion_fallbacks")
            log.warning("fusion failed (%s); using built-in reference fusion for this alert", exc)
            return fuse_builtin(det.threat_class, det.confidence, det.anomaly, recency)

    def process(self, det: Detection, ingest_ms: Optional[int]) -> Optional[dict]:
        self.metrics.inc("detections")
        alert_id = make_alert_id(det.flow_id, det.threat_class, det.detector)
        cd_key = self.keys.cooldown(det.src_ip, det.threat_class)
        holder = self.r.get(cd_key)
        if holder not in (None, alert_id):  # same alert redelivered => proceed (idempotent write)
            self.metrics.inc("alerts_suppressed")
            return None
        hist_key = self.keys.hist(det.src_ip)
        prior = [
            t for member, t in self.r.zrangebyscore(hist_key, det.event_time - self.cfg.recency_window_s, det.event_time, withscores=True)
            if member != alert_id
        ]
        recency = recency_score(prior, det.event_time, self.cfg.recency_half_life_s)
        risk = self._risk(det, recency)
        alert: dict[str, Any] = {
            "alert_id": alert_id, "timestamp": utc_iso(time.time()), "event_time": utc_iso(det.event_time),
            "flow_id": det.flow_id, "threat_class": det.threat_class, "confidence": round(det.confidence, 4),
            "risk_score": risk, "severity": severity_for(risk), "evidence": det.evidence, "incident_id": None,
            "src_ip": det.src_ip, "dst_ip": det.dst_ip, "detector": det.detector, "schema_version": SCHEMA_VERSION,
        }
        incident = self.correlate(alert)
        alert["incident_id"] = incident["incident_id"]
        # Fusion/correlation may legitimately raise the incident's score; the alert keeps its own.
        validate_alert(alert)  # raises ValueError -> counted as a contract violation by the caller
        self.sink.incident(incident)  # parent row first (FK: alerts.incident_id)
        self.sink.alert(alert)
        pipe = self.r.pipeline(transaction=False)
        pipe.zadd(hist_key, {alert_id: det.event_time})
        pipe.zremrangebyscore(hist_key, 0, det.event_time - self.cfg.recency_window_s)
        pipe.expire(hist_key, 86400)
        pipe.set(cd_key, alert_id, ex=max(1, int(self.cfg.cooldown_s)))
        pipe.execute()
        self.metrics.inc("alerts_emitted")
        if ingest_ms is not None:
            self.metrics.alert_latency_ms.append(max(0.0, time.time() * 1000.0 - ingest_ms))
        return alert


# ---------------------------------------------------------------------------
# Detection worker
# ---------------------------------------------------------------------------
class Worker:
    def __init__(self, cfg: Config, index: int = 0, r: Optional[redis.Redis] = None,
                 detectors: Optional[list[ManagedDetector]] = None, sink: Any = None):
        self.cfg = cfg
        self.name = f"worker-{index}"          # stable name => a restart reclaims its own pending entries
        self.r = r or connect_redis(cfg)
        self.keys = Keys(cfg.prefix)
        self.metrics = Metrics(self.keys, self.name)
        self.detectors = detectors if detectors is not None else load_detectors(cfg)
        raw_sink, self.sink_name = (sink, "injected") if sink is not None else resolve_sink(cfg)
        self.sink = ReliableSink(raw_sink, self.r, cfg, self.metrics)
        fusion, self.fusion_name = resolve_fusion()
        correlate, self.correlator_name = resolve_correlator(cfg, self.r, self.keys)
        self.engine = AlertEngine(cfg, self.r, self.keys, self.sink, self.metrics, fusion, correlate)
        self._last_housekeeping = 0.0

    def claim_slot(self, stop: threading.Event, wait_s: float = 0.0) -> None:
        key = self.keys.hb(self.name)
        val = self.r.get(key)
        if val:
            parts = str(val).split(":")
            if parts and parts[0]:
                try:
                    other_pid = int(parts[0])
                    if other_pid != os.getpid():
                        raise RuntimeError(f"worker slot {self.name} already running by pid {other_pid}")
                except ValueError:
                    pass
        self.r.set(key, f"{os.getpid()}:{time.time():.3f}", ex=15)

    def ensure_group(self) -> None:
        try:
            self.r.xgroup_create(self.cfg.stream, self.cfg.group, id="0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def process_entry(self, msg_id: str, fields: Mapping[str, str]) -> None:
        t0 = time.perf_counter()
        try:
            event = normalize_event(fields, msg_id)
        except ValueError as exc:
            self.metrics.inc("events_invalid")
            dead_letter(self.r, self.cfg, "event", dict(fields), f"invalid event {msg_id}: {exc}")
            return
        self.metrics.inc("events_in")
        detections: list[Detection] = []
        for det in self.detectors:
            found, errors, violations = det.run(event, self.r)
            detections.extend(found)
            if errors:
                self.metrics.inc("detector_errors", errors)
            if violations:
                self.metrics.inc("contract_violations", violations)
        for detection in detections:
            try:
                self.engine.process(detection, event["_ingest_ms"])
            except ValueError as exc:
                self.metrics.inc("contract_violations")
                log.warning("alert rejected by validation: %s", exc)
        self.metrics.proc_ms.append((time.perf_counter() - t0) * 1000.0)

    def _process_batch(self, entries: Sequence[tuple[str, Mapping[str, str]]]) -> None:
        acked: list[str] = []
        try:
            for msg_id, fields in entries:
                try:
                    self.process_entry(msg_id, fields)
                except redis.RedisError:
                    raise
                except Exception as exc:  # noqa: BLE001 - poison-pill protection
                    self.metrics.inc("events_failed")
                    log.exception("event %s crashed processing; dead-lettering", msg_id)
                    dead_letter(self.r, self.cfg, "event", dict(fields), f"crash {type(exc).__name__}: {exc}")
                acked.append(msg_id)
        finally:
            if acked:
                try:
                    self.r.xack(self.cfg.stream, self.cfg.group, *acked)
                except redis.RedisError:
                    log.warning("xack failed; entries will be redelivered (processing is idempotent)")

    def _housekeeping(self) -> None:
        now = time.time()
        if now - self._last_housekeeping < 30:
            return
        self._last_housekeeping = now
        try:
            res = self.r.xautoclaim(self.cfg.stream, self.cfg.group, self.name, min_idle_time=60_000, start_id="0-0", count=100)
            claimed = res[1] if isinstance(res, (list, tuple)) and len(res) > 1 else []
            if claimed:
                log.info("reclaimed %d stale entries from dead consumers", len(claimed))
                self._process_batch(claimed)
            self.r.xtrim(self.cfg.stream, maxlen=self.cfg.stream_maxlen, approximate=True)
        except redis.RedisError as exc:
            log.warning("housekeeping skipped: %s", exc)

    def run(self, stop: threading.Event) -> None:
        log.info("%s up | stream=%s group=%s | detectors=%d | fusion=%s | correlator=%s | sink=%s",
                 self.name, self.cfg.stream, self.cfg.group, len(self.detectors), self.fusion_name,
                 self.correlator_name, self.sink_name)
        backoff = 0.5
        read_id = "0"  # drain our own pending entries first, then switch to new messages (">")
        ensured = False
        while not stop.is_set():
            try:
                if not ensured:
                    self.ensure_group()
                    ensured = True
                self.r.set(self.keys.hb(self.name), f"{time.time():.3f}", ex=15)
                resp = self.r.xreadgroup(self.cfg.group, self.name, {self.cfg.stream: read_id}, count=self.cfg.batch,
                                         block=self.cfg.block_ms if read_id == ">" else None)
                entries = resp[0][1] if resp else []
                if entries:
                    self._process_batch(entries)
                elif read_id == "0":
                    read_id = ">"
                self._housekeeping()
                self.metrics.flush(self.r)
                backoff = 0.5
            except redis.RedisError as exc:
                log.error("redis error (%s); retrying in %.1fs", exc, backoff)
                read_id, ensured = "0", False
                stop.wait(backoff)
                backoff = min(10.0, backoff * 2)
        try:
            self.metrics.flush(self.r, force=True)
        except redis.RedisError:
            pass
        log.info("%s stopped", self.name)


# ---------------------------------------------------------------------------
# Privileged commands, network, boundary enforcement
# ---------------------------------------------------------------------------
def _bin(name: str) -> str:
    return shutil.which(name) or next((p for p in (f"/usr/sbin/{name}", f"/sbin/{name}") if os.path.exists(p)), name)


def _priv(cfg: Config) -> list[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    return shlex.split(cfg.priv_prefix)


def _run(argv: Sequence[str], check: bool = True, timeout: float = 30.0) -> subprocess.CompletedProcess:
    log.debug("$ %s", " ".join(argv))
    try:
        proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        if not check:
            return subprocess.CompletedProcess(list(argv), 127, stdout="", stderr=str(exc))
        raise
    if check and proc.returncode != 0:
        raise RuntimeError(f"`{' '.join(argv)}` failed (rc={proc.returncode}): {(proc.stderr or proc.stdout).strip()}")
    return proc


def iface_exists(iface: str) -> bool:
    return subprocess.run([_bin("ip"), "link", "show", iface], capture_output=True).returncode == 0


def setup_network(cfg: Config) -> None:
    """Create the virtual tap: tx_iface (source side) <=> rx_iface (monitor side, listen-only)."""
    pv, ip, tx, rx = _priv(cfg), _bin("ip"), cfg.tx_iface, cfg.rx_iface
    if not iface_exists(tx):
        _run(pv + [ip, "link", "add", tx, "type", "veth", "peer", "name", rx])
    for iface in (tx, rx):
        _run(pv + [ip, "link", "set", iface, "up"])
    _run(pv + [ip, "addr", "flush", "dev", rx], check=False)               # monitor NIC owns no IP address
    _run(pv + [ip, "link", "set", rx, "promisc", "on"])                     # see every frame, not only ours
    _run(pv + [ip, "link", "set", "dev", rx, "arp", "off"])                 # never emit ARP
    _run(pv + [_bin("sysctl"), "-w", f"net.ipv6.conf.{rx}.disable_ipv6=1"], check=False)   # no RS/MLD chatter
    if shutil.which("ethtool") or os.path.exists("/usr/sbin/ethtool") or os.path.exists("/sbin/ethtool"):
        _run(pv + [_bin("ethtool"), "-K", rx, "gro", "off", "lro", "off"], check=False)    # sensors want real frames
    # Read-only enforcement: anything the monitor NIC tries to *send* is dropped by the kernel.
    _run(pv + [_bin("tc"), "qdisc", "replace", "dev", rx, "clsact"], check=False)
    _run(pv + [_bin("tc"), "filter", "replace", "dev", rx, "egress", "pref", "1", "protocol", "all", "matchall", "action", "drop"], check=False)


def teardown_network(cfg: Config) -> None:
    if iface_exists(cfg.tx_iface):
        _run(_priv(cfg) + [_bin("ip"), "link", "del", cfg.tx_iface], check=False)


def verify_readonly(cfg: Config) -> dict[str, Any]:
    """Inspect the kernel state of the monitor NIC. ENFORCED only if every check passes."""
    rx = cfg.rx_iface
    report: dict[str, Any] = {"iface": rx, "no_ip": False, "arp_off": False, "promisc": False, "egress_drop": False}
    try:
        info = json.loads(_run([_bin("ip"), "-j", "addr", "show", rx]).stdout)[0]
        flags = info.get("flags", [])
        report["no_ip"] = not info.get("addr_info")
        report["arp_off"] = "NOARP" in flags
        report["promisc"] = "PROMISC" in flags
        shown = _run([_bin("tc"), "filter", "show", "dev", rx, "egress"], check=False)
        report["egress_drop"] = "drop" in (shown.stdout or "").lower()
    except Exception as exc:  # noqa: BLE001
        report["error"] = str(exc)
    report["level"] = "ENFORCED" if all(report[k] for k in ("no_ip", "arp_off", "promisc", "egress_drop")) else "PARTIAL"
    return report


def compose_command() -> Optional[list[str]]:
    if shutil.which("docker"):
        if subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0:
            return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    return None


def wait_for_redis(cfg: Config, timeout: float = 30.0) -> redis.Redis:
    deadline = time.time() + timeout
    last: Optional[Exception] = None
    while time.time() < deadline:
        try:
            r = connect_redis(cfg)
            r.ping()
            return r
        except redis.RedisError as exc:
            last = exc
            time.sleep(0.5)
    raise RuntimeError(f"Redis not reachable at {cfg.redis_url}: {last}")


def tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def build_replay_cmd(cfg: Config, pcap: Path, mode: str = "original", rate: Optional[float] = None, loop: int = 1) -> list[str]:
    if mode not in MODE_CHOICES:
        raise ValueError(f"mode must be one of {MODE_CHOICES}")
    argv = _priv(cfg) + [cfg.replay_bin, f"--intf1={cfg.tx_iface}"]
    if mode in ("pps", "mbps", "multiplier"):
        if rate is None or rate <= 0:
            raise ValueError(f"mode {mode!r} needs a positive rate")
        argv.append(f"--{mode}={rate:g}")
    elif mode == "topspeed":
        argv.append("--topspeed")
    if loop < 0:
        raise ValueError("loop must be >= 0 (0 = loop until stopped)")
    if loop != 1:
        argv.append(f"--loop={loop}")
    argv += ["--stats=5"] + shlex.split(cfg.replay_extra) + [str(pcap)]
    return argv


def validate_sim_request(cfg: Config, req: Mapping[str, Any]) -> tuple[Path, str, Optional[float], int]:
    """Control-plane input is untrusted: constrain it before it reaches a privileged process."""
    pcap = Path(req.get("pcap") or cfg.pcap)
    pcap = (pcap if pcap.is_absolute() else ROOT / pcap).resolve()
    allowed = (ROOT / "data").resolve()
    if allowed not in pcap.parents:
        raise ValueError(f"pcap must live under {allowed}")
    if not pcap.is_file() or pcap.suffix.lower() not in (".pcap", ".pcapng"):
        raise ValueError(f"pcap not found or not a .pcap/.pcapng file: {pcap}")
    mode = str(req.get("mode") or "original")
    if mode not in MODE_CHOICES:
        raise ValueError(f"mode must be one of {MODE_CHOICES}")
    rate = req.get("rate")
    rate = None if rate in (None, "") else _finite(rate, "rate")
    loop = int(req.get("loop", 1))
    if loop < 0 or loop > 1_000_000:
        raise ValueError("loop must be within 0..1000000 (0 = until stopped)")
    return pcap, mode, rate, loop


# ---------------------------------------------------------------------------
# Child-process supervision
# ---------------------------------------------------------------------------
class ManagedProcess:
    def __init__(self, name: str, argv: Sequence[str], env: Optional[Mapping[str, str]] = None,
                 restart: bool = True, max_restarts: int = 5, window_s: float = 60.0):
        self.name, self.argv = name, list(argv)
        self.env = {**os.environ, **(env or {})}
        self.restart, self.max_restarts, self.window_s = restart, max_restarts, window_s
        self.proc: Optional[subprocess.Popen] = None
        self.failed = False
        self.stopping = False
        self._restarts: deque[float] = deque()
        self._next_start = 0.0
        self.log = logging.getLogger(f"cherenkov.{name}")

    def start(self) -> None:
        preexec = None
        if sys.platform.startswith("linux"):
            def _preexec() -> None:
                try:
                    import ctypes
                    libc = ctypes.CDLL("libc.so.6")
                    libc.prctl(1, signal.SIGTERM)
                except Exception:
                    pass
            preexec = _preexec

        # sudo requires a controlling terminal to match cached PAM tty tickets;
        # detaching session breaks `sudo -n`
        new_session = not (self.argv and self.argv[0] == "sudo")
        self.proc = subprocess.Popen(self.argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                                     cwd=ROOT, env=self.env, start_new_session=new_session, preexec_fn=preexec)
        threading.Thread(target=self._pump, args=(self.proc,), name=f"pump-{self.name}", daemon=True).start()
        self.log.info("started pid=%s: %s", self.proc.pid, " ".join(shlex.quote(a) for a in self.argv))

    def _pump(self, proc: subprocess.Popen) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            self.log.info(line.rstrip())

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    @property
    def returncode(self) -> Optional[int]:
        return None if self.proc is None else self.proc.poll()

    def check(self) -> str:
        """Returns 'ok' | 'restarted' | 'failed' | 'exited' (non-restartable process ended)."""
        if self.alive or self.stopping:
            return "ok"
        if not self.restart:
            return "exited"
        if self.failed:
            return "failed"
        now = time.monotonic()
        if now < self._next_start:
            return "ok"
        while self._restarts and now - self._restarts[0] > self.window_s:
            self._restarts.popleft()
        if len(self._restarts) >= self.max_restarts:
            self.failed = True
            self.log.error("crashed %d times in %.0fs (rc=%s); giving up", self.max_restarts, self.window_s, self.returncode)
            return "failed"
        self._restarts.append(now)
        self._next_start = now + min(10.0, 0.5 * 2 ** len(self._restarts))
        self.log.warning("exited rc=%s; restarting (%d/%d in window)", self.returncode, len(self._restarts), self.max_restarts)
        self.start()
        return "restarted"

    def stop(self, timeout: float = 8.0) -> None:
        self.stopping = True
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            self.proc.terminate()  # via sudo, SIGTERM is relayed to the privileged child
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.log.warning("did not exit in %.0fs; killing", timeout)
            self.proc.kill()
            self.proc.wait(timeout=5)
        except (ProcessLookupError, PermissionError):
            pass


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
@dataclass
class Check:
    level: str   # OK | WARN | FAIL
    name: str
    detail: str


class Supervisor:
    def __init__(self, cfg: Config, args: argparse.Namespace, r: Optional[redis.Redis] = None):
        self.cfg, self.args = cfg, args
        self.keys = Keys(cfg.prefix)
        self.r = r
        self.stop_event = threading.Event()
        self.children: list[ManagedProcess] = []
        self.replay: Optional[ManagedProcess] = None
        self.state = "INIT"
        self.extra: dict[str, Any] = {}
        self._drain_since: Optional[float] = None
        self._quiet: tuple[Optional[str], float] = (None, time.monotonic())
        self._last_tick_error = 0.0
        self.simulation_enabled = not args.no_replay
        self.boundary: dict[str, Any] = {}

    # -- state ----------------------------------------------------------
    def set_state(self, state: str, message: str = "", **extra: Any) -> None:
        self.state = state
        self.extra.update(extra)
        log.info("STATE -> %s %s", state, message)
        self._publish(message=message)

    def _publish(self, message: Optional[str] = None) -> None:
        if self.r is None:
            return
        mapping = {"state": self.state, "updated": f"{time.time():.3f}", "pipeline_pid": str(os.getpid()),
                   "simulation_enabled": str(int(self.simulation_enabled)), "readonly_boundary": self.boundary.get("level", "UNKNOWN")}
        if message is not None:
            mapping["message"] = message
        mapping.update({k: str(v) for k, v in self.extra.items() if v is not None})
        try:
            self.r.hset(self.keys.state, mapping=mapping)
        except redis.RedisError:
            pass

    # -- preflight ------------------------------------------------------
    def preflight(self) -> list[Check]:
        cfg, out = self.cfg, []

        def add(level: str, name: str, detail: str) -> None:
            out.append(Check(level, name, detail))

        add("OK" if sys.version_info >= (3, 9) else "FAIL", "python", sys.version.split()[0])
        try:
            (self.r or connect_redis(cfg)).ping()
            add("OK", "redis", cfg.redis_url)
        except redis.RedisError as exc:
            add("FAIL", "redis", f"unreachable at {cfg.redis_url}: {exc}")
        spec = importlib.util.find_spec("streaming.event_processor") if (ROOT / "streaming").exists() else None
        add("OK" if spec or self.args.processor_cmd_overridden else "FAIL", "event_processor",
            "streaming.event_processor importable" if spec else f"not found; using CHERENKOV_PROCESSOR_CMD={cfg.processor_cmd!r}"
            if self.args.processor_cmd_overridden else "streaming/event_processor.py missing")
        loadable = [m for m in cfg.detectors if importlib.util.find_spec(m.split(".")[0]) and _find_spec_safe(m)]
        add("OK" if len(loadable) == len(cfg.detectors) else "WARN", "detectors",
            f"{len(loadable)}/{len(cfg.detectors)} modules found" + ("" if len(loadable) == len(cfg.detectors) else
                                                                    f" (missing: {sorted(set(cfg.detectors) - set(loadable))})"))
        pg = tcp_open(cfg.pg_host, cfg.pg_port)
        writer = _find_spec_safe("alerting.writer")
        if writer and pg:
            add("OK", "sink", "alerting.writer + Postgres reachable")
        else:
            add("WARN", "sink", f"Postgres/alerting.writer not ready (writer={'yes' if writer else 'no'}, "
                                f"postgres={'up' if pg else 'down'}); alerts go to {cfg.jsonl_path}")
        add("OK" if cfg.sensor_cmd else "WARN", "sensor",
            "CHERENKOV_SENSOR_CMD set" if cfg.sensor_cmd else "CHERENKOV_SENSOR_CMD empty: start Zeek/Suricata yourself on " + cfg.rx_iface)
        if self.simulation_enabled:
            add("OK" if shutil.which(cfg.replay_bin) else "FAIL", "tcpreplay", shutil.which(cfg.replay_bin) or f"{cfg.replay_bin!r} not on PATH")
            add("OK" if Path(self.args.pcap).exists() else "FAIL", "pcap", str(self.args.pcap))
            if not self.args.no_network:
                if not sys.platform.startswith("linux"):
                    add("WARN", "platform", "veth/tc virtual tap needs Linux (use WSL2/VM/Docker); bypassing tap on macOS")
                    self.args.no_network = True
                elif _priv(cfg) and subprocess.run(_priv(cfg) + ["true"], capture_output=True).returncode != 0:
                    add("FAIL", "privileges", f"`{cfg.priv_prefix} true` failed: run `sudo -v` first or configure passwordless sudo for ip/tc/tcpreplay")
                else:
                    add("OK", "privileges", "root or sudo available")
        return out

    # -- bring-up -------------------------------------------------------
    def _child_env(self) -> dict[str, str]:
        return {"REDIS_URL": self.cfg.redis_url, "CHERENKOV_STREAM": self.cfg.stream, "CHERENKOV_PREFIX": self.cfg.prefix,
                "CHERENKOV_LOG_DIR": str(self.cfg.log_dir), "PYTHONUNBUFFERED": "1",
                "PYTHONPATH": os.pathsep.join(filter(None, [str(ROOT), os.environ.get("PYTHONPATH", "")]))}

    def _spawn(self, name: str, argv: Sequence[str], **kw: Any) -> ManagedProcess:
        proc = ManagedProcess(name, argv, env=self._child_env(), **kw)
        proc.start()
        self.children.append(proc)
        return proc

    def bring_up(self) -> None:
        cfg, args = self.cfg, self.args
        self.cfg.log_dir.mkdir(parents=True, exist_ok=True)
        if args.compose:
            cmd = compose_command()
            if not cmd:
                raise RuntimeError("--compose given but neither `docker compose` nor `docker-compose` is available")
            log.info("starting Redis/Postgres: %s up -d", " ".join(cmd))
            _run(cmd + ["up", "-d"], timeout=300)
        self.r = wait_for_redis(cfg)
        if self.simulation_enabled and not args.no_network:
            log.info("creating virtual tap %s => %s", cfg.tx_iface, cfg.rx_iface)
            setup_network(cfg)
            self.boundary = verify_readonly(cfg)
            level = self.boundary["level"]
            (log.info if level == "ENFORCED" else log.warning)("read-only boundary: %s %s", level, self.boundary)
            if level != "ENFORCED" and args.strict_boundary:
                raise RuntimeError(f"--strict-boundary: monitor NIC is not fully listen-only: {self.boundary}")
        self.set_state("STARTING", "starting stages downstream-first so nothing is lost")
        # Consumers before producers: workers -> event processor -> sensor.
        for i in range(cfg.workers):
            self._spawn(f"worker-{i}", [sys.executable, "-m", "pipeline.consumer", "worker", "--index", str(i)])
        self._wait_workers()
        self._spawn("event_processor", shlex.split(cfg.processor_cmd))
        if cfg.sensor_cmd:
            self._spawn("sensor", shlex.split(cfg.sensor_cmd))
        time.sleep(1.0)
        dead = [c.name for c in self.children if not c.alive]
        if dead:
            raise RuntimeError(f"stage(s) died during start-up: {dead} (see log lines above)")

    def _wait_workers(self, timeout: float = 30.0) -> None:
        assert self.r is not None
        deadline = time.time() + timeout
        need = {self.keys.hb(f"worker-{i}") for i in range(self.cfg.workers)}
        while time.time() < deadline and not self.stop_event.is_set():
            if all(self.r.exists(k) for k in need):
                log.info("%d detection worker(s) ready", self.cfg.workers)
                return
            time.sleep(0.25)
        raise RuntimeError("detection worker(s) did not become ready in time")

    # -- simulation control ---------------------------------------------
    def start_simulation(self, req: Optional[Mapping[str, Any]] = None) -> None:
        if not self.simulation_enabled:
            log.warning("start ignored: orchestrator was started with --no-replay (production/live-capture mode)")
            return
        if self.state not in ("READY", "IDLE"):
            log.warning("start ignored: state is %s (need READY or IDLE)", self.state)
            return
        params = {"pcap": str(self.args.pcap), "mode": self.args.mode, "rate": self.args.rate, "loop": self.args.loop, **(req or {})}
        try:
            pcap, mode, rate, loop = validate_sim_request(self.cfg, params)
            argv = build_replay_cmd(self.cfg, pcap, mode, rate, loop)
        except ValueError as exc:
            log.error("start rejected: %s", exc)
            self._publish(message=f"start rejected: {exc}")
            return
        assert self.r is not None
        self.r.set(self.keys.metrics_reset, f"{time.time():.6f}")   # each run is its own measurement window
        self.r.delete(self.keys.metrics)
        self.replay = ManagedProcess("replay", argv, restart=False)
        self.replay.env = {**os.environ}
        self.replay.start()
        self._drain_since = None
        self.set_state("RUNNING", f"replaying {pcap.name} mode={mode} rate={rate} loop={loop}", pcap=pcap.name, mode=mode,
                       rate=rate, loop=loop, sim_started=f"{time.time():.3f}", sim_ended="", drained_at="")

    def stop_simulation(self) -> None:
        if self.replay and self.replay.alive:
            log.info("stopping replay")
            self.replay.stop()

    # -- periodic work --------------------------------------------------
    def _drained(self) -> bool:
        assert self.r is not None
        try:
            groups = self.r.xinfo_groups(self.cfg.stream)
            info = self.r.xinfo_stream(self.cfg.stream)
        except redis.ResponseError:
            return True  # no stream yet: nothing to drain
        group = next((g for g in groups if g.get("name") == self.cfg.group), None)
        if group is None:
            return False
        last_generated = info.get("last-generated-id")
        now = time.monotonic()
        if last_generated != self._quiet[0]:
            self._quiet = (last_generated, now)
        quiet = now - self._quiet[1] >= self.cfg.drain_quiet_s
        return bool(quiet and int(group.get("pending", 0)) == 0 and group.get("last-delivered-id") == last_generated)

    def tick(self) -> None:
        for child in list(self.children):
            outcome = child.check()
            if outcome == "failed":
                self.extra["health"] = f"DEGRADED: {child.name} failed permanently"
        if self.replay is not None and self.state == "RUNNING" and not self.replay.alive:
            rc = self.replay.returncode
            log.info("replay finished (rc=%s); draining pipeline", rc)
            self.replay = None
            self.set_state("DRAINING", f"replay exited rc={rc}; waiting for pipeline to catch up", sim_ended=f"{time.time():.3f}")
            self._drain_since = time.monotonic()
        if self.state == "DRAINING":
            timed_out = self._drain_since is not None and time.monotonic() - self._drain_since > self.cfg.drain_timeout_s
            if self._drained() or timed_out:
                msg = "drain timeout: backlog remains" if timed_out and not self._drained() else "run complete; send `start` for another run"
                self.set_state("IDLE", msg, drained_at=f"{time.time():.3f}")
                if self.args.exit_when_done:
                    self.stop_event.set()
        self._poll_control()
        self._publish()

    def _poll_control(self) -> None:
        assert self.r is not None
        for _ in range(16):
            raw = self.r.lpop(self.keys.ctl)
            if raw is None:
                return
            try:
                msg = json.loads(raw) if raw.strip().startswith("{") else {"cmd": raw.strip()}
                cmd = str(msg.get("cmd", "")).lower()
            except (json.JSONDecodeError, AttributeError):
                log.warning("ignoring malformed control message: %r", raw[:200])
                continue
            log.info("control: %s", cmd)
            if cmd == "start":
                self.start_simulation(msg)
            elif cmd == "stop":
                self.stop_simulation()
            elif cmd == "shutdown":
                self.stop_event.set()
            else:
                log.warning("unknown control command %r", cmd)

    # -- lifecycle ------------------------------------------------------
    def run(self) -> int:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: self.stop_event.set())
        self.set_state("PREFLIGHT")
        checks = self.preflight()
        for c in checks:
            (log.error if c.level == "FAIL" else log.warning if c.level == "WARN" else log.info)("preflight %-4s %-16s %s", c.level, c.name, c.detail)
        if any(c.level == "FAIL" for c in checks):
            log.error("preflight failed; nothing was started")
            return 2
        try:
            self.bring_up()
        except Exception as exc:  # noqa: BLE001
            log.error("start-up failed: %s", exc)
            self.shutdown()
            return 1
        self.set_state("READY", "all stages up; waiting for the start trigger", health="OK")
        if self.args.auto_start:
            self.start_simulation()
        elif self.simulation_enabled:
            self._announce()
        try:
            while not self.stop_event.is_set():
                try:
                    self.tick()
                except redis.RedisError as exc:
                    if time.time() - self._last_tick_error > 10:
                        log.error("redis error in supervisor loop: %s", exc)
                        self._last_tick_error = time.time()
                self.stop_event.wait(0.5)
        finally:
            self.shutdown()
        return 0

    def _announce(self) -> None:
        print("\n" + "=" * 72 + "\n READY. Start the simulation with ANY of:\n"
              "   * press ENTER in this terminal\n"
              "   * python -m pipeline.consumer start\n"
              "   * the 'Start simulation' button in the dashboard sidebar\n"
              + "=" * 72 + "\n", flush=True)
        if sys.stdin and sys.stdin.isatty() and not self.args.no_prompt:
            def wait_enter() -> None:
                try:
                    sys.stdin.readline()
                    self.r and self.r.rpush(self.keys.ctl, "start")
                except (OSError, redis.RedisError):
                    pass
            threading.Thread(target=wait_enter, name="stdin-trigger", daemon=True).start()

    def shutdown(self) -> None:
        if self.state == "STOPPED":
            return
        log.info("shutting down (reverse order)")
        self.set_state("STOPPING")
        self.stop_simulation()
        for child in reversed(self.children):
            child.stop()
        if self.args.teardown and self.simulation_enabled and not self.args.no_network:
            teardown_network(self.cfg)
        self.set_state("STOPPED", "pipeline stopped")


def _find_spec_safe(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------
def collect_status(cfg: Config, r: redis.Redis) -> dict[str, Any]:
    keys = Keys(cfg.prefix)
    state = r.hgetall(keys.state)
    age = time.time() - float(state["updated"]) if state.get("updated") else None
    workers = {}
    for k in r.scan_iter(match=f"{keys.metrics}:lat:*"):
        workers[k.rsplit(":", 1)[-1]] = r.hgetall(k)
    stream = {"length": 0, "pending": 0, "lag_entries": None}
    try:
        stream["length"] = r.xlen(cfg.stream)
        group = next((g for g in r.xinfo_groups(cfg.stream) if g.get("name") == cfg.group), None)
        if group:
            stream["pending"] = int(group.get("pending", 0))
            stream["lag_entries"] = group.get("lag")
    except redis.ResponseError:
        pass
    try:
        dlq = r.xlen(cfg.dlq)
    except redis.ResponseError:
        dlq = 0
    return {"supervisor": {**state, "heartbeat_age_s": None if age is None else round(age, 1),
                           "online": age is not None and age < 5},
            "totals": r.hgetall(keys.metrics), "workers": workers, "stream": stream, "dead_letter": dlq}


def print_status(st: Mapping[str, Any]) -> None:
    sup, tot = st["supervisor"], st["totals"]
    print(f"state      : {sup.get('state', 'OFFLINE')}  ({sup.get('message', '')})")
    print(f"supervisor : {'online' if sup.get('online') else 'OFFLINE'}   health={sup.get('health', '?')}   "
          f"read-only boundary={sup.get('readonly_boundary', '?')}")
    print(f"stream     : len={st['stream']['length']} pending={st['stream']['pending']} lag={st['stream']['lag_entries']}   dead-letter={st['dead_letter']}")
    print("totals     : " + (", ".join(f"{k}={v}" for k, v in sorted(tot.items())) or "(none)"))
    for name, w in sorted(st["workers"].items()):
        print(f"{name:11}: eps={w.get('eps')}  alert-latency p50/p95/p99 = {w.get('alert_latency_p50_ms')}/"
              f"{w.get('alert_latency_p95_ms')}/{w.get('alert_latency_p99_ms')} ms  proc p95={w.get('proc_p95_ms')} ms")


def send_control(cfg: Config, payload: Mapping[str, Any]) -> int:
    r = connect_redis(cfg)
    keys = Keys(cfg.prefix)
    state = r.hgetall(keys.state)
    if not state.get("updated") or time.time() - float(state["updated"]) > 10:
        print("warning: no live supervisor detected (start one with `python -m pipeline.consumer up`)", file=sys.stderr)
    r.rpush(keys.ctl, json.dumps(payload))
    print(f"sent: {json.dumps(payload)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m pipeline.consumer", description="Cherenkov pipeline orchestrator and detection worker")
    sub = p.add_subparsers(dest="command", required=True)

    def sim_args(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--pcap", default=None, help="pcap to replay (must be under data/)")
        sp.add_argument("--mode", choices=MODE_CHOICES, default=None, help="original = keep recorded timing (needed for beacon demos)")
        sp.add_argument("--rate", type=float, default=None, help="value for pps/mbps/multiplier modes")
        sp.add_argument("--loop", type=int, default=None, help="repeat count; 0 = until stopped")

    up = sub.add_parser("up", help="bring the whole pipeline up and wait for the start trigger")
    sim_args(up)
    up.add_argument("--compose", action="store_true", help="run `docker compose up -d` first")
    up.add_argument("--no-replay", action="store_true", help="production/live-capture mode: no virtual tap, no tcpreplay, no start trigger")
    up.add_argument("--no-network", action="store_true", help="skip veth/tc setup (interfaces already exist)")
    up.add_argument("--strict-boundary", action="store_true", help="refuse to run unless the monitor NIC is fully listen-only")
    up.add_argument("--auto-start", action="store_true", help="start the simulation immediately when READY")
    up.add_argument("--no-prompt", action="store_true", help="do not wait for ENTER on the terminal")
    up.add_argument("--exit-when-done", action="store_true", help="shut down after the first run has drained")
    up.add_argument("--teardown", action="store_true", help="delete the veth pair on exit")
    up.add_argument("--workers", type=int, default=None)
    w = sub.add_parser("worker", help="run one detection worker (spawned by `up`)")
    w.add_argument("--index", type=int, default=0)
    st = sub.add_parser("start", help="trigger the simulation on a running pipeline")
    sim_args(st)
    sub.add_parser("stop", help="stop the running replay (pipeline stays up and drains)")
    sub.add_parser("shutdown", help="stop the whole pipeline")
    s = sub.add_parser("status", help="show pipeline state and metrics")
    s.add_argument("--json", action="store_true")
    sub.add_parser("reset-metrics", help="zero counters and latency windows (before a benchmark step)")
    sub.add_parser("preflight", help="run the pre-flight checks and exit")
    sub.add_parser("dlq-replay", help="re-drive dead-lettered alerts/incidents into the sink")
    sub.add_parser("teardown", help="delete the virtual tap")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config.from_env()
    logging.basicConfig(level=getattr(logging, cfg.log_level, logging.INFO),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    cmd = args.command
    if cmd == "worker":
        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
        Worker(cfg, args.index).run(stop)
        return 0
    if cmd in ("up", "preflight"):
        for name in ("pcap", "mode", "rate", "loop", "workers"):
            if getattr(args, name, None) is None:
                setattr(args, name, {"pcap": cfg.pcap, "mode": "original", "rate": None, "loop": 1, "workers": cfg.workers}[name])
        for name, default in (("compose", False), ("no_replay", False), ("no_network", False), ("strict_boundary", False),
                              ("auto_start", False), ("no_prompt", False), ("exit_when_done", False), ("teardown", False)):
            if not hasattr(args, name):
                setattr(args, name, default)
        args.processor_cmd_overridden = bool(os.environ.get("CHERENKOV_PROCESSOR_CMD"))
        if args.workers != cfg.workers:
            cfg = Config(**{**cfg.__dict__, "workers": max(1, args.workers)})
        sup = Supervisor(cfg, args)
        if cmd == "preflight":
            bad = 0
            for c in sup.preflight():
                print(f"{c.level:4}  {c.name:16} {c.detail}")
                bad += c.level == "FAIL"
            return 2 if bad else 0
        return sup.run()
    if cmd == "start":
        payload: dict[str, Any] = {"cmd": "start"}
        payload.update({k: getattr(args, k) for k in ("pcap", "mode", "rate", "loop") if getattr(args, k) is not None})
        return send_control(cfg, payload)
    if cmd in ("stop", "shutdown"):
        return send_control(cfg, {"cmd": cmd})
    if cmd == "status":
        st = collect_status(cfg, connect_redis(cfg))
        print(json.dumps(st, indent=2) if args.json else "", end="")
        if not args.json:
            print_status(st)
        return 0
    if cmd == "reset-metrics":
        r = connect_redis(cfg)
        keys = Keys(cfg.prefix)
        r.set(keys.metrics_reset, f"{time.time():.6f}")
        r.delete(keys.metrics)
        print("metrics reset")
        return 0
    if cmd == "dlq-replay":
        replayed, remaining = replay_dead_letters(cfg)
        print(f"replayed={replayed} remaining={remaining}")
        return 0 if remaining == 0 else 1
    if cmd == "teardown":
        teardown_network(cfg)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())