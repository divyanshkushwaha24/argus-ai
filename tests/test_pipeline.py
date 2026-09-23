"""
tests/test_pipeline.py -- tests for pipeline/consumer.py

Two layers:
  * HERMETIC (default): fakeredis + in-memory sinks. No root, no network, no Redis server.
  * END-TO-END (opt-in): `CHERENKOV_IT=1 sudo -E pytest tests/test_pipeline.py -k e2e`
    Uses a real redis-server, a real veth pair, real tcpreplay and the real orchestrator.
    Needs Linux, root, redis-server, tcpreplay, iproute2. It creates/deletes veth0/veth1.
"""
from __future__ import annotations

import json
import math
import os
import shutil
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import fakeredis
import pytest
import redis

from pipeline import consumer as pc

ROOT = Path(pc.__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------
class MemorySink:
    """Idempotent in-memory sink shaped like alerting.writer (keyed upserts)."""

    def __init__(self, fail_times: int = 0):
        self.alerts: dict[str, dict] = {}
        self.incidents: dict[str, dict] = {}
        self.writes = 0
        self.fail_times = fail_times

    def _maybe_fail(self):
        if self.fail_times > 0:
            self.fail_times -= 1
            raise ConnectionError("postgres down")

    def write_alert(self, alert):
        self._maybe_fail()
        self.writes += 1
        self.alerts[alert["alert_id"]] = dict(alert)

    def upsert_incident(self, incident):
        self._maybe_fail()
        self.incidents[incident["incident_id"]] = dict(incident)


@pytest.fixture
def cfg(tmp_path):
    return pc.Config(
        jsonl_path=tmp_path / "alerts.jsonl", dead_letter_path=tmp_path / "dl.jsonl",
        cooldown_s=30, block_ms=50, batch=50,
    )


@pytest.fixture
def r():
    client = fakeredis.FakeRedis(decode_responses=True)
    yield client
    client.flushall()


@pytest.fixture
def keys(cfg):
    return pc.Keys(cfg.prefix)


def stub_detector(event, r):
    """Fires whenever an event carries a `cls` field; lets tests script detections."""
    if "cls" not in event:
        return None
    return [{"threat_class": event["cls"], "confidence": event.get("conf", 0.9), "anomaly": event.get("anom", 0.5),
             "evidence": [f"stub evidence for {event['cls']}"], "flow_id": event["flow_id"], "src_ip": event["src_ip"],
             "dst_ip": event.get("dst_ip")}]


def make_worker(cfg, r, sink=None, detectors=None):
    sink = sink or MemorySink()
    dets = detectors if detectors is not None else [pc.ManagedDetector("stub", stub_detector)]
    return pc.Worker(cfg, 0, r=r, detectors=dets, sink=sink), sink


def publish(r, cfg, **event):
    event.setdefault("ts", time.time())
    event.setdefault("event_type", "flow")
    event.setdefault("src_ip", "10.0.0.5")
    event.setdefault("flow_id", f"f{time.time_ns()}")
    return r.xadd(cfg.stream, {"data": json.dumps(event)})


def drain(worker):
    """Run the worker loop body once per call until the stream is fully consumed."""
    worker.ensure_group()
    for read_id in ("0", ">", ">"):
        resp = worker.r.xreadgroup(worker.cfg.group, worker.name, {worker.cfg.stream: read_id}, count=1000)
        entries = resp[0][1] if resp else []
        if entries:
            worker._process_batch(entries)


def alert_dict(cls="RECON_PORT_SCAN", risk=50, et=1_000_000.0, src="10.0.0.5"):
    return {"alert_id": f"{cls}{risk}{et}", "timestamp": pc.utc_iso(et), "event_time": pc.utc_iso(et), "flow_id": "f",
            "threat_class": cls, "confidence": 0.9, "risk_score": risk, "severity": pc.severity_for(risk),
            "evidence": ["e"], "incident_id": None, "src_ip": src, "dst_ip": None, "detector": "d", "schema_version": pc.SCHEMA_VERSION}


# ---------------------------------------------------------------------------
# Pure logic
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("score,band", [(0, "LOW"), (30, "LOW"), (31, "MEDIUM"), (60, "MEDIUM"), (61, "HIGH"), (80, "HIGH"), (81, "CRITICAL"), (100, "CRITICAL")])
def test_severity_bands_match_spec(score, band):
    assert pc.severity_for(score) == band


def test_fusion_params_weights_sum_to_one_and_cover_all_classes():
    assert set(pc.FUSION_PARAMS) == set(pc.THREAT_CLASSES)
    for weights, prior in pc.FUSION_PARAMS.values():
        assert math.isclose(sum(weights), 1.0)
        assert 0.0 <= prior <= 1.0


def test_fusion_documented_worked_example():
    # docs/model_notes.md s4: 0.40*0.9 + 0.20*0.6 + 0.30*0.9 + 0.10*0.3 = 0.78
    assert pc.fuse_builtin("DATA_EXFILTRATION", 0.9, 0.6, 0.3) == 78


def test_fusion_is_clipped_and_monotonic():
    assert pc.fuse_builtin("DDOS", 5, 5, 5) <= 100
    assert pc.fuse_builtin("DDOS", -5, -5, -5) >= 0
    assert pc.fuse_builtin("DDOS", 0.9, 0.5, 0.0) > pc.fuse_builtin("DDOS", 0.5, 0.5, 0.0)


def test_threat_class_aliases():
    assert pc.canonical_threat_class("dga") == "DGA_DNS_TUNNELING"
    assert pc.canonical_threat_class("Port-Scan") == "RECON_PORT_SCAN"
    assert pc.canonical_threat_class("DATA_EXFILTRATION") == "DATA_EXFILTRATION"
    with pytest.raises(ValueError):
        pc.canonical_threat_class("ransomware")


def test_recency_decay():
    assert pc.recency_score([], 100.0, 120.0) == 0.0
    assert math.isclose(pc.recency_score([100.0], 100.0, 120.0), 1 - math.exp(-1))
    assert math.isclose(pc.recency_score([100.0 - 120.0], 100.0, 120.0), 1 - math.exp(-0.5))
    assert pc.recency_score([100.0, 90.0], 100.0, 120.0) > pc.recency_score([100.0], 100.0, 120.0)


def test_percentile_nearest_rank():
    data = sorted(range(1, 101))
    assert pc.percentile(data, 50) == 50 and pc.percentile(data, 95) == 95 and pc.percentile(data, 99) == 99
    assert pc.percentile([], 50) == 0.0


# ---------------------------------------------------------------------------
# Contracts: events and detections
# ---------------------------------------------------------------------------
def test_normalize_event_ok_and_rejects_bad_input():
    ev = pc.normalize_event({"data": json.dumps({"ts": "12.5", "flow_id": 7, "src_ip": "1.1.1.1", "event_type": "dns"})}, "1700000000123-0")
    assert ev["ts"] == 12.5 and ev["flow_id"] == "7" and ev["_ingest_ms"] == 1700000000123
    for bad in ({}, {"data": "not json"}, {"data": "[1]"}, {"data": json.dumps({"ts": 1, "flow_id": "x", "src_ip": "y"})},
                {"data": json.dumps({"ts": "nan", "flow_id": "x", "src_ip": "y", "event_type": "flow"})}):
        with pytest.raises(ValueError):
            pc.normalize_event(bad, "1-0")


def test_coerce_detection_defaults_clamps_and_validates():
    event = {"flow_id": "F1", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "ts": 100.0}
    d = pc.coerce_detection({"threat_class": "scan", "confidence": 1.7, "evidence": "183 unique ports in 18s"}, event, "scan_detector")
    assert (d.threat_class, d.confidence, d.flow_id, d.dst_ip, d.event_time, d.detector) == ("RECON_PORT_SCAN", 1.0, "F1", "10.0.0.9", 100.0, "scan_detector")
    for bad in ({"threat_class": "scan", "confidence": 0.5, "evidence": []},
                {"threat_class": "scan", "confidence": float("nan"), "evidence": ["x"]},
                {"threat_class": "nope", "confidence": 0.5, "evidence": ["x"]},
                {"threat_class": "scan", "confidence": "high", "evidence": ["x"]}):
        with pytest.raises(ValueError):
            pc.coerce_detection(bad, event, "d")


def test_validate_alert_is_strict():
    good = alert_dict(risk=50)
    good["incident_id"] = "INC-000001"
    pc.validate_alert(good)
    for mutate in (lambda a: a.pop("evidence"), lambda a: a.update(risk_score=101), lambda a: a.update(severity="LOW"),
                   lambda a: a.update(threat_class="X"), lambda a: a.update(confidence=1.2), lambda a: a.update(extra=1),
                   lambda a: a.update(evidence=[]), lambda a: a.update(timestamp="yesterday"), lambda a: a.update(risk_score=50.0)):
        bad = dict(good)
        mutate(bad)
        with pytest.raises((ValueError, KeyError)):
            pc.validate_alert(bad)


def test_detector_circuit_breaker_and_isolation():
    calls = {"n": 0}

    def boom(event, r):
        calls["n"] += 1
        raise RuntimeError("bug in detector")

    det = pc.ManagedDetector("boom", boom)
    for _ in range(20):
        det.run({"flow_id": "f", "src_ip": "s", "ts": 1.0}, None)
    assert calls["n"] == pc.ManagedDetector.TRIP_AFTER  # tripped after 5, then skipped
    assert det.errors == 5


def test_detector_contract_violations_are_counted_not_fatal():
    det = pc.ManagedDetector("bad", lambda e, r: [{"threat_class": "scan", "confidence": 0.9, "evidence": []}])
    found, errors, violations = det.run({"flow_id": "f", "src_ip": "s", "ts": 1.0}, None)
    assert (found, errors, violations) == ([], 0, 1)


# ---------------------------------------------------------------------------
# Incident correlation
# ---------------------------------------------------------------------------
def test_incident_risk_escalates_like_the_demo(cfg, r, keys):
    corr = pc.IncidentCorrelator(cfg, r, keys)
    seq = [("RECON_PORT_SCAN", 40), ("DGA_DNS_TUNNELING", 42), ("C2_BEACONING", 50), ("DATA_EXFILTRATION", 70)]
    risks, ids = [], set()
    for i, (cls, risk) in enumerate(seq):
        inc = corr.attach(alert_dict(cls, risk, et=1_000_000.0 + i * 30))
        risks.append(inc["risk_score"])
        ids.add(inc["incident_id"])
    assert risks == [40, 65, 83, 95]
    assert len(ids) == 1 and inc["alert_count"] == 4 and inc["threat_classes"] == [c for c, _ in seq]
    assert inc["severity"] == "CRITICAL"


def test_incident_same_class_repeats_do_not_inflate(cfg, r, keys):
    corr = pc.IncidentCorrelator(cfg, r, keys)
    first = corr.attach(alert_dict("RECON_PORT_SCAN", 40, et=1000.0))
    again = corr.attach(alert_dict("RECON_PORT_SCAN", 30, et=1010.0))
    assert first["incident_id"] == again["incident_id"] and again["risk_score"] == 40 and again["alert_count"] == 2


def test_incident_separation_by_source_and_by_gap(cfg, r, keys):
    corr = pc.IncidentCorrelator(cfg, r, keys)
    a = corr.attach(alert_dict(risk=40, et=1000.0, src="10.0.0.5"))
    b = corr.attach(alert_dict(risk=40, et=1001.0, src="10.0.0.6"))
    c = corr.attach(alert_dict(risk=40, et=1000.0 + cfg.incident_gap_s + 1, src="10.0.0.5"))
    assert len({a["incident_id"], b["incident_id"], c["incident_id"]}) == 3


def test_ddos_incident_correlation_groups_by_victim_destination(cfg, r, keys):
    corr = pc.IncidentCorrelator(cfg, r, keys)
    # Two DDoS alerts from different spoofed sources attacking the same victim destination
    a1 = alert_dict(cls="DDOS", risk=70, et=1000.0, src="10.0.1.5")
    a1["dst_ip"] = "192.168.50.254"
    a2 = alert_dict(cls="DDOS", risk=75, et=1005.0, src="10.0.2.8")
    a2["dst_ip"] = "192.168.50.254"
    inc1 = corr.attach(a1)
    inc2 = corr.attach(a2)
    # Both should be grouped into the same incident keyed on the target victim
    assert inc1["incident_id"] == inc2["incident_id"]
    assert inc2["alert_count"] == 2
    assert inc2["src_ip"] == "192.168.50.254"

    # DDoS against a different victim creates a separate incident
    a3 = alert_dict(cls="DDOS", risk=70, et=1006.0, src="10.0.3.9")
    a3["dst_ip"] = "192.168.50.100"
    inc3 = corr.attach(a3)
    assert inc3["incident_id"] != inc1["incident_id"]


def test_multistage_killchain_simulation_correlates_to_critical(cfg, r, keys):
    corr = pc.IncidentCorrelator(cfg, r, keys)
    host = "192.168.50.100"

    # Stage 1: Reconnaissance (Port Scan) -> risk 55 (MEDIUM)
    a1 = alert_dict(cls="RECON_PORT_SCAN", risk=55, et=1000.0, src=host)
    inc1 = corr.attach(a1)
    assert inc1["risk_score"] == 55
    assert inc1["severity"] == "MEDIUM"
    assert inc1["alert_count"] == 1
    assert inc1["threat_classes"] == ["RECON_PORT_SCAN"]

    # Stage 2: C2 Beaconing -> risk 77 (HIGH) compounds into 90 (CRITICAL)
    a2 = alert_dict(cls="C2_BEACONING", risk=77, et=1030.0, src=host)
    inc2 = corr.attach(a2)
    assert inc2["incident_id"] == inc1["incident_id"]
    assert inc2["risk_score"] == 90
    assert inc2["severity"] == "CRITICAL"
    assert inc2["alert_count"] == 2
    assert inc2["threat_classes"] == ["RECON_PORT_SCAN", "C2_BEACONING"]

    # Stage 3: Data Exfiltration -> risk 82 (CRITICAL) compounds into 98 (CRITICAL)
    a3 = alert_dict(cls="DATA_EXFILTRATION", risk=82, et=1060.0, src=host)
    inc3 = corr.attach(a3)
    assert inc3["incident_id"] == inc1["incident_id"]
    assert inc3["risk_score"] == 98
    assert inc3["severity"] == "CRITICAL"
    assert inc3["alert_count"] == 3
    assert inc3["threat_classes"] == ["RECON_PORT_SCAN", "C2_BEACONING", "DATA_EXFILTRATION"]

    # Repeat alert within same class (e.g., further C2 beacon) does NOT inflate the 98 ceiling
    a4 = alert_dict(cls="C2_BEACONING", risk=75, et=1090.0, src=host)
    inc4 = corr.attach(a4)
    assert inc4["incident_id"] == inc1["incident_id"]
    assert inc4["risk_score"] == 98
    assert inc4["alert_count"] == 4

    # Standalone probe from another host does NOT get merged into the kill chain incident
    unrelated = alert_dict(cls="RECON_PORT_SCAN", risk=55, et=1095.0, src="192.168.50.15")
    inc_unrelated = corr.attach(unrelated)
    assert inc_unrelated["incident_id"] != inc1["incident_id"]
    assert inc_unrelated["risk_score"] == 55
    assert inc_unrelated["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Worker end to end (fakeredis)
# ---------------------------------------------------------------------------
def test_worker_end_to_end_alert_incident_ack_and_metrics(cfg, r, keys):
    worker, sink = make_worker(cfg, r)
    publish(r, cfg, cls="RECON_PORT_SCAN", conf=0.9, anom=0.7, flow_id="A1")
    publish(r, cfg, event_type="dns", flow_id="noise")  # no detection expected
    drain(worker)
    assert len(sink.alerts) == 1 and len(sink.incidents) == 1
    alert = next(iter(sink.alerts.values()))
    pc.validate_alert(alert)
    assert alert["threat_class"] == "RECON_PORT_SCAN" and alert["flow_id"] == "A1"
    assert alert["risk_score"] == pc.fuse_builtin("RECON_PORT_SCAN", 0.9, 0.7, 0.0)
    assert alert["incident_id"] in sink.incidents
    assert r.xpending(cfg.stream, cfg.group)["pending"] == 0     # everything acknowledged
    worker.metrics.flush(r, force=True)
    totals = r.hgetall(keys.metrics)
    assert totals["events_in"] == "2" and totals["alerts_emitted"] == "1"
    lat = r.hgetall(keys.lat("worker-0"))
    assert float(lat["alert_latency_p50_ms"]) >= 0 and lat["alert_latency_n"] == "1"


def test_cooldown_suppresses_alert_storms_but_not_other_classes(cfg, r):
    worker, sink = make_worker(cfg, r)
    for i in range(50):                                            # a scan: 50 qualifying flows
        publish(r, cfg, cls="RECON_PORT_SCAN", flow_id=f"s{i}")
    publish(r, cfg, cls="C2_BEACONING", flow_id="b1")              # different class, same host
    drain(worker)
    classes = sorted(a["threat_class"] for a in sink.alerts.values())
    assert classes == ["C2_BEACONING", "RECON_PORT_SCAN"]
    assert worker.metrics.counters["alerts_suppressed"] == 49


def test_ddos_cooldown_suppresses_alert_flood_by_destination_ip(cfg, r):
    worker, sink = make_worker(cfg, r)
    # 20 DDoS flows with random spoofed sources hitting the same target
    for i in range(20):
        publish(r, cfg, cls="DDOS", flow_id=f"ddos_{i}", src_ip=f"10.0.{i}.1", dst_ip="192.168.50.254")
    # 1 DDoS flow hitting a different target
    publish(r, cfg, cls="DDOS", flow_id="ddos_other", src_ip="10.0.99.1", dst_ip="192.168.50.100")
    drain(worker)
    # 19 of the 20 attacks on the first target should be suppressed by cooldown
    assert worker.metrics.counters["alerts_suppressed"] == 19
    # Only 2 alerts emitted: 1 for victim .254 and 1 for victim .100
    assert len(sink.alerts) == 2


def test_batch_correlation_groups_ddos_by_destination():
    from models.alert_schema import Alert
    from models.correlation import correlate_alerts, get_incident_summary
    alerts = [
        Alert(timestamp="2026-09-23T10:00:00+00:00", flow_id="f1", src_ip="10.0.0.1", dest_ip="192.168.50.30", threat_class="ddos", risk_score=75),
        Alert(timestamp="2026-09-23T10:01:00+00:00", flow_id="f2", src_ip="10.0.0.2", dest_ip="192.168.50.30", threat_class="ddos", risk_score=80),
        Alert(timestamp="2026-09-23T10:01:30+00:00", flow_id="f3", src_ip="10.0.0.3", dest_ip="192.168.50.99", threat_class="ddos", risk_score=70),
    ]
    correlated = correlate_alerts(alerts)
    # First two alerts target .30 -> same incident
    assert correlated[0].incident_id == correlated[1].incident_id
    # Third alert targets .99 -> different incident
    assert correlated[2].incident_id != correlated[0].incident_id

    summaries = get_incident_summary(correlated)
    assert len(summaries) == 2
    by_ip = {s["src_ip"]: s for s in summaries}
    assert by_ip["192.168.50.30"]["alert_count"] == 2
    assert by_ip["192.168.50.99"]["alert_count"] == 1


def test_recency_raises_risk_on_repeat_source(cfg, r):
    worker, sink = make_worker(cfg, r)
    t = time.time()
    publish(r, cfg, cls="RECON_PORT_SCAN", flow_id="r1", ts=t)
    publish(r, cfg, cls="DGA_DNS_TUNNELING", flow_id="r2", ts=t + 5)
    drain(worker)
    by_class = {a["threat_class"]: a for a in sink.alerts.values()}
    first = pc.fuse_builtin("RECON_PORT_SCAN", 0.9, 0.5, 0.0)
    assert by_class["RECON_PORT_SCAN"]["risk_score"] == first
    assert by_class["DGA_DNS_TUNNELING"]["risk_score"] > pc.fuse_builtin("DGA_DNS_TUNNELING", 0.9, 0.5, 0.0)


def test_redelivery_is_idempotent(cfg, r):
    worker, sink = make_worker(cfg, r)
    ev = pc.normalize_event({"data": json.dumps({"ts": time.time(), "flow_id": "X", "src_ip": "10.0.0.5", "event_type": "flow", "cls": "DDOS"})},
                            f"{int(time.time() * 1000)}-0")
    det = pc.coerce_detection(stub_detector(ev, r)[0], ev, "stub")
    a1 = worker.engine.process(det, ev["_ingest_ms"])
    a2 = worker.engine.process(det, ev["_ingest_ms"])   # simulated crash-before-ack redelivery
    assert a1["alert_id"] == a2["alert_id"] and a1["risk_score"] == a2["risk_score"]
    assert len(sink.alerts) == 1                        # keyed upsert: exactly one row


def test_poison_message_is_dead_lettered_and_acked(cfg, r):
    worker, sink = make_worker(cfg, r)
    r.xadd(cfg.stream, {"data": "{{{ not json"})
    r.xadd(cfg.stream, {"wrong": "shape"})
    publish(r, cfg, cls="DDOS", flow_id="ok")
    drain(worker)
    assert r.xlen(cfg.dlq) == 2 and len(sink.alerts) == 1
    assert r.xpending(cfg.stream, cfg.group)["pending"] == 0
    assert worker.metrics.counters["events_invalid"] == 2


def test_detector_crash_does_not_block_other_detectors(cfg, r):
    def broken(event, r):
        raise ValueError("kaboom")

    worker, sink = make_worker(cfg, r, detectors=[pc.ManagedDetector("broken", broken), pc.ManagedDetector("stub", stub_detector)])
    publish(r, cfg, cls="DDOS", flow_id="z")
    drain(worker)
    assert len(sink.alerts) == 1 and worker.metrics.counters["detector_errors"] == 1


def test_sink_outage_dead_letters_then_replays(cfg, r, monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda s: None)          # skip retry backoff
    down = MemorySink(fail_times=10_000)
    worker, _ = make_worker(cfg, r, sink=down)
    publish(r, cfg, cls="DATA_EXFILTRATION", flow_id="e1")
    drain(worker)
    assert r.xlen(cfg.dlq) == 2                                  # incident + alert parked, nothing lost
    assert r.xpending(cfg.stream, cfg.group)["pending"] == 0     # the event itself was consumed
    healthy = MemorySink()
    replayed, remaining = pc.replay_dead_letters(cfg, r=r, sink=healthy)
    assert (replayed, remaining) == (2, 0) and len(healthy.alerts) == 1 and len(healthy.incidents) == 1
    assert r.xlen(cfg.dlq) == 0


def test_unacked_entries_are_reprocessed_after_a_crash(cfg, r):
    worker, sink = make_worker(cfg, r)
    publish(r, cfg, cls="DDOS", flow_id="crash1")
    worker.ensure_group()
    r.xreadgroup(cfg.group, worker.name, {cfg.stream: ">"}, count=10)   # delivered, never acked (crash)
    assert r.xpending(cfg.stream, cfg.group)["pending"] == 1
    drain(worker)                                                       # restart: reads own pending first
    assert len(sink.alerts) == 1 and r.xpending(cfg.stream, cfg.group)["pending"] == 0


def test_jsonl_sink_roundtrip(cfg, r):
    worker, _ = make_worker(cfg, r, sink=pc.JsonlSink(cfg.jsonl_path))
    publish(r, cfg, cls="C2_BEACONING", flow_id="j1")
    drain(worker)
    rows = [json.loads(line) for line in cfg.jsonl_path.read_text().splitlines()]
    assert [x["kind"] for x in rows] == ["incident", "alert"]       # parent before child


def test_metrics_reset_clears_window_and_acknowledges(cfg, r, keys):
    m = pc.Metrics(keys, "worker-0")
    m.flush(r, force=True)
    m.inc("events_in", 5)
    m.alert_latency_ms.extend([10, 20, 30])
    m.flush(r, force=True)
    assert r.hget(keys.metrics, "events_in") == "5"
    r.set(keys.metrics_reset, "epoch-2")
    m.flush(r)                                                       # noticed even inside the flush interval
    assert r.hget(keys.lat("worker-0"), "reset_epoch") == "epoch-2"
    assert r.hget(keys.lat("worker-0"), "alert_latency_n") == "0"
    r.delete(keys.metrics)
    m.inc("events_in", 2)
    m.flush(r, force=True)
    assert r.hget(keys.metrics, "events_in") == "2"                  # nothing from the old window leaks in


# ---------------------------------------------------------------------------
# Orchestrator pieces that need no privileges
# ---------------------------------------------------------------------------
def test_build_replay_cmd(cfg, monkeypatch):
    monkeypatch.setattr(pc, "_priv", lambda c: [])
    p = Path("/x/demo.pcap")
    assert pc.build_replay_cmd(cfg, p) == ["tcpreplay", "--intf1=veth0", "--stats=5", "/x/demo.pcap"]
    assert "--pps=10000" in pc.build_replay_cmd(cfg, p, "pps", 10000)
    assert "--multiplier=2.5" in pc.build_replay_cmd(cfg, p, "multiplier", 2.5)
    assert "--topspeed" in pc.build_replay_cmd(cfg, p, "topspeed")
    assert "--loop=0" in pc.build_replay_cmd(cfg, p, "original", loop=0)
    with pytest.raises(ValueError):
        pc.build_replay_cmd(cfg, p, "pps", None)
    with pytest.raises(ValueError):
        pc.build_replay_cmd(cfg, p, "warp")


def test_control_plane_input_is_validated(cfg, tmp_path):
    good = ROOT / "data" / "replay" / "_t.pcap"
    good.parent.mkdir(parents=True, exist_ok=True)
    good.write_bytes(b"x")
    try:
        assert pc.validate_sim_request(cfg, {"pcap": str(good), "mode": "pps", "rate": "500", "loop": 2})[1:] == ("pps", 500.0, 2)
        for bad in ({"pcap": "/etc/passwd"}, {"pcap": str(tmp_path / "x.pcap")}, {"pcap": "../../etc/shadow"},
                    {"pcap": str(good), "mode": "; rm -rf /"}, {"pcap": str(good), "mode": "pps", "rate": "inf"},
                    {"pcap": str(good), "loop": -1}, {"pcap": str(good), "loop": 10**9}):
            with pytest.raises(ValueError):
                pc.validate_sim_request(cfg, bad)
    finally:
        good.unlink()


def test_verify_readonly_reports_partial_and_enforced(cfg, monkeypatch):
    def fake_run(out_ip, out_tc):
        def run(argv, check=True, timeout=30.0):
            text = out_ip if "addr" in argv else out_tc
            return subprocess.CompletedProcess(argv, 0, stdout=text, stderr="")
        return run

    ip_ok = json.dumps([{"flags": ["BROADCAST", "MULTICAST", "PROMISC", "NOARP", "UP"], "addr_info": []}])
    monkeypatch.setattr(pc, "_run", fake_run(ip_ok, "filter protocol all pref 1 matchall\n  action order 1: gact action drop"))
    assert pc.verify_readonly(cfg)["level"] == "ENFORCED"
    monkeypatch.setattr(pc, "_run", fake_run(ip_ok, ""))
    assert pc.verify_readonly(cfg)["level"] == "PARTIAL"
    ip_bad = json.dumps([{"flags": ["UP"], "addr_info": [{"local": "10.1.1.1"}]}])
    monkeypatch.setattr(pc, "_run", fake_run(ip_bad, "action drop"))
    rep = pc.verify_readonly(cfg)
    assert rep["level"] == "PARTIAL" and rep["no_ip"] is False and rep["arp_off"] is False


def test_managed_process_restarts_then_gives_up():
    proc = pc.ManagedProcess("crashy", [sys.executable, "-c", "raise SystemExit(3)"], max_restarts=2, window_s=60)
    proc.start()
    seen = set()
    deadline = time.time() + 20
    while time.time() < deadline and "failed" not in seen:
        proc.proc.wait()
        seen.add(proc.check())
        time.sleep(0.05)
        proc._next_start = 0.0
    assert "restarted" in seen and "failed" in seen
    proc.stop()


def test_managed_process_stop_is_graceful():
    proc = pc.ManagedProcess("sleeper", [sys.executable, "-c", "import time; time.sleep(60)"])
    proc.start()
    assert proc.alive
    proc.stop(timeout=5)
    assert not proc.alive and proc.check() == "ok"    # stopping flag: no resurrection during shutdown


def test_duplicate_worker_is_refused(cfg, r, keys):
    worker, _ = make_worker(cfg, r)
    r.set(keys.hb("worker-0"), f"{os.getpid() + 12345}:{time.time():.3f}", ex=15)   # someone else holds the slot
    import threading
    with pytest.raises(RuntimeError, match="already running"):
        worker.claim_slot(threading.Event(), wait_s=0.0)
    r.delete(keys.hb("worker-0"))
    worker.claim_slot(threading.Event(), wait_s=0.0)                                # free slot: fine
    r.set(keys.hb("worker-0"), f"{os.getpid()}:{time.time():.3f}", ex=15)           # our own heartbeat: fine
    worker.claim_slot(threading.Event(), wait_s=0.0)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux-only")
def test_children_die_with_a_killed_supervisor():
    """A crashed/SIGKILLed orchestrator must not leave orphaned workers running."""
    code = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(ROOT)!r})
        from pipeline import consumer as pc
        p = pc.ManagedProcess("sleeper", [sys.executable, "-c", "import time; time.sleep(120)"])
        p.start(); print(p.proc.pid, flush=True); time.sleep(120)
    """)
    parent = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    child_pid = int(parent.stdout.readline())
    os.kill(child_pid, 0)                       # alive
    parent.kill()
    parent.wait()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            os.kill(child_pid, 0)
            with open(f"/proc/{child_pid}/stat") as fh:
                if fh.read().split(")")[-1].split()[0] == "Z":   # zombie = already dead
                    return
        except (ProcessLookupError, FileNotFoundError):
            return
        time.sleep(0.1)
    pytest.fail("child survived its supervisor")


# ---------------------------------------------------------------------------
# END-TO-END: real redis-server + veth + tcpreplay + orchestrator (opt-in)
# ---------------------------------------------------------------------------
E2E_READY = (os.environ.get("CHERENKOV_IT") == "1" and sys.platform.startswith("linux") and hasattr(os, "geteuid")
             and os.geteuid() == 0 and shutil.which("redis-server") and shutil.which("tcpreplay") and shutil.which("ip"))

FAKE_PROCESSOR = textwrap.dedent('''
    """Test stand-in for streaming/event_processor.py: sniff veth1, keep a scan window in Redis, publish events."""
    import json, os, socket, struct, time, redis
    r = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)); s.bind((os.environ.get("CHERENKOV_RX_IFACE", "veth1"), 0))
    while True:
        frame = s.recv(65535)
        if frame[12:14] != b"\\x08\\x00":
            continue
        ihl = (frame[14] & 0x0F) * 4
        src, dst = socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34])
        sport, dport = struct.unpack("!HH", frame[14 + ihl:14 + ihl + 4])
        ts = time.time()
        key = "f:scan:" + src
        pipe = r.pipeline()
        pipe.zadd(key, {f"{dst}:{dport}": ts}); pipe.zremrangebyscore(key, 0, ts - 30); pipe.expire(key, 120)
        pipe.execute()                                        # window first ...
        ev = {"ts": ts, "flow_id": f"{src}:{sport}>{dst}:{dport}", "event_type": "flow", "src_ip": src, "dst_ip": dst,
              "src_port": sport, "dst_port": dport, "proto": "TCP"}
        r.xadd(os.environ.get("CHERENKOV_STREAM", "cherenkov:events"), {"data": json.dumps(ev)})   # ... then publish
''')

STUB_DETECTOR = textwrap.dedent('''
    def evaluate(event, r):
        n = r.zcard("f:scan:" + event["src_ip"])
        if n >= 10:
            return [{"threat_class": "RECON_PORT_SCAN", "confidence": 0.9, "anomaly": 0.7,
                     "evidence": [f"{n} unique destination ports in 30s"]}]
''')


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.skipif(not E2E_READY, reason="set CHERENKOV_IT=1 and run as root on Linux with redis-server, tcpreplay, iproute2")
def test_e2e_pcap_to_alert_through_real_orchestrator(tmp_path):
    port = _free_port()
    server = subprocess.Popen(["redis-server", "--port", str(port), "--save", "", "--appendonly", "no"], stdout=subprocess.DEVNULL)
    try:
        url = f"redis://127.0.0.1:{port}/0"
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                redis.Redis.from_url(url).ping()
                break
            except redis.RedisError:
                time.sleep(0.1)
        (tmp_path / "stubdet.py").write_text(STUB_DETECTOR)
        (tmp_path / "fake_processor.py").write_text(FAKE_PROCESSOR)
        pcap = ROOT / "data" / "replay" / "_e2e.pcap"
        from scapy.all import IP, TCP, Ether, wrpcap  # test-only dependency
        wrpcap(str(pcap), [Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40000 + i, dport=1000 + i, flags="S") for i in range(30)])
        out = tmp_path / "alerts.jsonl"
        env = {**os.environ, "REDIS_URL": url, "CHERENKOV_DETECTORS": "stubdet", "CHERENKOV_JSONL_PATH": str(out),
               "CHERENKOV_PROCESSOR_CMD": f"{sys.executable} {tmp_path / 'fake_processor.py'}", "CHERENKOV_SINK": "jsonl",
               "CHERENKOV_DRAIN_QUIET_S": "1", "CHERENKOV_LOG_LEVEL": "INFO", "PYTHONPATH": f"{tmp_path}{os.pathsep}{ROOT}"}
        result = subprocess.run([sys.executable, "-m", "pipeline.consumer", "up", "--auto-start", "--no-prompt", "--exit-when-done",
                                 "--teardown", "--pcap", str(pcap), "--mode", "pps", "--rate", "200"],
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
        rows = [json.loads(line) for line in out.read_text().splitlines()]
        alerts = [x for x in rows if x["kind"] == "alert"]
        assert len(alerts) == 1, rows                          # cooldown: one alert for the whole scan
        pc.validate_alert({k: v for k, v in alerts[0].items() if k != "kind"})
        assert alerts[0]["threat_class"] == "RECON_PORT_SCAN" and alerts[0]["incident_id"].startswith("INC-")
        r = redis.Redis.from_url(url, decode_responses=True)
        state = r.hgetall("cherenkov:state")
        assert state["state"] == "STOPPED"
        assert int(r.hget("cherenkov:metrics", "events_in") or 0) >= 30
        assert r.xpending("cherenkov:events", "cherenkov-detect")["pending"] == 0
    finally:
        server.terminate()
        server.wait(timeout=5)
        (ROOT / "data" / "replay" / "_e2e.pcap").unlink(missing_ok=True)
        subprocess.run(["ip", "link", "del", "veth0"], capture_output=True)