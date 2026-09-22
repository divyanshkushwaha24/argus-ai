#!/usr/bin/env python3
"""
Cherenkov -- streaming/event_processor.py

Tails Zeek's JSON logs and Suricata's eve.json, normalizes both into one
event shape, and dispatches each event into the Redis-backed sliding-
window features in features/. Deliberately plain Python + threading --
no Kafka, per the tech-stack doc's explicit call-out that a broker isn't
needed to satisfy "streaming, not batch" (PS constraint c).

By default this reads each log file from the beginning, then keeps
following new lines -- which means it works identically against a
finished, static fixture (e.g. data/sample_logs/portscan/) and against a
log that's still actively growing under a live Zeek/Suricata pair. Use
--no-from-start if you specifically want to skip existing content and
only process new events from process-start onward.

Usage (against a committed fixture, needs no live capture running):
    python3 streaming/event_processor.py \\
        --zeek-dir data/sample_logs/portscan/zeek \\
        --eve-json data/sample_logs/portscan/suricata/eve.json

Usage (against a live capture, same directories ingest/test_all_threats.sh
or a manually-started Zeek/Suricata pair is currently writing to):
    python3 streaming/event_processor.py \\
        --zeek-dir /path/to/live/zeek/output \\
        --eve-json /path/to/live/suricata/eve.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import queue
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# Make `features` importable regardless of the working directory this
# script is launched from.
_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

_candidate_sites = [
    _repo_root / ".venv" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages",
    Path(os.path.expanduser(f"~/.local/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")),
]
for _s in _candidate_sites:
    if _s.is_dir() and str(_s) not in sys.path:
        sys.path.insert(0, str(_s))

import redis

from features.state_store import StateStore
from features import entropy, periodicity, fanout, fingerprint


ZEEK_LOG_TYPES = ["conn", "dns", "ssl", "ssh", "http", "notice", "software"]
CONNECTION_LOG_TYPES = {"conn", "flow"}  # one record per actual connection/flow


# ---------------------------------------------------------------------
# Normalization: Zeek's and Suricata's schemas -> one common event shape
# ---------------------------------------------------------------------

def normalize_zeek(log_type: str, raw: dict) -> dict:
    flow_id = raw.get("uid") or f"{raw.get('id.orig_h')}:{raw.get('id.orig_p')}-{raw.get('id.resp_h')}:{raw.get('id.resp_p')}"
    return {
        "source": "zeek",
        "log_type": log_type,
        "event_type": log_type,
        "ts": float(raw.get("ts", time.time())),
        "flow_id": str(flow_id),
        "uid": raw.get("uid"),
        "src_ip": raw.get("id.orig_h"),
        "src_port": raw.get("id.orig_p"),
        "dst_ip": raw.get("id.resp_h"),
        "dst_port": raw.get("id.resp_p"),
        "proto": raw.get("proto"),
        "app_proto": raw.get("service"),
        "orig_bytes": raw.get("orig_bytes"),
        "resp_bytes": raw.get("resp_bytes"),
        "bytes_out": raw.get("orig_bytes"),
        "bytes_in": raw.get("resp_bytes"),
        "pkts_toserver": raw.get("orig_pkts"),
        "pkts_toclient": raw.get("resp_pkts"),
        "duration": raw.get("duration"),
        "conn_state": raw.get("conn_state"),
        "query": raw.get("query"),        # populated on dns.log rows
        "dns_query": raw.get("query"),
        "qtype": raw.get("qtype_name"),   # populated on dns.log rows
        "dns_qtype": raw.get("qtype_name"),
        "ja3": None,                      # Zeek needs the salesforce/ja3 zkg
                                           # package for this -- see
                                           # ingest/zeek_config/local.zeek
        "raw": raw,
    }


def _parse_suricata_ts(ts_str) -> float:
    """Suricata's timestamp is ISO 8601, e.g.
    '2026-09-21T10:15:03.123456+0000'. Python 3.11+'s fromisoformat
    handles this directly; older Pythons would need a manual fallback."""
    if not ts_str:
        return time.time()
    try:
        return datetime.fromisoformat(ts_str).timestamp()
    except ValueError:
        return time.time()


def normalize_suricata(raw: dict) -> dict:
    event_type = raw.get("event_type", "unknown")
    flow = raw.get("flow") or {}
    tls = raw.get("tls") or {}
    dns = raw.get("dns") or {}
    ja3 = (tls.get("ja3") or {}).get("hash") or raw.get("ja3") or raw.get("ja3_hash")
    flow_id = raw.get("flow_id") or f"{raw.get('src_ip')}:{raw.get('src_port')}-{raw.get('dest_ip')}:{raw.get('dest_port')}"

    dns_query = dns.get("rrname")
    dns_qtype = dns.get("rrtype")
    if not dns_query and isinstance(dns.get("queries"), list) and dns["queries"]:
        dns_query = dns["queries"][0].get("rrname")
        dns_qtype = dns["queries"][0].get("rrtype")

    return {
        "source": "suricata",
        "log_type": event_type,
        "event_type": event_type,
        "ts": _parse_suricata_ts(raw.get("timestamp")),
        "flow_id": str(flow_id),
        "uid": raw.get("flow_id"),
        "src_ip": raw.get("src_ip"),
        "src_port": raw.get("src_port"),
        "dst_ip": raw.get("dest_ip"),
        "dst_port": raw.get("dest_port"),
        "proto": raw.get("proto"),
        "app_proto": raw.get("app_proto"),
        "orig_bytes": flow.get("bytes_toserver"),
        "resp_bytes": flow.get("bytes_toclient"),
        "bytes_out": flow.get("bytes_toserver"),
        "bytes_in": flow.get("bytes_toclient"),
        "pkts_toserver": flow.get("pkts_toserver"),
        "pkts_toclient": flow.get("pkts_toclient"),
        "duration": float(flow.get("age", 0.001)) if flow.get("age") is not None else None,
        "conn_state": flow.get("state"),
        "query": dns_query,
        "dns_query": dns_query,
        "qtype": dns_qtype,
        "dns_qtype": dns_qtype,
        "ja3": ja3,
        "raw": raw,
    }


# ---------------------------------------------------------------------
# File tailing (tail -f, multiple files, via threads + a shared queue)
# ---------------------------------------------------------------------

def follow(path: str, poll_interval: float = 0.5,
           stop_event: threading.Event | None = None, from_start: bool = True):
    """Yields new lines appended to `path`, like `tail -f`. Waits for the
    file to appear if it doesn't exist yet -- Zeek/Suricata may not have
    created it the instant this process starts."""
    while not os.path.exists(path):
        if stop_event and stop_event.is_set():
            return
        time.sleep(poll_interval)

    with open(path, "r") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        while not (stop_event and stop_event.is_set()):
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            yield line


def tail_worker(path: str, source: str, log_type: str | None, out_q: "queue.Queue",
                 stop_event: threading.Event, from_start: bool) -> None:
    for line in follow(path, stop_event=stop_event, from_start=from_start):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        out_q.put((source, log_type, raw))


def discover_zeek_files(zeek_dir: str) -> dict:
    """Maps log_type -> file path for whichever Zeek logs exist in the
    directory right now. Missing log types (e.g. no ssh.log if there was
    no SSH traffic in this pcap) are simply skipped -- new ones that
    appear after startup are not auto-discovered in this version."""
    found = {}
    for log_type in ZEEK_LOG_TYPES:
        path = os.path.join(zeek_dir, f"{log_type}.log")
        if os.path.exists(path):
            found[log_type] = path
    return found


# ---------------------------------------------------------------------
# Dispatch: route one normalized event into the relevant feature updates
# ---------------------------------------------------------------------

def dispatch(store: StateStore, blacklist: set, event: dict) -> None:
    """A single event can feed more than one feature family. Connection-
    level features (fan-out, periodicity, destination-hit entropy) are
    only updated from actual connection/flow records (Zeek's conn.log,
    Suricata's 'flow' events) -- not from every protocol-detail log line
    describing the same connection (ssl.log, http.log, etc.) -- so one
    real connection is counted once, not three or four times."""
    log_type = event["log_type"]
    src_ip, dst_ip = event.get("src_ip"), event.get("dst_ip")
    ts = event.get("ts")

    if log_type in CONNECTION_LOG_TYPES and src_ip and dst_ip:
        fanout.record_connection_attempt(store, src_ip, dst_ip, event.get("dst_port") or 0, ts)
        periodicity.record_connection(store, src_ip, dst_ip, ts)
        entropy.record_destination_hit(store, dst_ip, src_ip, ts)

    if log_type == "dns" and event.get("query") and src_ip:
        entropy.record_dns_query(store, src_ip, event["query"], ts)

    if event.get("ja3") and src_ip:
        fingerprint.check_ja3(store, src_ip, event["ja3"], blacklist, ts)


def enrich_streaming_features(store: StateStore, event: dict) -> dict:
    """Query StateStore → inject aggregate features into the event dict."""

    # ── Fix field name mismatch ONCE here, before ANY detector sees the event ──
    if "dst_ip" in event and "dest_ip" not in event:
        event["dest_ip"] = event["dst_ip"]
    if "dst_port" in event and "dest_port" not in event:
        event["dest_port"] = event["dst_port"]
    if "conn_state" in event and "flow_state" not in event:
        event["flow_state"] = event["conn_state"]
    if "ja3" in event and "ja3_hash" not in event:
        event["ja3_hash"] = event["ja3"]

    src_ip = event.get("src_ip")
    dst_ip = event.get("dst_ip") or event.get("dest_ip")

    # 1. Fanout & unique destination ports / IPs
    if src_ip:
        event["unique_destination_ports"] = store.set_cardinality(f"fanout:dst_ports:{src_ip}") or 1
        event["destination_fanout"] = event["unique_destination_ports"]
        event["unique_destination_ips"] = store.set_cardinality(f"fanout:dst_ips:{src_ip}") or 1
        event["source_flow_count"] = store.ts_count(f"fanout:attempts:{src_ip}", window_s=600.0) or 1

    # 2. Inter-arrival time for beaconing
    if src_ip and dst_ip:
        ts_list = store.ts_timestamps(f"periodicity:{src_ip}:{dst_ip}", window_s=600.0)
        if len(ts_list) >= 2:
            diffs = [ts_list[i] - ts_list[i - 1] for i in range(1, len(ts_list))]
            event["src_interarrival_sec"] = float(sum(diffs) / len(diffs)) if diffs else 0.0
        else:
            event["src_interarrival_sec"] = 0.0

    # 3. Real Shannon entropy for DDoS detection (Bug 1 fix)
    if dst_ip:
        hit_counts = store.get_hit_counts(f"entropy:dst_sources:{dst_ip}")
        if hit_counts:
            total = sum(hit_counts.values())
            source_ip_entropy = -sum(
                (count / total) * math.log2(count / total)
                for count in hit_counts.values()
                if count > 0
            )
            source_ip_count = len(hit_counts)
        else:
            source_ip_entropy = 0.0
            source_ip_count = 1
        event["source_ip_entropy_in_file"] = source_ip_entropy
        event["source_ip_count_in_file"] = source_ip_count

    # 4. Exfiltration byte/packet rates and ratios
    bytes_out = float(event.get("bytes_out") or event.get("orig_bytes") or 0)
    bytes_in = float(event.get("bytes_in") or event.get("resp_bytes") or 0)
    duration = float(event.get("duration") or 0.001)
    event["bytes_to_server"] = bytes_out
    event["bytes_to_client"] = bytes_in
    event["total_bytes"] = bytes_out + bytes_in
    event["upload_download_ratio"] = bytes_out / max(1.0, bytes_in)
    event["byte_rate"] = (bytes_out + bytes_in) / max(0.001, duration)

    # 5. Packets and Anomaly Model features
    pkts_out = float(event.get("pkts_toserver") or event.get("packets_to_server") or 0)
    pkts_in = float(event.get("pkts_toclient") or event.get("packets_to_client") or 0)
    total_pkts = pkts_out + pkts_in
    event["packets_to_server"] = pkts_out
    event["packets_to_client"] = pkts_in
    event["total_packets"] = total_pkts
    event["average_packet_size"] = (bytes_out + bytes_in) / max(1.0, total_pkts)
    event["flow_duration"] = duration
    event["packet_rate"] = total_pkts / max(0.001, duration)

    # 6. Protocol event indicators
    is_tls = bool(event.get("ja3") or event.get("ja3_hash") or event.get("app_proto") == "tls" or event.get("log_type") == "ssl")
    event["tls_event_count"] = 1 if is_tls else 0

    is_dns = bool(event.get("dns_query") or event.get("query") or event.get("log_type") == "dns" or event.get("event_type") == "dns")
    if is_dns and src_ip:
        event["dns_event_count"] = store.ts_count(f"entropy:dns_events:{src_ip}", window_s=600.0) or 1
    elif is_dns:
        event["dns_event_count"] = 1
    else:
        event["dns_event_count"] = 0

    return event


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Cherenkov event processor")
    parser.add_argument("--zeek-dir", default="data/sample_logs/portscan/zeek", help="directory containing Zeek's *.log files")
    parser.add_argument("--eve-json", default="data/sample_logs/portscan/suricata/eve.json", help="path to Suricata's eve.json")
    parser.add_argument("--redis-host", default="localhost")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--stream", default=os.getenv("CHERENKOV_STREAM", "cherenkov:events"),
                        help="Redis stream key to publish normalized events")
    parser.add_argument("--ja3-blacklist", default="data/ja3_blacklist/blacklist.csv")
    parser.add_argument("--no-from-start", action="store_true",
                         help="skip existing log content, only process new lines")
    args = parser.parse_args()
    from_start = not args.no_from_start

    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        r = redis.Redis.from_url(redis_url, decode_responses=True)
    else:
        r = redis.Redis(host=args.redis_host, port=args.redis_port, decode_responses=True)

    try:
        r.ping()
    except redis.exceptions.ConnectionError as e:
        endpoint = redis_url or f"{args.redis_host}:{args.redis_port}"
        print(f"cannot reach Redis at {endpoint} -- is `docker-compose up -d` running? ({e})")
        sys.exit(1)

    store = StateStore(r)
    blacklist = fingerprint.load_blacklist(args.ja3_blacklist)
    print(f"loaded {len(blacklist)} JA3 blacklist entries from {args.ja3_blacklist}")

    q: "queue.Queue" = queue.Queue()
    stop_event = threading.Event()
    threads = []

    zeek_files = discover_zeek_files(args.zeek_dir)
    if not zeek_files:
        print(f"warning: no Zeek logs found yet under {args.zeek_dir}")
    for log_type, path in zeek_files.items():
        t = threading.Thread(target=tail_worker, args=(path, "zeek", log_type, q, stop_event, from_start), daemon=True)
        t.start()
        threads.append(t)
        print(f"tailing {path}")

    t = threading.Thread(target=tail_worker, args=(args.eve_json, "suricata", None, q, stop_event, from_start), daemon=True)
    t.start()
    threads.append(t)
    print(f"tailing {args.eve_json}")

    processed = 0
    try:
        while True:
            source, log_type, raw = q.get()
            event = normalize_zeek(log_type, raw) if source == "zeek" else normalize_suricata(raw)
            if not event.get("src_ip"):
                continue
            dispatch(store, blacklist, event)
            enrich_streaming_features(store, event)

            # Contract 1: Publish normalized event to Redis stream for detection workers
            stream_event = {k: v for k, v in event.items() if k != "raw" and v is not None}
            try:
                r.xadd(args.stream, {"data": json.dumps(stream_event, default=str)}, maxlen=200_000, approximate=True)
            except Exception as exc:
                if processed % 100 == 0:
                    print(f"warning: failed to publish to stream {args.stream}: {exc}")

            processed += 1
            if processed % 50 == 0:
                print(f"processed {processed} events")
    except KeyboardInterrupt:
        print(f"\nstopping -- processed {processed} events total")
        stop_event.set()


if __name__ == "__main__":
    main()
