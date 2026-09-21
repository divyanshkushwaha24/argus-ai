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
import os
import queue
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# Make `features` importable regardless of the working directory this
# script is launched from.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import redis

from features.state_store import StateStore
from features import entropy, periodicity, fanout, fingerprint


ZEEK_LOG_TYPES = ["conn", "dns", "ssl", "ssh", "http", "notice", "software"]
CONNECTION_LOG_TYPES = {"conn", "flow"}  # one record per actual connection/flow


# ---------------------------------------------------------------------
# Normalization: Zeek's and Suricata's schemas -> one common event shape
# ---------------------------------------------------------------------

def normalize_zeek(log_type: str, raw: dict) -> dict:
    return {
        "source": "zeek",
        "log_type": log_type,
        "ts": float(raw.get("ts", time.time())),
        "uid": raw.get("uid"),
        "src_ip": raw.get("id.orig_h"),
        "src_port": raw.get("id.orig_p"),
        "dst_ip": raw.get("id.resp_h"),
        "dst_port": raw.get("id.resp_p"),
        "proto": raw.get("proto"),
        "orig_bytes": raw.get("orig_bytes"),
        "resp_bytes": raw.get("resp_bytes"),
        "duration": raw.get("duration"),
        "conn_state": raw.get("conn_state"),
        "query": raw.get("query"),        # populated on dns.log rows
        "qtype": raw.get("qtype_name"),   # populated on dns.log rows
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
    ja3 = (tls.get("ja3") or {}).get("hash")

    return {
        "source": "suricata",
        "log_type": event_type,
        "ts": _parse_suricata_ts(raw.get("timestamp")),
        "uid": raw.get("flow_id"),
        "src_ip": raw.get("src_ip"),
        "src_port": raw.get("src_port"),
        "dst_ip": raw.get("dest_ip"),
        "dst_port": raw.get("dest_port"),
        "proto": raw.get("proto"),
        "orig_bytes": flow.get("bytes_toserver"),
        "resp_bytes": flow.get("bytes_toclient"),
        "duration": None,
        "conn_state": flow.get("state"),
        "query": dns.get("rrname"),
        "qtype": dns.get("rrtype"),
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


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Cherenkov event processor")
    parser.add_argument("--zeek-dir", default="data/sample_logs/portscan/zeek", help="directory containing Zeek's *.log files")
    parser.add_argument("--eve-json", default="data/sample_logs/portscan/suricata/eve.json", help="path to Suricata's eve.json")
    parser.add_argument("--redis-host", default="localhost")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--ja3-blacklist", default="data/ja3_blacklist/blacklist.csv")
    parser.add_argument("--no-from-start", action="store_true",
                         help="skip existing log content, only process new lines")
    args = parser.parse_args()
    from_start = not args.no_from_start

    r = redis.Redis(host=args.redis_host, port=args.redis_port, decode_responses=True)
    try:
        r.ping()
    except redis.exceptions.ConnectionError as e:
        print(f"cannot reach Redis at {args.redis_host}:{args.redis_port} -- "
              f"is `docker-compose up -d` running? ({e})")
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
            dispatch(store, blacklist, event)
            processed += 1
            if processed % 50 == 0:
                print(f"processed {processed} events")
    except KeyboardInterrupt:
        print(f"\nstopping -- processed {processed} events total")
        stop_event.set()


if __name__ == "__main__":
    main()
