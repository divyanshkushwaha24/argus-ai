#!/usr/bin/env python3
"""
Argus AI — Fresh Synthetic Dataset Generator.

Generates:
1. Fresh synthetic PCAP packet captures via ingest/generate_synthetic.py
2. Fresh flow telemetry dataset with dynamic, randomized parameters:
   - Dynamic attacker and victim IP addresses
   - Dynamic DDoS flow rate z-scores and source-IP entropies
   - Dynamic beacon inter-arrival intervals and jitter
   - Dynamic DGA subdomains with variable entropy, length, and n-grams
   - Dynamic port scan fanouts and destination port ranges
   - Dynamic data exfiltration byte volumes and upload/download ratios
   - Current UTC timestamps

This ensures that every pipeline execution produces fresh, distinct detections,
threat scores, SHAP explanations, and incident correlations on the dashboard.

Usage:
    python3 ingest/generate_fresh_dataset.py
    python3 ingest/generate_fresh_dataset.py --output data/synthetic/fresh_flows.csv
"""

from __future__ import annotations

import argparse
import math
import os
import random
import string
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd

# Add repo root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _calc_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


def _rand_ipv4() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _random_domain_label(length: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def generate_fresh_dataset(output_path: str = "data/synthetic/fresh_flows.csv") -> pd.DataFrame:
    """Generate fresh synthetic network flow telemetry."""
    now_epoch = time.time()
    now_iso = datetime.now(timezone.utc).isoformat()

    rows: List[Dict[str, Any]] = []

    # Attacker and victim profiles for this run
    victim_ip = f"192.168.50.{random.randint(20, 99)}"
    beacon_c2_ip = f"203.0.113.{random.randint(50, 90)}"
    exfil_dest_ip = f"198.51.100.{random.randint(10, 80)}"
    scanner_ip = f"192.168.50.{random.randint(10, 19)}"
    dns_server_ip = "8.8.8.8"

    # Base template with all required columns initialized to safe defaults
    def make_base_flow(label: str, src_ip: str, dest_ip: str, dest_port: int, proto: str = "TCP") -> Dict[str, Any]:
        return {
            "label": label,
            "timestamp": now_iso,
            "timestamp_epoch": now_epoch,
            "flow_id": random.randint(100_000_000_000_000, 999_000_000_000_000),
            "src_ip": src_ip,
            "src_port": random.randint(1024, 65535),
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": proto,
            "app_proto": np.nan,
            "flow_state": "new",
            "packets_to_server": 1,
            "packets_to_client": 0,
            "bytes_to_server": 54,
            "bytes_to_client": 0,
            "total_packets": 1,
            "total_bytes": 54,
            "flow_duration": 0.0,
            "packet_rate": 0.0,
            "byte_rate": 0.0,
            "average_packet_size": 54.0,
            "upload_download_ratio": 54.0,
            "dns_event_count": 0,
            "dns_record_type": np.nan,
            "dns_type": np.nan,
            "dns_rcode": np.nan,
            "dns_unique_domain_count_per_flow": 0,
            "dns_max_query_length_per_flow": 0,
            "tls_event_count": 0,
            "sni": np.nan,
            "tls_version": np.nan,
            "ja3_hash": np.nan,
            "ja3_string": np.nan,
            "ja3s_hash": np.nan,
            "ja3s_string": np.nan,
            "ja4": np.nan,
            "tls_subject": np.nan,
            "tls_issuer": np.nan,
            "quic_event_count": 0,
            "quic_version": np.nan,
            "quic_sni": np.nan,
            "quic_ja3": np.nan,
            "quic_ja3s": np.nan,
            "source_flow_count": 1,
            "unique_destination_ips": 1,
            "unique_destination_ports": 1,
            "dns_query_count_by_source": 0,
            "unique_dns_domains_by_source": 0,
            "repeated_dns_queries": 0,
            "destination_fanout": 1,
            "source_ip_count_in_file": 1,
            "source_ip_entropy_in_file": 0.0,
            "src_interarrival_sec": 0.0,
            "dns_query": np.nan,
            "dns_query_length": 0,
            "dns_entropy": 0.0,
            "dns_digit_count": 0,
            "dns_letter_count": 0,
            "dns_hyphen_count": 0,
            "dns_dot_count": 0,
            "dns_digit_ratio": 0.0,
            "dns_label_count": 0,
            "dns_longest_label": 0,
            "dns_bigram_count": 0,
            "dns_unique_bigram_count": 0,
            "dns_trigram_count": 0,
            "dns_unique_trigram_count": 0,
        }

    # 1. DDoS Floods: 150-250 flows from spoofed IPs hitting victim_ip
    n_ddos = random.randint(120, 220)
    spoofed_ips = [_rand_ipv4() for _ in range(n_ddos)]
    ddos_entropy = _calc_entropy(spoofed_ips)

    for s_ip in spoofed_ips:
        f = make_base_flow("ddos", s_ip, victim_ip, 80, proto="TCP")
        f["source_ip_count_in_file"] = n_ddos
        f["source_ip_entropy_in_file"] = ddos_entropy
        f["packet_rate"] = random.uniform(800.0, 1500.0)
        f["source_flow_count"] = random.randint(1, 3)
        f["bytes_to_server"] = random.randint(40, 74)
        f["total_bytes"] = f["bytes_to_server"]
        rows.append(f)

    # 2. Beaconing: 25-45 periodic flows with low CV jitter
    n_beacon = random.randint(25, 45)
    beacon_mean_interval = random.uniform(3.0, 8.0)
    beacon_jitter_std = random.uniform(0.05, 0.20)
    t_curr = now_epoch
    for _ in range(n_beacon):
        dt = max(0.001, random.gauss(beacon_mean_interval, beacon_jitter_std))
        t_curr += dt
        f = make_base_flow("beacon", scanner_ip, beacon_c2_ip, 443, proto="TCP")
        f["timestamp_epoch"] = t_curr
        f["timestamp"] = datetime.fromtimestamp(t_curr, tz=timezone.utc).isoformat()
        f["src_interarrival_sec"] = dt
        f["flow_duration"] = random.uniform(0.02, 0.08)
        f["packets_to_server"] = random.randint(2, 5)
        f["bytes_to_server"] = random.randint(120, 350)
        f["total_packets"] = f["packets_to_server"] + 1
        f["total_bytes"] = f["bytes_to_server"] + 64
        f["source_flow_count"] = n_beacon
        rows.append(f)

    # 3. DGA / DNS Tunneling: 15-30 high-entropy suspicious DNS queries
    n_dns = random.randint(15, 30)
    tunnel_domains = ["sec-cloud.net", "data-cache.org", "cdn-update.info", "edge-telemetry.io"]
    domain_suffix = random.choice(tunnel_domains)
    for _ in range(n_dns):
        sub_len = random.randint(28, 52)
        sub = _random_domain_label(sub_len)
        query = f"{sub}.{domain_suffix}"
        f = make_base_flow("dns_tunnel", scanner_ip, dns_server_ip, 53, proto="UDP")
        f["dns_event_count"] = 1
        f["dns_query"] = query
        f["dns_query_length"] = len(query)
        f["dns_entropy"] = _calc_entropy(sub)
        f["dns_digit_count"] = sum(c.isdigit() for c in query)
        f["dns_letter_count"] = sum(c.isalpha() for c in query)
        f["dns_hyphen_count"] = query.count("-")
        f["dns_dot_count"] = query.count(".")
        f["dns_digit_ratio"] = f["dns_digit_count"] / max(1, len(query))
        f["dns_label_count"] = len(query.split("."))
        f["dns_longest_label"] = sub_len
        f["dns_unique_domain_count_per_flow"] = 1
        f["dns_max_query_length_per_flow"] = len(query)
        f["bytes_to_server"] = random.randint(70, 180)
        f["total_bytes"] = f["bytes_to_server"]
        rows.append(f)

    # 4. Recon / Port Scan: 35-65 unique destination ports scanned on victim
    n_scan = random.randint(35, 65)
    scanned_ports = random.sample(range(20, 60000), n_scan)
    for i, port in enumerate(scanned_ports):
        f = make_base_flow("portscan", scanner_ip, victim_ip, port, proto="TCP")
        f["destination_fanout"] = n_scan
        f["unique_destination_ports"] = n_scan
        f["unique_destination_ips"] = 1
        f["source_flow_count"] = n_scan
        f["src_interarrival_sec"] = random.uniform(0.0001, 0.005)
        rows.append(f)

    # 5. Data Exfiltration: large outbound payload, negligible inbound
    n_exfil = random.randint(2, 5)
    for _ in range(n_exfil):
        bytes_out = random.randint(250_000, 2_500_000)
        bytes_in = random.randint(40, 200)
        f = make_base_flow("exfil", scanner_ip, exfil_dest_ip, 443, proto="TCP")
        f["bytes_to_server"] = bytes_out
        f["bytes_to_client"] = bytes_in
        f["total_bytes"] = bytes_out + bytes_in
        f["packets_to_server"] = bytes_out // 1400 + 1
        f["packets_to_client"] = 3
        f["total_packets"] = f["packets_to_server"] + f["packets_to_client"]
        f["upload_download_ratio"] = float(bytes_out) / max(1.0, float(bytes_in))
        f["flow_duration"] = random.uniform(1.2, 5.0)
        f["byte_rate"] = float(f["total_bytes"]) / max(0.1, f["flow_duration"])
        f["packet_rate"] = float(f["total_packets"]) / max(0.1, f["flow_duration"])
        f["average_packet_size"] = float(f["total_bytes"]) / max(1, f["total_packets"])
        rows.append(f)

    # 6. TLS Malware / Suspicious Encrypted Sessions
    n_tls = random.randint(2, 6)
    for i in range(n_tls):
        f = make_base_flow("ja3_malware", scanner_ip, beacon_c2_ip, 443, proto="TCP")
        f["tls_event_count"] = 1
        f["sni"] = f"node-{random.randint(100, 999)}.telemetry-c2.net"
        f["tls_version"] = "TLS 1.2"
        f["bytes_to_server"] = random.randint(600, 1800)
        f["bytes_to_client"] = random.randint(400, 1200)
        f["total_bytes"] = f["bytes_to_server"] + f["bytes_to_client"]
        f["packets_to_server"] = random.randint(8, 20)
        f["packets_to_client"] = random.randint(6, 15)
        f["total_packets"] = f["packets_to_server"] + f["packets_to_client"]
        f["flow_duration"] = random.uniform(0.1, 0.6)
        f["upload_download_ratio"] = float(f["bytes_to_server"]) / max(1.0, float(f["bytes_to_client"]))
        f["average_packet_size"] = float(f["total_bytes"]) / max(1, f["total_packets"])
        rows.append(f)

    # 7. Benign Control Traffic: 10-20 normal web and DNS queries
    n_benign = random.randint(10, 20)
    benign_hosts = ["93.184.216.34", "142.250.72.14", "151.101.1.140", "1.1.1.1"]
    for _ in range(n_benign):
        target = random.choice(benign_hosts)
        f = make_base_flow("benign", f"192.168.50.{random.randint(100, 200)}", target, 443, proto="TCP")
        f["bytes_to_server"] = random.randint(300, 1500)
        f["bytes_to_client"] = random.randint(1000, 8000)
        f["total_bytes"] = f["bytes_to_server"] + f["bytes_to_client"]
        f["packets_to_server"] = random.randint(4, 10)
        f["packets_to_client"] = random.randint(6, 18)
        f["total_packets"] = f["packets_to_server"] + f["packets_to_client"]
        f["upload_download_ratio"] = float(f["bytes_to_server"]) / max(1.0, float(f["bytes_to_client"]))
        f["flow_duration"] = random.uniform(0.05, 0.4)
        rows.append(f)

    # Convert to DataFrame
    df = pd.DataFrame(rows)
    # Shuffle flows so arrivals interleave naturally
    df = df.sample(frac=1.0, random_state=random.randint(1, 10000)).reset_index(drop=True)

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_file, index=False)
    print(f"Generated {len(df)} fresh flow records -> {output_path}")
    print(f"Flow breakdown by label:\n{df['label'].value_counts().to_string()}")
    return df


def main():
    parser = argparse.ArgumentParser(description="Argus AI - Fresh Synthetic Data & PCAP Generator")
    parser.add_argument("--output", default="data/synthetic/fresh_flows.csv", help="Target CSV file path")
    parser.add_argument("--skip-pcap", action="store_true", help="Skip PCAP regeneration")
    args = parser.parse_args()

    # Step 1: Generate fresh PCAPs
    if not args.skip_pcap:
        gen_script = ROOT / "ingest" / "generate_synthetic.py"
        if gen_script.exists():
            print("Regenerating all synthetic PCAPs...")
            subprocess.run([sys.executable, str(gen_script), "all"], check=True)

    # Step 2: Generate fresh flow dataset CSV
    print(f"\nGenerating fresh flow records...")
    generate_fresh_dataset(args.output)
    print("\nFresh synthetic data generation complete!")


if __name__ == "__main__":
    main()

