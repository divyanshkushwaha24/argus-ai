#!/usr/bin/env python3
"""
Cherenkov -- synthetic traffic generator using Scapy.

Covers all six threats from the tech-stack doc's section 4, plus a benign
control. Each generator produces one labeled pcap with a clean, known
ground truth -- useful for validating detector logic before real labeled
datasets (CICIDS2017/2018, CTU-13) are wired in.

Threat -> generator mapping (matches models/ file names):
    ddos_detector.py       <- gen_ddos            -> ddos.pcap
    beacon_detector.py     <- gen_beacon           -> beacon.pcap
    dga_model.py            <- gen_dns_tunnel       -> dns_tunnel.pcap
    tls_malware_model.py    <- gen_ja3_malware      -> ja3_malware.pcap
    scan_detector.py        <- gen_portscan         -> portscan.pcap
    exfil_detector.py       <- gen_exfil            -> exfil.pcap
    (control)                gen_benign            -> benign.pcap

Usage:
    python3 ingest/generate_synthetic.py all
    python3 ingest/generate_synthetic.py ddos beacon dns_tunnel
"""

import os
import random
import string
import struct
import sys
import time

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"
SRC_IP = "192.168.50.10"

OUT_DIR = "data/synthetic"


def _frame(src_mac, dst_mac, ip_layer, l4_layer):
    return Ether(src=src_mac, dst=dst_mac) / ip_layer / l4_layer


def _rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _random_label(length):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


# ---------------------------------------------------------------------
# Control: benign traffic
# ---------------------------------------------------------------------

def gen_benign(n=40):
    """A handful of normal-looking short TCP conversations to a few hosts --
    the negative-class control. Detectors should stay quiet here."""
    packets = []
    hosts = ["93.184.216.34", "142.250.72.14", "151.101.1.140"]
    t = time.time()
    for _ in range(n):
        dst = random.choice(hosts)
        sport = random.randint(40000, 60000)
        syn = _frame(SRC_MAC, DST_MAC, IP(src=SRC_IP, dst=dst),
                     TCP(sport=sport, dport=443, flags="S", seq=1000))
        syn.time = t
        synack = _frame(DST_MAC, SRC_MAC, IP(src=dst, dst=SRC_IP),
                         TCP(sport=443, dport=sport, flags="SA", seq=2000, ack=1001))
        synack.time = t + 0.02
        ack = _frame(SRC_MAC, DST_MAC, IP(src=SRC_IP, dst=dst),
                      TCP(sport=sport, dport=443, flags="A", seq=1001, ack=2001))
        ack.time = t + 0.03
        packets += [syn, synack, ack]
        t += random.uniform(0.5, 3.0)
    return packets


# ---------------------------------------------------------------------
# Threat 1: Volumetric / protocol DDoS
# Signal: flow rate, source-IP entropy -> rolling z-score
# ---------------------------------------------------------------------

def gen_ddos(target="192.168.50.30", n=1000):
    """High-rate SYN flood from many distinct (spoofed) source IPs hitting
    one destination -- flow-rate spike + high source-IP entropy, exactly
    the two signals the rolling z-score detector keys off."""
    packets = []
    t = time.time()
    for _ in range(n):
        spoofed_src = _rand_ip()
        sport = random.randint(1024, 65535)
        pkt = _frame(SRC_MAC, DST_MAC, IP(src=spoofed_src, dst=target),
                     TCP(sport=sport, dport=80, flags="S", seq=random.randint(0, 2**32 - 1)))
        pkt.time = t
        packets.append(pkt)
        t += 0.001  # ~1000 pkts/sec, tight burst
    return packets


# ---------------------------------------------------------------------
# Threat 2: Botnet C2 beaconing
# Signal: inter-arrival regularity, few destinations -> autocorrelation/FFT
# ---------------------------------------------------------------------

def gen_beacon(target="203.0.113.77", n=30, interval=5.0, jitter=0.3):
    """Small, near-perfectly periodic connections to one destination -- the
    timing regularity an autocorrelation/FFT-based beacon detector looks for."""
    packets = []
    t = time.time()
    for _ in range(n):
        sport = random.randint(40000, 60000)
        syn = _frame(SRC_MAC, DST_MAC, IP(src=SRC_IP, dst=target),
                     TCP(sport=sport, dport=443, flags="S", seq=1000))
        syn.time = t
        packets.append(syn)
        t += interval + random.uniform(-jitter, jitter)
    return packets


# ---------------------------------------------------------------------
# Threat 3: DGA / DNS tunneling
# Signal: domain entropy, n-gram, query length/type -> RandomForest/XGBoost
# ---------------------------------------------------------------------

def gen_dns_tunnel(n=60, domain="update-cache.net"):
    """High-entropy, unusually long subdomain queries over TXT records --
    the classic DGA / DNS-tunneling signature dns.log exposes."""
    packets = []
    t = time.time()
    for _ in range(n):
        label = _random_label(random.randint(30, 55))
        qname = f"{label}.{domain}"
        sport = random.randint(40000, 60000)
        pkt = _frame(SRC_MAC, DST_MAC, IP(src=SRC_IP, dst="8.8.8.8"),
                     UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT")))
        pkt.time = t
        packets.append(pkt)
        t += random.uniform(0.05, 0.3)
    return packets


# ---------------------------------------------------------------------
# Threat 4: Encrypted-session malware
# Signal: JA3/JA3S/JA4, packet size/timing -> blocklist + classifier
# ---------------------------------------------------------------------

def _build_client_hello(sni, ciphers=None):
    """Hand-builds a minimal, valid TLS 1.2 ClientHello record as raw bytes
    (no scapy.layers.tls dependency -- keeps this script's only dependency
    as plain scapy). This is NOT a copy of any specific real malware
    family's exact fingerprint -- fabricating one from memory would be
    unreliable. It's a deliberately narrow, non-browser-like cipher/
    extension set. Suricata computes the real JA3 hash for whatever
    ClientHello it actually sees; the testing guide below shows how to
    read that computed hash back out and use it to prove your blocklist
    matching logic, rather than trying to guess a hash in advance."""
    if ciphers is None:
        ciphers = [0xc02b, 0xc02f, 0xc02c, 0xc030, 0x009e, 0x009f]

    client_version = b"\x03\x03"
    random_bytes = bytes(random.getrandbits(8) for _ in range(32))
    session_id = b"\x00"

    cipher_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
    cipher_suites = struct.pack(">H", len(cipher_bytes)) + cipher_bytes
    compression = b"\x01\x00"

    extensions = b""
    sni_bytes = sni.encode()
    server_name_list = struct.pack(">B", 0) + struct.pack(">H", len(sni_bytes)) + sni_bytes
    server_name_ext_body = struct.pack(">H", len(server_name_list)) + server_name_list
    extensions += struct.pack(">HH", 0x0000, len(server_name_ext_body)) + server_name_ext_body

    groups = [0x001d, 0x0017, 0x0018]
    groups_bytes = b"".join(struct.pack(">H", g) for g in groups)
    groups_ext_body = struct.pack(">H", len(groups_bytes)) + groups_bytes
    extensions += struct.pack(">HH", 0x000a, len(groups_ext_body)) + groups_ext_body

    formats_bytes = bytes([0x00])
    formats_ext_body = struct.pack(">B", len(formats_bytes)) + formats_bytes
    extensions += struct.pack(">HH", 0x000b, len(formats_ext_body)) + formats_ext_body

    ext_block = struct.pack(">H", len(extensions)) + extensions
    body = client_version + random_bytes + session_id + cipher_suites + compression + ext_block
    handshake = struct.pack(">B", 0x01) + struct.pack(">I", len(body))[1:] + body
    record_header = struct.pack(">B", 0x16) + struct.pack(">H", 0x0301) + struct.pack(">H", len(handshake))
    return record_header + handshake


def gen_ja3_malware(target="203.0.113.55", n=5):
    """A handful of TLS sessions using the narrow ClientHello above --
    fingerprint-based malware signal, distinct from the DDoS/scan/exfil
    threats which never rely on TLS content."""
    packets = []
    t = time.time()
    for i in range(n):
        sport = random.randint(40000, 60000)
        seq = 1000
        syn = _frame(SRC_MAC, DST_MAC, IP(src=SRC_IP, dst=target),
                     TCP(sport=sport, dport=443, flags="S", seq=seq))
        syn.time = t; packets.append(syn); t += 0.01
        synack = _frame(DST_MAC, SRC_MAC, IP(src=target, dst=SRC_IP),
                         TCP(sport=443, dport=sport, flags="SA", seq=5000, ack=seq + 1))
        synack.time = t; packets.append(synack); t += 0.01
        client_hello = _build_client_hello(sni=f"c2-node-{i}.badstuff.example")
        hello_pkt = _frame(SRC_MAC, DST_MAC, IP(src=SRC_IP, dst=target),
                            TCP(sport=sport, dport=443, flags="PA", seq=seq + 1, ack=5001) / Raw(load=client_hello))
        hello_pkt.time = t; packets.append(hello_pkt); t += 0.5
    return packets


# ---------------------------------------------------------------------
# Threat 5: Recon / port scanning
# Signal: fan-out across ports/hosts -> threshold / fan-out count
# ---------------------------------------------------------------------

def gen_portscan(target="192.168.50.20", n_ports=200):
    """A fast SYN scan across many destination ports on one host -- one
    source, one destination, many ports, tight timing: the fan-out
    signature a threshold-based scan detector counts."""
    packets = []
    t = time.time()
    ports = random.sample(range(1, 65535), n_ports)
    for p in ports:
        sport = random.randint(40000, 60000)
        pkt = _frame(SRC_MAC, DST_MAC, IP(src=SRC_IP, dst=target),
                     TCP(sport=sport, dport=p, flags="S", seq=1000))
        pkt.time = t
        packets.append(pkt)
        t += 0.01
    return packets


# ---------------------------------------------------------------------
# Threat 6: Data exfiltration
# Signal: outbound:inbound byte ratio -> rolling z-score
# ---------------------------------------------------------------------

def gen_exfil(target="203.0.113.99", total_bytes=2_000_000, chunk_size=1400):
    """One connection, one direction: a large outbound transfer with a
    near-empty inbound response -- the skewed outbound:inbound byte ratio
    the exfiltration detector watches for."""
    packets = []
    t = time.time()
    sport = random.randint(40000, 60000)
    seq = 1000

    syn = _frame(SRC_MAC, DST_MAC, IP(src=SRC_IP, dst=target),
                 TCP(sport=sport, dport=443, flags="S", seq=seq))
    syn.time = t; packets.append(syn); t += 0.01
    synack = _frame(DST_MAC, SRC_MAC, IP(src=target, dst=SRC_IP),
                     TCP(sport=443, dport=sport, flags="SA", seq=5000, ack=seq + 1))
    synack.time = t; packets.append(synack); t += 0.01
    seq += 1

    sent = 0
    payload = b"X" * chunk_size
    while sent < total_bytes:
        pkt = _frame(SRC_MAC, DST_MAC, IP(src=SRC_IP, dst=target),
                     TCP(sport=sport, dport=443, flags="PA", seq=seq, ack=5001) / Raw(load=payload))
        pkt.time = t
        packets.append(pkt)
        seq += chunk_size
        sent += chunk_size
        t += 0.005

    finalack = _frame(DST_MAC, SRC_MAC, IP(src=target, dst=SRC_IP),
                       TCP(sport=443, dport=sport, flags="A", seq=5001, ack=seq))
    finalack.time = t
    packets.append(finalack)
    return packets


GENERATORS = {
    "benign": gen_benign,
    "ddos": gen_ddos,
    "beacon": gen_beacon,
    "dns_tunnel": gen_dns_tunnel,
    "ja3_malware": gen_ja3_malware,
    "portscan": gen_portscan,
    "exfil": gen_exfil,
}


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    targets = sys.argv[1:] or ["all"]
    names = GENERATORS.keys() if "all" in targets else targets
    for name in names:
        if name not in GENERATORS:
            print(f"unknown generator: {name} (choices: {list(GENERATORS)})")
            continue
        packets = GENERATORS[name]()
        packets.sort(key=lambda p: p.time)
        outfile = f"{OUT_DIR}/{name}.pcap"
        wrpcap(outfile, packets)
        print(f"wrote {len(packets)} packets -> {outfile}")


if __name__ == "__main__":
    main()
