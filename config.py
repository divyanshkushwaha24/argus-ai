"""
Argus AI — Central configuration.

All tunables (thresholds, weights, network definitions) live here so they
are easy to find, audit, and change without touching detector logic.
"""

import os
from ipaddress import ip_network

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Network topology ──────────────────────────────────────────────────
# Which subnets are "internal".  Needed by the exfiltration detector to
# know the direction of traffic.  Add/remove as needed for your site.
INTERNAL_SUBNETS = [
    ip_network("192.168.50.0/24"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
]

# ── Detector thresholds ───────────────────────────────────────────────

# DDoS — rolling z-score
DDOS_ZSCORE_THRESHOLD     = 3.0     # flag when z > 3
DDOS_SRC_ENTROPY_HIGH     = 3.0     # many spoofed sources
DDOS_FLOW_RATE_WINDOW     = 60      # seconds of history for rolling stats

# C2 beaconing — inter-arrival regularity
BEACON_CV_THRESHOLD       = 0.30    # CV < 0.30 → metronome-like
BEACON_MIN_FLOWS          = 5       # need at least N flows to judge
BEACON_AUTOCORR_THRESHOLD = 0.7     # autocorrelation peak strength

# Port scan — fan-out
SCAN_FANOUT_THRESHOLD     = 20      # unique dst ports in a window
SCAN_WINDOW_SEC           = 10      # time window for fan-out count
SCAN_FANOUT_NORMALIZE     = 100.0   # confidence = min(1, fanout / this)

# Exfiltration — byte ratio
EXFIL_RATIO_THRESHOLD     = 10.0    # upload / download ratio
EXFIL_MIN_OUTBOUND_BYTES  = 100_000 # 100 KB minimum
EXFIL_ZSCORE_THRESHOLD    = 3.0

# DGA / DNS tunnelling — ML model features
DGA_ENTROPY_BENIGN_MAX    = 3.0     # typical benign domain entropy ceiling

# TLS malware — JA3 blocklist
TLS_BLOCKLIST_CONFIDENCE  = 0.95    # confidence if JA3 is on blocklist

# ── Risk fusion weights ──────────────────────────────────────────────
# P = detector confidence, A = anomaly score, S = severity prior, R = recency
FUSION_WEIGHT_P = 0.50
FUSION_WEIGHT_A = 0.20
FUSION_WEIGHT_S = 0.20
FUSION_WEIGHT_R = 0.10

# Severity priors per threat class (domain-expert judgement)
SEVERITY_PRIORS = {
    "ddos":        0.80,
    "beacon":      0.90,
    "dns_tunnel":  0.70,
    "ja3_malware": 0.85,
    "portscan":    0.50,
    "exfil":       0.95,
}

# Risk level thresholds
RISK_LEVELS = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (40, "MEDIUM"),
    (0,  "LOW"),
]

# ── Z-score → confidence mapping ─────────────────────────────────────
# Linear: confidence = min(1.0, z / Z_CONFIDENCE_CEILING)
# Rationale: z=6 maps to confidence=1.0.  A z=3 (our threshold) becomes
# 0.5, which makes intuitive sense — "something is happening but we're
# not fully certain yet".  See docs/model_notes.md for discussion.
Z_CONFIDENCE_CEILING = 6.0

# ── Incident correlation ─────────────────────────────────────────────
INCIDENT_GAP_MINUTES = 10  # merge alerts from same host within this gap

# ── Recency decay ────────────────────────────────────────────────────
RECENCY_HALF_LIFE_MINUTES = 30  # exp(-age / half_life)

# ── Infrastructure ───────────────────────────────────────────────────
POSTGRES_DSN = os.getenv("POSTGRES_DSN")
REDIS_URL    = "redis://localhost:6379/0"

# ── Paths ─────────────────────────────────────────────────────────────
MODEL_SAVE_DIR = "models/saved"
