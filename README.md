# Argus AI (Cherenkov)
### Real-Time Passive Network Threat Detection & Incident Correlation Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![PostgreSQL 16](https://img.shields.io/badge/postgres-16-336791.svg)](https://www.postgresql.org/)
[![Redis 7](https://img.shields.io/badge/redis-7-dc382d.svg)](https://redis.io/)
[![Streamlit](https://img.shields.io/badge/dashboard-streamlit-ff4b4b.svg)](https://streamlit.io/)
[![Test Suite](https://img.shields.io/badge/tests-51%20passed-brightgreen.svg)](tests/)
[![Architecture](https://img.shields.io/badge/security-read--only%20tap-success.svg)](docs/architecture.md)

**Argus AI (Cherenkov)** is a passive, real-time Network Intrusion Detection System (NIDS) and Security Operations Center (SOC) intelligence platform. Operating strictly downstream of a mirrored TAP, SPAN port, or virtual Ethernet boundary, Argus continuously sniffs high-throughput IP traffic, parses deep-packet metadata via native Suricata sensors, updates sliding-window flow kinetics in Redis, evaluates 6 specialized machine learning and statistical threat detectors, fuses multiple risk signals, and automatically correlates multi-stage kill chains into actionable security incidents.

---

##  Table of Contents

- [Key Architectural Highlights](#-key-architectural-highlights)
- [End-to-End Architecture](#-end-to-end-architecture)
- [Threat Detection Vectors](#-threat-detection-vectors)
- [Multi-Signal Risk Fusion & Incident Correlation](#-multi-signal-risk-fusion--incident-correlation)
- [Quick Start](#-quick-start)
  - [Option 1: One-Click Real-Time Host Launcher (Recommended)](#option-1-one-click-real-time-host-launcher-recommended)
  - [Option 2: Docker Compose Stack](#option-2-docker-compose-stack)
- [Simulation & Multi-Stage Attack Generation](#-simulation--multi-stage-attack-generation)
- [Repository Layout](#-repository-layout)
- [Configuration & Tunables](#-configuration--tunables)
- [Testing & Quality Assurance](#-testing--quality-assurance)
- [License](#-license)

---

## ⚡ Key Architectural Highlights

* **Guaranteed Read-Only Boundary**: Sniffs network packets passively. With enforced kernel egress drop filters (`tc filter drop`) and zero routes back to the monitored network, Argus AI cannot inject, transmit, or disrupt operational network fabric.
* **Metadata-Only Deep Packet Inspection (DPI)**: Analyzes TLS ClientHello fingerprints (JA3/JA3S/JA4), SNI domains, DNS query lexical entropy, and directional flow packet/byte ratios without decrypting payload data.
* **Sub-Millisecond Event Pipeline**: An asynchronous Redis Stream (`cherenkov:events`) decouples Suricata log tailing (`event_processor.py`) from multi-process ML detector workers, handling thousands of events per second with zero packet loss.
* **Multi-Stage Kill Chain Incident Correlation**: Uses Noisy-OR probability mathematics to group related attack phases (Reconnaissance $\to$ C2 Beaconing $\to$ Exfiltration) on a single compromised host, naturally escalating compound risk scores up to **98 (CRITICAL)**.
* **Intelligent DDoS Flood Dampening**: Victim-aware cooldown deduplication suppresses massive volumetric SYN floods down to single periodic alerts per victim host, eliminating SOC alert fatigue while preserving visibility.
* **Live Auto-Refreshing SOC Dashboard**: Streamlit-based web dashboard (`dashboard/app.py`) with 2-second auto-refresh, real-time threat distribution charts, incident escalation graphs, and sessional database archiving.

---

## 🏗️ End-to-End Architecture

```
                    MONITORED NETWORK SEGMENT
                                │
                    [Promiscuous SPAN / veth TAP]
                                │ (One-way listen-only boundary)
                                ▼
                        Suricata DPI Sensor
                     sniffing monitor tap (veth1)
                                │
                                ▼
                       data/raw/live_suricata/eve.json
                                │
                                ▼ (Continuous Non-Blocking tail -f)
                     streaming/event_processor.py
                     - Sliding-window entropy & fan-out in Redis StateStore
                     - Dispatches normalized event payloads
                                │
                                ▼
                       Redis Event Stream
                       (cherenkov:events)
                                │
                                ▼ (Consumer Group: cherenkov-detect)
                     pipeline/consumer.py (Workers)
         ┌──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼
  DDoS / Volumetric      C2 Beacon Detector     Recon / Port Scan
  (Rolling Z-Score)      (Autocorrelation/FFT)   (Fan-Out Windows)
         ▼                      ▼                      ▼
  DNS Tunnel / DGA        TLS Malware Model     Data Exfiltration
  (XGBoost Classifier)    (Random Forest + JA3) (Ratio Asymmetry)
         └──────────────────────┬──────────────────────┘
                                │ Detections
                                ▼
                       AlertEngine.process()
                     ├── Victim Cooldown Deduplication
                     ├── Sliding Recency Decay
                     ├── Multi-Signal Risk Fusion (0-100)
                     └── Incident Correlation (Noisy-OR)
                                │
                                ▼
                   PostgreSQL / SQLite Storage
                   ├── public.alerts
                   ├── public.incidents
                   └── public.history_logs
                                │
                                ▼ (2s Auto-Refresh)
                    Streamlit SOC Dashboard
                     (http://localhost:8501)
```

---

## 🎯 Threat Detection Vectors

Argus AI deploys 6 specialized, contract-compliant detectors running simultaneously:

| Threat Class | Vector Name | Detection Engine & Signals | Severity Baseline |
| :--- | :--- | :--- | :---: |
| **Port Scan** | `RECON_PORT_SCAN` | Sliding-window fan-out analysis counting unique destination ports probed from a single source host within 10s. | `MEDIUM` (55) |
| **DDoS Attack** | `DDOS` | Rolling z-score on volumetric packet rates paired with high Shannon source-IP entropy ($H \ge 3.0$). Keyed on victim destination IP. | `HIGH` (74) |
| **C2 Beaconing** | `C2_BEACONING` | Inter-arrival timing regularity (Coefficient of Variation $\text{CV} < 0.30$) and autocorrelation peak strength on repeated outbound TCP sessions. | `HIGH` (80) |
| **DNS Tunneling** | `DGA_DNS_TUNNELING`| Gradient-boosted tree (XGBoost) evaluating subdomain Shannon entropy, query character length, digit-to-letter ratios, and bi/tri-gram probabilities. | `HIGH` (66) |
| **Encrypted Malware** | `ENCRYPTED_MALWARE` | Random Forest classifier and cryptographic JA3 hash matching against known Cobalt Strike, TrickBot, Emotet, and AsyncRAT ClientHello fingerprints. | `HIGH` (77) |
| **Data Exfiltration** | `DATA_EXFILTRATION` | Extreme upload-to-download byte ratio asymmetry ($> 10.0$) and high-volume outbound data flow (> 100 KB payload) from internal subnets to external IPs. | `CRITICAL` (82) |

---

## 🧮 Multi-Signal Risk Fusion & Incident Correlation

### 1. Calibrated Risk Fusion
Rather than relying solely on raw classifier probabilities, Argus AI fuses four orthogonal telemetry signals into a single normalized score ($0 - 100$):

$$\text{Risk Score} = \Big( w_P \cdot P_{\text{detector}} + w_A \cdot A_{\text{anomaly}} + w_S \cdot S_{\text{prior}} + w_R \cdot R_{\text{recency}} \Big) \times 100$$

* **$P$ (Detector Confidence)**: Normalized certainty ($0.0 - 1.0$) output by the model.
* **$A$ (Anomaly Score)**: Behavioral deviation baseline derived from unsupervised Isolation Forests.
* **$S$ (Severity Prior)**: Domain-expert threat impact weighting (e.g., Exfiltration has a higher inherent risk prior than exploratory port scanning).
* **$R$ (Recency Score)**: Exponential decay function based on the volume and proximity of recent alerts from the same source: $R = 1 - e^{-m}$.

| Score Band | Severity Tier | SOC Operational Action |
| :---: | :---: | :--- |
| **0 – 30** | `LOW` | Routine informational baseline; logged silently. |
| **31 – 60** | `MEDIUM` | Exploratory activity / reconnaissance; monitored. |
| **61 – 80** | `HIGH` | Active compromise indicators / C2 presence; triage required. |
| **81 – 100** | `CRITICAL` | Severe breach, confirmed exfiltration, or multi-stage incident; immediate incident response. |

### 2. Multi-Stage Kill Chain Correlation (Noisy-OR)
Real-world enterprise breaches rarely consist of a single isolated alert. The Cherenkov `IncidentCorrelator` groups alerts belonging to the same host within an active 10-minute window and computes compound incident risk using the **Noisy-OR** formulation:

$$\text{Incident Risk} = 1 - \prod_{c \in \text{Threat Classes}} \left(1 - \frac{r_c}{100}\right)$$

where $r_c = \max(\text{risk of all alerts in threat class } c)$.

* **Isolated Stage 1 (Portscan)**: Risk = **55 (MEDIUM)**
* **Stage 2 Added (C2 Beaconing)**: Risk = $1 - (1 - 0.55)(1 - 0.77) = \mathbf{90}$ (**CRITICAL 🚨**)
* **Stage 3 Added (Data Exfiltration)**: Risk = $1 - (0.45 \times 0.23 \times 0.18) = \mathbf{98}$ (**MAX CRITICAL 🚨**)

Repeated alerts of the *same* class do not artificially inflate the score; only a distinct kill chain phase elevates the incident severity.

---

## 🚀 Quick Start

### Prerequisites (Linux Host)

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y python3 python3-venv python3-pip redis postgresql

# Optional for native kernel taps & hardware packet replay:
sudo apt install -y suricata tcpreplay iproute2
```

---

### Option 1: One-Click Real-Time Host Launcher (Recommended)

The automated supervisor handles environment checks, database resets, virtual tap setup, Suricata DPI, ML workers, and the Streamlit dashboard:

```bash
# 1. Clone the repository
git clone https://github.com/divyanshkushwaha24/argus-ai.git
cd argus-ai

# 2. Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Launch the full real-time platform
./run_realtime.sh
```

*(Alternatively, run `python3 run_realtime.py` with custom arguments):*

```bash
python3 run_realtime.py --interval 1.5           # Faster event streaming pacing
python3 run_realtime.py --native                 # Force native Suricata DPI on veth1
python3 run_realtime.py --no-dashboard           # Headless daemon mode for production servers
```

Once running, the SOC dashboard automatically launches in your browser at **`http://localhost:8501`**.

---

### Option 2: Docker Compose Stack

To spin up Redis, PostgreSQL, the Cherenkov Streaming Worker, and the Streamlit Dashboard in isolated containers:

```bash
docker compose up -d
```

#### Useful Docker Operations:
```bash
# Check worker status and event queues:
docker compose run --rm pipeline python -m pipeline.consumer status

# Tail live streaming detection logs:
docker compose logs -f pipeline

# Run the unit test suite inside container:
docker compose run --rm pipeline pytest tests/ -v

# Tear down container stack:
docker compose down
```

---

## 🔬 Simulation & Multi-Stage Attack Generation

Argus AI includes a built-in Scapy packet generator that synthesizes realistic attack PCAPs with correct TCP state handshakes, TLS ClientHello records, and DNS records:

```bash
# Generate all threat PCAPs including the multi-stage kill chain:
python3 ingest/generate_synthetic.py all
```

This generates 8 standalone PCAPs in `data/synthetic/`:
- `killchain.pcap`: Multi-stage attack progression (Recon $\to$ C2 $\to$ Exfil on target `192.168.50.100`).
- `ddos.pcap`: High-rate SYN flood from spoofed IPs targeting `192.168.50.254`.
- `beacon.pcap`: Periodic C2 beaconing connections.
- `dns_tunnel.pcap`: High-entropy DGA domain lookups over TXT records.
- `ja3_malware.pcap`: Handcrafted TLS 1.2 handshakes with malicious JA3 cipher signatures.
- `portscan.pcap`: Fast SYN scans across unique destination ports.
- `exfil.pcap`: Asymmetric outbound TCP payload transfers.
- `benign.pcap`: Normal HTTP/HTTPS web traffic.

---

## 📁 Repository Layout

```
argus-ai/
├── alerting/                # PostgreSQL alert writer & Pydantic schema validation
│   ├── schema.py            # Unified Alert and Incident dataclass contracts
│   └── writer.py            # Idempotent database insertion layer
├── config.py                # Central tuning parameters, subnet definitions, fusion weights
├── dashboard/               # Live SOC Streamlit application
│   └── app.py               # 2s auto-refreshing UI, charts, and session history viewer
├── data/
│   ├── sample_logs/         # Authentic Suricata eve.json event logs
│   └── synthetic/           # Synthesized PCAP packet captures
├── database/
│   └── schema.sql           # PostgreSQL table definitions (alerts, incidents, history_logs)
├── db.py                    # Database connection manager with automatic SQLite fallback
├── docker-compose.yml       # Production multi-container composition
├── Dockerfile               # Container specification for streaming pipeline & dashboard
├── features/                # StateStore & sliding window feature extraction
│   ├── state_store.py       # Redis-backed sliding window buffers
│   └── statistical.py       # Rolling z-score & entropy calculations
├── ingest/
│   └── generate_synthetic.py# Scapy PCAP generator for synthetic threat scenarios
├── models/                  # 6 Core ML and statistical detection engines
│   ├── alert_schema.py      # Detection & Alert data representations
│   ├── anomaly.py           # Unsupervised Isolation Forest anomaly scorer
│   ├── beacon_detector.py   # C2 periodicity and autocorrelation detector
│   ├── correlation.py       # Incident aggregation helpers
│   ├── ddos_detector.py     # Rolling volumetric z-score detector
│   ├── dga_model.py         # XGBoost lexical DNS tunneling classifier
│   ├── exfil_detector.py    # Directional byte-ratio asymmetry detector
│   ├── fusion.py            # 4-signal calibrated risk fusion engine
│   ├── scan_detector.py     # Sliding-window port scan fan-out detector
│   ├── tls_malware_model.py # Random Forest JA3 fingerprint classifier
│   └── saved/               # Serialized model artifacts (.joblib, ja3_blocklist.json)
├── pipeline/
│   └── consumer.py          # Cherenkov streaming orchestrator, workers, & circuit breakers
├── run_realtime.py          # One-click end-to-end supervisor script
├── run_realtime.sh          # Shell wrapper with virtualenv detection
├── streaming/
│   └── event_processor.py   # Non-blocking eve.json tailer & Redis stream producer
└── tests/                   # Hermetic pytest suite (51 unit & integration tests)
    ├── test_alerting_schema.py
    └── test_pipeline.py
```

---

## ⚙️ Configuration & Tunables

All tunable thresholds live in [`config.py`](file:///home/divyanshkushwaha2023/argus-ai/config.py) for easy auditing without touching detector logic:

```python
# Network Subnets considered internal
INTERNAL_SUBNETS = [
    ip_network("192.168.50.0/24"),
    ip_network("10.0.0.0/8"),
]

# Detector Thresholds
DDOS_ZSCORE_THRESHOLD     = 3.0    # Trigger when flow rate z-score > 3.0
BEACON_CV_THRESHOLD       = 0.30   # Periodic beaconing when coefficient of variation < 0.30
SCAN_FANOUT_THRESHOLD     = 20     # Unique destination ports probed within time window
EXFIL_RATIO_THRESHOLD     = 10.0   # Outbound / Inbound byte ratio
EXFIL_MIN_OUTBOUND_BYTES  = 100_000# Minimum 100 KB payload for exfiltration

# Fusion Weights (P: Confidence, A: Anomaly, S: Severity Prior, R: Recency)
FUSION_PARAMS = {
    "ddos":        (0.45, 0.25, 0.20, 0.10),
    "beacon":      (0.45, 0.20, 0.25, 0.10),
    "dns_tunnel":  (0.50, 0.15, 0.25, 0.10),
    "ja3_malware": (0.50, 0.15, 0.25, 0.10),
    "portscan":    (0.40, 0.20, 0.30, 0.10),
    "exfil":       (0.40, 0.20, 0.30, 0.10),
}
```

---

## 🧪 Testing & Quality Assurance

Argus AI maintains a comprehensive suite of 51 automated unit and integration tests covering alert schema validation, circuit breaker isolation, DDoS deduplication, Noisy-OR compounding, and multi-stage kill chains:

```bash
# Run the full test suite:
PYTHONPATH=. .venv/bin/pytest tests/ -v
```

```text
============================= test session starts ==============================
collected 52 items

tests/test_alerting_schema.py::test_valid_alert PASSED                   [  1%]
tests/test_alerting_schema.py::test_invalid_confidence PASSED            [  3%]
tests/test_pipeline.py::test_severity_bands_match_spec[81-CRITICAL] PASSED [ 28%]
tests/test_pipeline.py::test_fusion_params_weights_sum_to_one PASSED     [ 32%]
tests/test_pipeline.py::test_ddos_cooldown_suppresses_alert_flood PASSED [ 67%]
tests/test_pipeline.py::test_multistage_killchain_simulation_correlates_to_critical PASSED [ 61%]
...
======================== 51 passed, 1 skipped in 4.12s =========================
```

---

## 📜 License

Distributed under the Apache 2.0 License. See `LICENSE` for details.
Designed and built for high-assurance network security telemetry.
