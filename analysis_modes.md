# Argus AI — Architecture & Operational Modes Analysis

## Real-Time IP Traffic Ingestion vs. Synthetic Batch Processing

---

## 1. Executive Summary

This report provides a comprehensive architectural evaluation of **Argus AI (Cherenkov)** in response to whether the pipeline can ingest **live, real-time IP network traffic**, dynamically detect threats, and continuously populate the SOC dashboard as packets arrive on the wire until analysis is stopped.

### Key Finding
> **Yes.** The platform architecture inherently features an asynchronous, event-driven streaming pipeline designed specifically for real-time traffic ingestion, multi-model evaluation, and live dashboard telemetry. While `run_fresh.py` executes in **Batch Mode** (reading pre-computed synthetic CSV flows), the underlying system includes a fully developed **Streaming Mode** (`pipeline.consumer`) capable of sniffing real network interfaces or virtual taps via Suricata/Zeek and continuously updating the PostgreSQL database and Streamlit dashboard in real time.

---

## 2. Architecture Comparison

Argus AI contains two distinct execution pipelines:

```
Batch Mode (pipeline.py / run_fresh.py)          Streaming Mode (run_realtime.py / consumer up)
──────────────────────────────────────          ──────────────────────────────────────────────
           Fresh Synthetic CSV                                Live NIC or tcpreplay
                   │                                                    │
                   ▼                                                    ▼
           Feature Simulation                                  veth0 (Transmitter)
                   │                                                    │
                   ▼                                                (Kernel)
         6 Threat Classifiers                                           │
       (DDoS, Beacon, Scan, DGA,                                        ▼
          Exfil, TLS Malware)                                    veth1 (Monitor Tap)
                   │                                                    │
                   ▼                                                    ▼
         SHAP / Calibrated Risk                                  Suricata Sensor
                   │                                             (af-packet / IDS)
                   ▼                                                    │
           Incident Correlation                                  eve.json Stream
                   │                                                    │
                   ▼                                                    ▼
         db.insert_alerts_batch()                               event_processor.py
                   │                                            (Continuous tail -f)
                   ▼                                                    │
          PostgreSQL Database                                    Redis Stream
                   │                                          (cherenkov:events)
                   ▼                                                    │
          Streamlit Dashboard                                           ▼
             (Static View)                                       consumer worker
                                                               (6 Streaming Models)
                                                                        │
                                                                        ▼
                                                                alerting/writer.py
                                                                        │
                                                                        ▼
                                                               PostgreSQL Database
                                                               (Continuous Appends)
                                                                        │
                                                                        ▼
                                                               Streamlit Dashboard
                                                                (2s Auto-Refresh)
```

---

## 3. Detailed Operational Modes

### Mode A: Batch Flow Processing (`run_fresh.py`)
- **Input Source**: Pre-generated CSV (`data/synthetic/fresh_flows.csv`).
- **Execution**: Runs synchronously through `pipeline.py`.
- **Flow**: Evaluates all rows, computes isolation forest anomaly scores, runs SHAP explanations, correlates alerts into incident graphs, clears previous database records, and inserts the batch into PostgreSQL.
- **Latency / Behavior**: One-shot execution. When processing ends, the script opens Streamlit.
- **Use Case**: Offline benchmarking, rapid development, model validation, and static presentation.

### Mode B: Real-Time Event-Driven Streaming (`pipeline.consumer`)
- **Input Source**: Live raw packets from physical network adapters (e.g. `eth0`) or virtual ethernet taps (`veth0` <-> `veth1`).
- **Sensor Layer**: Deep Packet Inspection (DPI) via **Suricata** running natively on the monitoring interface (`veth1`). Suricata extracts flow metrics, DNS queries, TLS handshakes with JA3 hashes, and HTTP payloads, continuously appending JSON Lines to `eve.json`.
- **Event Processor**: `streaming/event_processor.py` implements a persistent non-blocking `tail -f` (`follow()`) loop. It parses each JSON event, updates rolling window state in Redis (fan-out, connection periodicity, destination hit entropy), and pushes normalized events onto the Redis Stream (`cherenkov:events`).
- **Worker Detection Tier**: Python worker processes (`pipeline.consumer worker`) read from the Redis consumer group (`cherenkov-detect`). Incoming events are routed through 6 active detectors:
  1. `DDoSDetector`: SYN flood & high packet-rate anomaly detection.
  2. `BeaconDetector`: C2 periodic beacon interval analysis.
  3. `ScanDetector`: Horizontal/vertical reconnaissance detection.
  4. `ExfilDetector`: Skewed upload/download volume anomaly detection.
  5. `DGAModel`: High-entropy, algorithmically generated domain classifier.
  6. `TLSMalwareModel`: Malicious JA3 fingerprint matching against blacklists.
- **Persistence & Sink**: Validated threat detections are formatted according to the unified alert contract and written to PostgreSQL (`public.alerts` and `public.incidents`) via `alerting/writer.py`.
- **Dashboard Telemetry**: The Streamlit dashboard (`dashboard/app.py`) executes an automatic 2-second polling refresh cycle (`st.rerun()`). As new alerts land in PostgreSQL, the UI metrics, threat distribution charts, and incident tables dynamically increment and repopulate without user interaction.
- **Termination**: The pipeline runs indefinitely, continuously ingesting packets until a termination signal (SIGINT / Ctrl+C) is received.

---

## 4. Capability Comparison Matrix

| Capability | Batch Mode (`run_fresh.py`) | Real-Time Streaming (`run_realtime.py`) |
|---|---|---|
| **Processes Real NIC Traffic** | ❌ No (CSV only) | ✅ **Yes** (Sniffs raw packets via Suricata) |
| **Supports tcpreplay PCAP Injection** | ❌ No | ✅ **Yes** (Injected at configurable PPS) |
| **Continuous Dashboard Telemetry** | ❌ No (One-shot batch) | ✅ **Yes** (Live real-time feed, 2s auto-refresh) |
| **Runs Indefinitely until Stopped** | ❌ No (Exits after CSV) | ✅ **Yes** (Continuous background workers) |
| **Root / Sudo Requirement** | 🟢 None (Non-root user) | 🟡 Required for `veth` & raw socket capture |
| **Infrastructure Dependencies** | PostgreSQL | PostgreSQL + Redis + Suricata + veth |
| **Throughput & Backpressure** | Batch sequential (~16 flows/s) | Asynchronous Redis Streams (>10,000 eps) |

---

## 5. Requirements for Full Real-Time Operation

To achieve live traffic ingestion from packet arrival to dashboard presentation, four integrated layers must be orchestrated:

### 1. Kernel Virtual Tap Setup
A bidirectional virtual ethernet pair with an enforced listen-only monitoring boundary:
```bash
# Create paired virtual adapters
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up && sudo ip link set veth1 up

# Enforce read-only / monitor boundary on veth1
sudo ip addr flush dev veth1
sudo ip link set veth1 promisc on
sudo ip link set dev veth1 arp off
sudo sysctl -w net.ipv6.conf.veth1.disable_ipv6=1

# Kernel packet drop rule on veth1 egress (sniff-only guarantee)
sudo tc qdisc replace dev veth1 clsact
sudo tc filter replace dev veth1 egress pref 1 protocol all matchall action drop
```

### 2. Live Suricata DPI Sensor
Suricata sniffs `veth1` in non-blocking mode and outputs structured telemetry to `eve.json`:
```bash
sudo suricata -i veth1 -l data/raw/live_suricata/
```

### 3. Streaming Orchestrator & Event Processor
The orchestrator brings up detection workers, starts the event tailer on `eve.json`, and routes alerts into PostgreSQL:
```bash
CHERENKOV_PROCESSOR_CMD="python3 -m streaming.event_processor --eve-json data/raw/live_suricata/eve.json" \
python3 -m pipeline.consumer up --auto-start --no-network
```

### 4. Traffic Injection or Production Tap
Traffic can either arrive natively via a physical network interface or be continuously injected using `tcpreplay`:
```bash
sudo tcpreplay --intf1=veth0 --pps=1000 data/synthetic/portscan.pcap
```

---

## 6. End-to-End Automation: `run_realtime.py`

To eliminate the complexity of manually coordinating 5 terminal tabs, `run_realtime.py` provides a **single-command supervisor** that:
1. Validates that PostgreSQL and Redis containers are healthy.
2. Automates `veth0`/`veth1` interface creation and kernel read-only boundary enforcement.
3. Launches the native Suricata sensor on `veth1`.
4. Spawns the Cherenkov Streaming Orchestrator (`pipeline.consumer`) with downstream workers and `event_processor`.
5. Launches a background traffic injector (looping through synthetic PCAPs or listening for external frames).
6. Automatically launches the Streamlit SOC Dashboard and opens `http://localhost:8501`.
7. Traps `Ctrl+C` to ensure clean process teardown, stopping Suricata, workers, and replaying without orphaned background processes.

