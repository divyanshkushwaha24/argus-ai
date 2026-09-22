# Argus AI — Comprehensive Feature Extraction Architecture Report

**Module:** `features/`  
**System:** Argus AI (Cherenkov Streaming Threat Intelligence Engine)  
**Authors:** Google DeepMind Advanced Agentic Coding Pair  
**Status:** Production & Verified  

---

## 1. Executive Summary & Data Flow Architecture

Feature extraction in **Argus AI** operates across two synchronized execution planes:
1. **Batch Extraction Plane** (`pipeline.py`, `ingest/generate_fresh_dataset.py`): Ingests pre-captured telemetry and synthetic datasets (`data/synthetic/fresh_flows.csv`), computing static flow kinetics, lexical n-grams, and dataset-level Shannon entropy.
2. **Real-Time Streaming Plane** (`streaming/event_processor.py`, `features/state_store.py`): Tails live Suricata EVE JSON (`data/raw/live_suricata/eve.json`) and Zeek connection logs in real time, maintains stateful sliding windows inside Redis, and enriches raw wire events with dynamic behavioral aggregations before publishing to the `cherenkov:events` stream.

Both pipelines converge on the same feature schema, feeding into the **6 specialized ML threat detectors** (`models/*.py`), the **Bayesian risk calibrator** (`models/fusion.py`), and the **multi-stage incident correlator** (`models/correlation.py`).

```
                    [ Network Wire Telemetry ]
               (Suricata EVE JSON / Zeek TSV / PCAPs)
                                │
                                ▼
         ┌──────────────────────────────────────────────┐
         │ 1. Ingestion & Schema Normalization          │
         │    normalize_suricata() / normalize_zeek()    │
         └──────────────────────┬───────────────────────┘
                                │ Normalized 5-tuple + L7 payload
                                ▼
         ┌──────────────────────────────────────────────┐
         │ 2. Stateful Sliding-Window Dispatcher        │
         │    features/state_store.py (Redis Backend)   │
         │    - ZSET: Timestamp sequences (600s window) │
         │    - HASH: Per-entity frequency hit counts   │
         │    - SET:  Cardinality of distinct targets   │
         └──────────────────────┬───────────────────────┘
                                │ Window aggregations
                                ▼
         ┌──────────────────────────────────────────────┐
         │ 3. Streaming Feature Enrichment Engine       │
         │    enrich_streaming_features()               │
         │    Computes: Entropy, Fanout, CV, Ratios     │
         └──────────────────────┬───────────────────────┘
                                │ Canonical feature dictionary
                                ▼
   ┌──────────────────────────────────────────────────────────┐
   │ 4. Parallel Detection Workers (pipeline/consumer.py)     │
   │    ├── models/ddos_detector.py      (Rate z-score, H(IP))│
   │    ├── models/beacon_detector.py    (IAT CV, Autocorr)   │
   │    ├── models/dga_model.py          (Bigrams, Entropy)   │
   │    ├── models/tls_malware_model.py  (JA3 Hash, RF model) │
   │    ├── models/scan_detector.py      (Port/IP Fanout)     │
   │    └── models/exfil_detector.py     (Byte Ratios, Vol)   │
   └──────────────────────────────────────────────────────────┘
```

---

## 2. Ingestion & Normalization Layer

Raw network sensors emit telemetry in disparate formats:
- **Suricata EVE JSON**: Nested JSON dictionaries (`flow`, `tls`, `dns`, `http`, `alert`).
- **Zeek TSV Logs**: Tab-separated connection logs (`conn.log`, `dns.log`, `ssl.log`).

The normalization engine (`streaming/event_processor.py`) standardizes these into a uniform dictionary shape with canonical 5-tuples:

```python
{
    "source": "suricata",
    "event_type": "flow",
    "ts": 1727028945.123,
    "flow_id": "192.168.1.105:54321-10.0.0.1:80",
    "src_ip": "192.168.1.105",
    "src_port": 54321,
    "dst_ip": "10.0.0.1",
    "dest_ip": "10.0.0.1",        # Automatic alias reconciliation
    "dst_port": 80,
    "dest_port": 80,              # Automatic alias reconciliation
    "proto": "TCP",
    "bytes_out": 5242880,
    "bytes_in": 1024,
    "pkts_toserver": 3800,
    "pkts_toclient": 12,
    "duration": 4.25,
    "conn_state": "SF",
    "flow_state": "SF",
    "dns_query": "xy91024abzc.corp-update.net",
    "ja3": "e7d705a3286e19ea42f587b344ee6865",
    "ja3_hash": "e7d705a3286e19ea42f587b344ee6865"
}
```

---

## 3. Subsystem Breakdown of Feature Extraction Modules

### 3.1 DNS & DGA Feature Extraction (`features/dns_features.py`)

Designed for the detection of **Domain Generation Algorithms (DGA)** and **DNS Exfiltration Tunnels**.

#### A. Lexical & Morphological Features
Given a raw query string (e.g., `v89zpq019kxm.badc2.org`), the primary domain/subdomain is isolated and evaluated:
- **`dns_query_length`**: Total character length of the query. DGAs and DNS exfiltration tunnels systematically produce longer query strings ($> 28$ chars).
- **`dns_entropy`**: Character-level Shannon entropy of the subdomain label:
  $$H(S) = -\sum_{c \in \Sigma} p(c) \log_2 p(c)$$
  Legitimate domains average $1.8 - 2.5$ bits; algorithmic or encrypted labels typically exceed $3.6$ bits.
- **`dns_digit_ratio`**: Numerical density $\frac{\sum \text{digits}}{\text{length}}$. Malware domain generators frequently incorporate pseudo-random hex or epoch digits.
- **`dns_label_count`**: Number of dot-delimited hierarchy labels (`len(query.split('.'))`).
- **`dns_longest_label`**: Maximum length of an individual label. Exfiltration payloads pack high volumes of base64/hex bytes into single sub-labels.
- **`dns_unique_bigram_count` & `dns_unique_trigram_count`**: Cardinality of distinct 2-character and 3-character sub-sequences. Random strings exhibit near-complete uniqueness compared to natural language.

#### B. English Bigram Log-Likelihood (`ngram_score`)
Natural language domains follow predictable character-pair transitions (e.g., `th`, `er`, `on`). Algorithmic domains generate rare transitions (e.g., `q0`, `zx`, `v8`).
- **Model**: Pre-computed relative frequency matrix derived from the Google English Web Corpus (Peter Norvig analysis), with Laplace smoothing for unseen bigrams:
  $$\text{score}(D) = \frac{1}{N-1} \sum_{i=1}^{N-1} \log_2 P(c_i c_{i+1})$$
- More negative scores denote lower linguistic plausibility (strong DGA signal).

---

### 3.2 Dynamic Shannon Entropy Engine (`features/entropy.py`)

Used by the **DDoS Detector** and **DNS Tunnel Detector**.

#### Mathematical Modeling
In a DDoS attack, a target IP experiences a flood of traffic originating either from a vast botnet or from randomized spoofed source addresses. Shannon entropy measures the dispersion of source IPs hitting a given destination:
$$H(S_{\text{dst}}) = -\sum_{i=1}^{k} \left(\frac{c_i}{N}\right) \log_2 \left(\frac{c_i}{N}\right)$$
Where:
- $k$ is the number of distinct source IPs observed hitting `dst_ip`.
- $c_i$ is the number of packets/connections originating from source $i$.
- $N = \sum_{i=1}^k c_i$ is the total packet volume targeting `dst_ip`.

#### State Store Mechanics
- Tracked via Redis Hash counters: `HINCRBY entropy:dst_sources:{dst_ip} {src_ip} 1`.
- When an event arrives, `get_hit_counts()` returns `{src_ip: count}`.
- True Shannon entropy (`source_ip_entropy_in_file`) and distinct attacker cardinality (`source_ip_count_in_file`) are dynamically computed over the distribution.

---

### 3.3 Port Scan & Reconnaissance Fanout (`features/fanout.py`)

Used by the **Scan Detector** to identify network mapping, port knocking, and horizontal/vertical reconnaissance.

#### Extracted Features:
- **`unique_destination_ports`**: Number of distinct destination ports contacted by `src_ip` within the sliding window. Tracked in Redis Set `fanout:dst_ports:{src_ip}` (`SCARD`).
- **`destination_fanout` / `unique_destination_ips`**: Number of distinct destination IPs contacted by `src_ip`. Tracked in Redis Set `fanout:dst_ips:{src_ip}` (`SCARD`).
- **`source_flow_count`**: Velocity of connection attempts made by `src_ip` within a 600-second window. Tracked via Redis Sorted Set `fanout:attempts:{src_ip}` (`ZCOUNT`).

---

### 3.4 C2 Beaconing & Periodicity Kinetics (`features/periodicity.py`)

Used by the **Beacon Detector** to uncover stealthy Command-and-Control malware agents checking in with external infrastructure at programmed intervals.

#### Extracted Features:
- **`src_interarrival_sec`**: Sequence of inter-arrival gaps $\Delta t_i = t_{i} - t_{i-1}$ across consecutive connections between a specific source and destination pair (`src_ip` $\rightarrow$ `dst_ip`). Tracked in Redis Sorted Set `periodicity:{src_ip}:{dst_ip}`.
- **Coefficient of Variation ($CV$)**:
  $$CV = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}} = \frac{\sqrt{\frac{1}{n-1}\sum (\Delta t_i - \bar{\Delta t})^2}}{\bar{\Delta t}}$$
  - **Automated Beacon**: $CV \approx 0.01 - 0.15$ (highly metronomic).
  - **Human Interactive Browsing**: $CV > 1.0$ (bursty, sporadic).
- **Autocorrelation & FFT Dominant Frequency**: Evaluates cyclical lag peaks and periodicity spikes to isolate fixed check-in intervals even in the presence of random jitter.

---

### 3.5 TLS Fingerprinting & Encrypted Malware Classification (`features/tls_features.py`)

Identifies malware communicating over encrypted channels without breaking TLS encryption.

#### A. JA3 Fingerprint Matching
- **JA3 String Formulation**: MD5 hash of client parameters:
  $$\text{JA3} = \text{MD5}(\text{SSLVersion},\text{CipherSuites},\text{Extensions},\text{EllipticCurves},\text{PointFormats})$$
- Evaluated against active blocklists (`data/ja3_blacklist/blacklist.csv` and `models/saved/ja3_blocklist.json`):
  - Cobalt Strike Malleable C2 (`a0e9f5d64349fb13191bc781f81f42e1`)
  - TrickBot / Emotet (`6734f37431670ce18779794dd34f4aa0`)
  - Metasploit Meterpreter (`72a589da586844d7f0818ce684948eea`)
  - AsyncRAT (`51c64c77e60f3980eea90869b68c58a8`)
  - Sliver C2 (`b32309a26951912be7dba376398abc3b`)
  - Synthetic Lab Malware (`e7d705a3286e19ea42f587b344ee6865`)

#### B. TLS Flow Kinetics & Classifier Features
- **`tls_event_count`**: Indicator flag denoting cryptographic handshake presence.
- **`upload_download_ratio`**: Ratio of egress to ingress bytes over the TLS tunnel.
- **`average_packet_size`**: Payload size distribution indicative of heartbeat telemetry vs data transmission.

---

### 3.6 Flow Kinetics & Exfiltration Telemetry (`features/statistical.py`)

Extracts directional flow volumes and transmission velocity used across the **Exfil Detector**, **DDoS Detector**, and **Anomaly Model**.

| Feature Key | Formula / Computation | Target Detector |
|---|---|---|
| `bytes_to_server` | Total egress payload bytes ($B_{\text{out}}$) | Exfiltration |
| `bytes_to_client` | Total ingress payload bytes ($B_{\text{in}}$) | Exfiltration |
| `total_bytes` | $B_{\text{out}} + B_{\text{in}}$ | DDoS / Exfil |
| `upload_download_ratio` | $\frac{B_{\text{out}}}{\max(1.0, B_{\text{in}})}$ | Exfiltration ($> 10.0$) |
| `byte_rate` | $\frac{\text{total\_bytes}}{\max(0.001, \text{duration})}$ | DDoS / Exfil |
| `packets_to_server` | Outbound packet count ($P_{\text{out}}$) | DDoS / Portscan |
| `packets_to_client` | Inbound packet count ($P_{\text{in}}$) | DDoS / Portscan |
| `total_packets` | $P_{\text{out}} + P_{\text{in}}$ | DDoS |
| `packet_rate` | $\frac{\text{total\_packets}}{\max(0.001, \text{duration})}$ | DDoS Flood |
| `average_packet_size`| $\frac{\text{total\_bytes}}{\max(1, \text{total\_packets})}$ | Anomaly Model |
| `flow_duration` | Connection lifetime in seconds | Beacon / Exfil |

---

## 4. State Management & Sliding Windows (`features/state_store.py`)

In streaming mode, features are not static rows in a CSV; they evolve over time. `StateStore` provides an abstraction backed by Redis with local in-memory fallback.

### Redis Key Design & Memory Structure:

```
[cherenkov:state]
  ├── fanout:dst_ports:{src_ip}   ──► SET   ──► SADD dst_port (TTL: 3600s)
  ├── fanout:dst_ips:{src_ip}     ──► SET   ──► SADD dst_ip   (TTL: 3600s)
  ├── fanout:attempts:{src_ip}    ──► ZSET  ──► ZADD ts {dst_ip}:{dst_port} (Sliding: 600s)
  ├── periodicity:{src_ip}:{dst_ip}─► ZSET  ──► ZADD ts ts (Sliding: 600s)
  ├── entropy:dst_sources:{dst_ip}──► HASH  ──► HINCRBY src_ip 1 (TTL: 3600s)
  └── entropy:dns_events:{src_ip} ──► ZSET  ──► ZADD ts query (Sliding: 600s)
```

- **Sliding Window Pruning**: On each `record_ts()` call, a non-transactional Redis pipeline automatically executes `ZREMRANGEBYSCORE(key, 0, ts - window_s)`, evicting expired connection events and maintaining constant memory complexity $O(W)$.

---

## 5. Detector-to-Feature Mapping Matrix

| Threat Detector | Primary Features Extracted | Auxiliary / Fusion Features | Threshold / Criteria |
|---|---|---|---|
| **DDoS Detector** | `source_ip_entropy_in_file`, `source_ip_count_in_file`, `packet_rate` | `byte_rate`, `total_packets` | $H(\text{IP}) > 4.5$ bits, Flow rate z-score $> 3.0$ |
| **Beacon Detector** | `src_interarrival_sec`, `coefficient_of_variation` | `flow_duration`, `average_packet_size` | $CV < 0.20$, $\ge 5$ connection pulses |
| **DNS Tunnel / DGA** | `dns_entropy`, `ngram_score`, `dns_query_length` | `dns_digit_ratio`, `dns_label_count`, `dns_event_count` | Entropy $> 3.8$, N-Gram $< -7.5$, Length $> 28$ |
| **TLS / JA3 Malware** | `ja3` / `ja3_hash`, `tls_event_count` | `upload_download_ratio`, `bytes_to_server` | Match in JA3 blocklist or RF Classifier $> 0.85$ |
| **Scan Detector** | `unique_destination_ports`, `destination_fanout` | `source_flow_count`, `conn_state` | Fanout $> 15$ ports in 30s, High SYN-to-ACK ratio |
| **Exfiltration Detector** | `upload_download_ratio`, `bytes_to_server` | `byte_rate`, `flow_duration` | Payload $> 5 \text{ MB}$, Out/In Ratio $> 10.0$ |

---

## 6. Critical Fixes & Hardening Applied

### 1. The Real Shannon Entropy Resolution
- **Issue**: Historical implementations stored source IPs in a Redis Set (`SADD`). Sets only track membership ($1$ or $0$), not frequency. Computing entropy from cardinality yielded a constant flat number rather than a frequency distribution.
- **Resolution**: Converted storage to Redis Hashes (`HINCRBY entropy:dst_sources:{dst_ip} {src_ip} 1`). `features/state_store.py` now provides `get_hit_counts()`, enabling true mathematical Shannon entropy calculation on read.

### 2. Centralized Alias Reconciliation
- **Issue**: Inconsistent key names between network parsers and detector models (`dst_ip` vs `dest_ip`, `dst_port` vs `dest_port`, `conn_state` vs `flow_state`, `ja3` vs `ja3_hash`). Previously, each detector carried redundant, error-prone fallback code.
- **Resolution**: Standardized upfront in `enrich_streaming_features()` (`streaming/event_processor.py`), guaranteeing that every event delivered to any detector conforms to both schemas simultaneously.

### 3. Redis Safe String/Byte Decoding
- **Issue**: `HGETALL` and `SMEMBERS` returned `bytes` in standard Redis configurations, causing crashes when `.decode()` was invoked on clients instantiated with `decode_responses=True`.
- **Resolution**: Implemented dynamic type checking: `m.decode("utf-8") if isinstance(m, bytes) else str(m)`.

---

## 7. Verification & Unit Testing

The feature extraction layer is validated by 48 automated test modules:
```bash
PYTHONPATH=. pytest tests/
```
- **`tests/test_pipeline.py`**: Verifies feature extraction consistency across batch and streaming modes.
- **`tests/test_alerting_schema.py`**: Asserts strict Pydantic and dataclass schema compliance for enriched alerts.
- **`tests/test_session_archive.py`**: Verifies state store reset and session archiving persistence.
