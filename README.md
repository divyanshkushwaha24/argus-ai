# Argus AI — Real-Time Threat Intelligence & Streaming Detection

Argus AI is an end-to-end passive network threat detection pipeline. It ingests network telemetry (flows, DNS, TLS/JA3, Suricata/Zeek logs), evaluates 6 specialized threat detectors, computes calibrated risk scores, generates human-readable explanations, correlates alerts into multi-stage incidents, and visualizes them on a live Streamlit dashboard.

---

## 🚀 Quick Start for Linux Teammates

You can run Argus AI in two ways on Linux:

1. **Via Docker (Recommended)** — 1 command, zero manual dependencies.
2. **Via Native Host** — directly using Python 3 and virtual environment.

---

### Method 1: Docker (Fastest & Zero Configuration)

#### 1. Clone the repository

```bash
git clone https://github.com/divyanshkushwaha24/argus-ai.git
cd argus-ai
```

#### 2. Start all services

```bash
docker compose up -d
```

This automatically:

- Builds the detection and dashboard container.
- Provisions **Redis 7** (sliding-window state store & event streams).
- Provisions **PostgreSQL 16** and automatically initializes the database schema (`alerts` & `incidents` tables).
- Starts the **Cherenkov Streaming Orchestrator**.
- Starts the **Streamlit Threat Intelligence Dashboard** on port 8501.

#### 3. Open the Dashboard

Visit `http://localhost:8501` in your browser.

#### 4. Useful Docker Commands

```bash
# Run the batch flow pipeline anytime (processes test dataset CSV):
docker compose run --rm pipeline python pipeline.py

# Run the full unit test suite:
docker compose run --rm pipeline pytest tests/

# Check status of streaming workers and queues:
docker compose run --rm pipeline python pipeline/consumer.py status

# View live container logs:
docker compose logs -f pipeline

# Stop the entire stack:
docker compose down
```

---

### Method 2: Native Linux Host (Bare Metal)

#### 1. Prerequisites (Ubuntu / Debian)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

_(Optional for raw packet simulation):_

```bash
sudo apt install -y tcpreplay iproute2
```

#### 2. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/divyanshkushwaha24/argus-ai.git
cd argus-ai

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### 3. Run the Batch Pipeline (Zero External Dependencies)

To process the flow dataset, run all 6 detectors, correlate incidents, and write to the local database:

```bash
python pipeline.py
```

#### 4. Launch the Dashboard

```bash
streamlit run dashboard/app.py
```

Open `http://localhost:8501` to view live alerts, threat distributions, and incident correlation.

#### 5. Run the Real-Time Streaming Pipeline (Cherenkov)

If you have Redis running (e.g. `docker compose up -d redis` or local Redis service):

```bash
# Verify system preflight:
python pipeline/consumer.py preflight

# Start streaming orchestrator:
python pipeline/consumer.py up --auto-start --no-network
```

---

## 🛡️ Detectors Included

| Threat Class            | Detection Mechanism                                    | Model Type         |
| ----------------------- | ------------------------------------------------------ | ------------------ |
| **DDoS**                | Rolling z-score on packet rates + source IP entropy    | Rule-based         |
| **C2 Beaconing**        | Inter-arrival regularity (CV < 0.3) + Autocorrelation  | Statistical        |
| **Port Scan**           | Fan-out connection thresholding in sliding time window | Rule-based         |
| **Exfiltration**        | Upload/Download byte ratio asymmetry + z-score         | Statistical        |
| **DGA / DNS Tunneling** | Subdomain entropy, length, n-gram score                | XGBoost Classifier |
| **TLS Malware**         | JA3 fingerprint match against blocklist + cipher sets  | Random Forest      |

---

## 🧪 Running Tests

```bash
PYTHONPATH=. pytest tests/
```

All 45 hermetic tests verify alert schemas, Pydantic contracts, and detector evaluation logic.
