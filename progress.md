# Argus AI — Progress Log

## Stage 1-4 (Pre-existing)
- Scapy → synthetic PCAP generation (6 threats + benign)
- Zeek + Suricata → JSON log parsing
- Feature extraction → train_dataset.csv (1070 rows) + test_dataset.csv (268 rows), 80/20 split
- Docker (Redis + Postgres), architecture docs

## Stage 5: Detectors
- **4 rule-based**: DDoS (z-score + src-IP entropy), beacon (CV + autocorrelation), portscan (fan-out threshold), exfil (byte ratio z-score)
- **2 ML-trained**: DGA/DNS-tunnel (XGBoost, calibrated), TLS malware (JA3 blocklist + RandomForest, calibrated)
- Tools: scikit-learn, xgboost, scipy, numpy

## Stage 6: Risk Fusion
- Weighted sum: P(0.5) + A(0.2) + S(0.2) + R(0.1)
- Isolation Forest anomaly baseline on benign traffic
- Z-score→confidence: linear min(1, z/6)
- Levels: LOW/MED/HIGH/CRITICAL

## Stage 7: Explanation + Correlation
- SHAP TreeExplainer for DGA and TLS models → top-3 features → human sentences
- Template-based explanations for rule-based detectors
- Incident correlation: group by src_ip, 10min gap merge, noisy-OR risk combination

## Stage 8: Pipeline
- Streaming runner: reads CSV, routes to detectors, fuses, explains, correlates
- Writes to SQLite (Postgres fallback available)
- 25 flows/sec throughput, 40ms/flow latency

## Stage 9: Dashboard
- Streamlit app polling DB every 2s
- KPI cards, threat distribution pie, risk histogram, alert table with filters, incident view

## Test Results (test_dataset.csv)
- Overall weighted F1: **0.99**
- DDoS: 1.00, portscan: 1.00, dns_tunnel: 1.00, beacon: 1.00, ja3_malware: 1.00, benign: 0.94
- 311 alerts → 201 incidents, top incident CRITICAL (100) combining 4 threat types
