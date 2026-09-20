# Argus AI — Model Notes

## Z-Score → Confidence Mapping

**Method**: Linear mapping  
**Formula**: `confidence = min(1.0, |z| / 6.0)`

| z-score | Confidence | Interpretation |
|---------|------------|---------------|
| 1.0 | 0.17 | Slightly unusual |
| 3.0 | 0.50 | Noteworthy — at threshold |
| 4.5 | 0.75 | Strong signal |
| 6.0+ | 1.00 | Very strong signal |

**Rationale**: z = 3 (our detection threshold) maps to confidence 0.50, which makes intuitive sense — "something is happening but we're not fully certain yet". z = 6 saturates to 1.0 because at that point we're 6 standard deviations from normal, which is an extremely rare event in any distribution.

**Alternative considered**: Logistic curve `1 / (1 + exp(-1.5*(z - 3)))` produces a sharper transition around the threshold. We chose linear for transparency — every z increase maps to a proportional confidence increase, making it easier to explain.

---

## Model Calibration

**DGA XGBoost**: Calibrated using `CalibratedClassifierCV(cv=3, method="sigmoid")` (Platt scaling). This ensures the model's output probability is a true probability — when the model says 0.80, approximately 80% of those predictions are correct.

**TLS Malware RF**: Calibrated using `CalibratedClassifierCV(cv=2, method="sigmoid")`. Fewer folds due to very small positive class (4 training samples). Combined with JA3 blocklist for primary detection.

**Isolation Forest**: Unsupervised — outputs are anomaly scores, not probabilities. Mapped to [0, 1] via `anomaly = max(0, min(1, -decision_function / 0.5))`.

---

## Incident Correlation: Noisy-OR Rule

**Formula**: `incident_risk = 1 − Π(1 − rᵢ)`

Each alert's risk (0-1) is treated as an independent probability. The combined incident risk answers: "what is the probability that at least one of these alerts represents a real threat?"

**Worked example**:
```
Alert risks: [0.40, 0.42, 0.50, 0.70]
Step 1: 1 - 0.40 = 0.60
Step 2: 0.60 × 0.58 = 0.348
Step 3: 0.348 × 0.50 = 0.174
Step 4: 0.174 × 0.30 = 0.0522
Result: 1 - 0.0522 = 0.9478 ≈ 95% → CRITICAL
```

This matches the desired escalation story: isolated medium-risk alerts combine into a critical incident.

---

## Risk Fusion Weights

| Component | Weight | Source |
|-----------|--------|--------|
| P (detector confidence) | 0.50 | Model output / z-score mapping |
| A (anomaly score) | 0.20 | Isolation Forest |
| S (severity prior) | 0.20 | Expert-assigned per threat class |
| R (recency) | 0.10 | exp(-age / 30min) decay |

**Risk Levels**: 0–39 LOW, 40–69 MEDIUM, 70–89 HIGH, 90–100 CRITICAL

---

## Per-Model Metrics (Test Set)

### DGA / DNS Tunnel — XGBoost
- **Precision**: 1.00
- **Recall**: 1.00
- **F1**: 1.00
- **ROC-AUC (train)**: 1.00
- **Features used**: dns_entropy, dns_query_length, dns_digit_ratio, dns_label_count, dns_longest_label, dns_unique_bigram_count, dns_unique_trigram_count, dns_event_count, dns_unique_domain_count_per_flow, dns_max_query_length_per_flow, ngram_score
- **Note**: High performance expected on synthetic data. Real-world DGA domains will have more variety; retrain on CICIDS/CTU-13 datasets.

### TLS Malware — RandomForest + JA3 Blocklist
- **Precision**: 1.00
- **Recall**: 1.00
- **F1**: 1.00
- **ROC-AUC (train)**: 1.00
- **Features used**: packets_to_server, packets_to_client, bytes_to_server, bytes_to_client, total_packets, total_bytes, average_packet_size, upload_download_ratio, tls_event_count, source_flow_count, flow_duration, packet_rate, byte_rate
- **Note**: Only 5 total malware samples. JA3 blocklist is the primary signal; RF is secondary.

### Overall Pipeline (Weighted F1: 0.99)
| Threat | Precision | Recall | F1 | Samples |
|--------|-----------|--------|-----|---------|
| ddos | 1.00 | 1.00 | 1.00 | 200 |
| portscan | 1.00 | 1.00 | 1.00 | 40 |
| dns_tunnel | 1.00 | 1.00 | 1.00 | 12 |
| benign | 0.89 | 1.00 | 0.94 | 8 |
| beacon | 1.00 | 1.00 | 1.00 | 6 |
| ja3_malware | 1.00 | 1.00 | 1.00 | 1 |
| exfil | 0.00 | 0.00 | 0.00 | 1* |

*Exfil test sample is an IPv6 multicast discovery packet (70 bytes, not exfiltration). The real exfil flow (2MB outbound, ratio 19239:1) is in training data and correctly detected there.

---

## Feature Importance (DGA XGBoost, Top 5)

1. **dns_entropy** — character randomness of domain name
2. **dns_query_length** — total query length
3. **ngram_score** — English-likeness of letter pairs
4. **dns_longest_label** — longest subdomain label length
5. **dns_digit_ratio** — proportion of digits in domain name
