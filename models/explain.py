"""
Argus AI — Explanation engine (Stage 7a).

Translates model predictions into human-readable sentences.

For ML models (DGA, TLS): uses SHAP TreeExplainer to find top-3 features
that pushed the score up/down, then renders them as prose.

For rule-based detectors: uses template sentences from the evidence dict.
"""

from __future__ import annotations

from typing import Dict, Optional

import config
from models.alert_schema import Alert, Detection


# ── Human-friendly feature name mapping ──────────────────────────────
_FEATURE_NAMES = {
    "dns_entropy": "domain entropy",
    "dns_query_length": "query length",
    "dns_digit_ratio": "digit ratio",
    "dns_label_count": "label count",
    "dns_longest_label": "longest label",
    "dns_unique_bigram_count": "unique bigrams",
    "dns_unique_trigram_count": "unique trigrams",
    "dns_event_count": "DNS event count",
    "dns_unique_domain_count_per_flow": "unique domains/flow",
    "dns_max_query_length_per_flow": "max query length/flow",
    "ngram_score": "English-likeness score",
    "packets_to_server": "packets to server",
    "packets_to_client": "packets to client",
    "bytes_to_server": "bytes to server",
    "bytes_to_client": "bytes to client",
    "total_packets": "total packets",
    "total_bytes": "total bytes",
    "average_packet_size": "avg packet size",
    "upload_download_ratio": "upload/download ratio",
    "tls_event_count": "TLS event count",
    "source_flow_count": "source flow count",
    "flow_duration": "flow duration",
    "packet_rate": "packet rate",
    "byte_rate": "byte rate",
}

# Benign reference values for comparison
_BENIGN_REFERENCE = {
    "dns_entropy": 2.5,
    "dns_query_length": 15,
    "dns_digit_ratio": 0.05,
    "dns_longest_label": 10,
    "ngram_score": -3.0,
    "upload_download_ratio": 2.0,
    "average_packet_size": 300,
}


def explain_detection(alert: Alert) -> str:
    """Generate a human-readable explanation for an alert.

    Returns a sentence or two that a security analyst can read and
    understand without seeing raw feature vectors.
    """
    evidence = alert.evidence if isinstance(alert.evidence, dict) else {}

    # ── If the detector already provided a 'reason', use it ──────────
    if "reason" in evidence and evidence["reason"]:
        explanation = str(evidence["reason"])
        # Augment with SHAP if available
        shap_text = _format_shap(evidence.get("shap_top_features", {}))
        if shap_text:
            explanation += f". Key features: {shap_text}"
        return explanation

    # ── Template-based fallback per threat class ─────────────────────
    tc = alert.threat_class

    if tc == "ddos":
        return _explain_ddos(evidence)
    elif tc == "beacon":
        return _explain_beacon(evidence)
    elif tc == "dns_tunnel":
        return _explain_dga(evidence)
    elif tc == "ja3_malware":
        return _explain_tls(evidence)
    elif tc == "portscan":
        return _explain_scan(evidence)
    elif tc == "exfil":
        return _explain_exfil(evidence)
    else:
        return f"Threat detected: {tc} (confidence {alert.confidence:.2f})"


def _format_shap(shap_features: Dict) -> str:
    """Format SHAP feature contributions as readable text."""
    if not shap_features or not isinstance(shap_features, dict):
        return ""
    parts = []
    for feat_name, info in shap_features.items():
        if not isinstance(info, dict):
            continue
        human_name = _FEATURE_NAMES.get(feat_name, feat_name)
        value = info.get("value", "?")
        shap_val = info.get("shap", 0)
        direction = "↑" if shap_val > 0 else "↓"
        ref = _BENIGN_REFERENCE.get(feat_name)
        if ref is not None:
            parts.append(f"{human_name} {value} (benign typical {ref}) {direction}")
        else:
            parts.append(f"{human_name} {value} {direction}")
    return ", ".join(parts[:3])


def _explain_ddos(ev: Dict) -> str:
    z = ev.get("flow_rate_zscore", 0)
    ent = ev.get("source_ip_entropy", 0)
    cnt = ev.get("source_ip_count", 0)
    return (
        f"Volumetric DDoS: flow rate z-score {z:.1f} "
        f"(threshold {config.DDOS_ZSCORE_THRESHOLD}), "
        f"source IP entropy {ent:.2f}, {cnt} unique source IPs"
    )


def _explain_beacon(ev: Dict) -> str:
    cv = ev.get("inter_arrival_cv", 0)
    period = ev.get("beacon_period_sec", 0)
    flows = ev.get("source_flow_count", 0)
    return (
        f"C2 beaconing: inter-arrival CV {cv:.3f} "
        f"(threshold < {config.BEACON_CV_THRESHOLD}), "
        f"estimated {period:.1f}s interval, {flows} periodic flows"
    )


def _explain_dga(ev: Dict) -> str:
    prob = ev.get("model_probability", 0)
    query = ev.get("dns_query", "")[:50]
    shap_text = _format_shap(ev.get("shap_top_features", {}))
    base = f"DGA/DNS tunnel: model probability {prob:.2f}, query '{query}'"
    if shap_text:
        base += f". Key features: {shap_text}"
    return base


def _explain_tls(ev: Dict) -> str:
    ja3 = ev.get("ja3_hash", "N/A")
    bl = ev.get("blocklist_hit", False)
    rf = ev.get("rf_confidence", 0)
    parts = [f"Encrypted malware"]
    if bl:
        parts.append(f"JA3 {ja3[:16]}... on blocklist")
    if rf > 0.3:
        parts.append(f"RF classifier confidence {rf:.2f}")
    shap_text = _format_shap(ev.get("shap_top_features", {}))
    if shap_text:
        parts.append(f"key features: {shap_text}")
    return ": ".join(parts[:1]) + " — " + ", ".join(parts[1:])


def _explain_scan(ev: Dict) -> str:
    ports = ev.get("unique_destination_ports", 0)
    flows = ev.get("source_flow_count", 0)
    state = ev.get("flow_state", "")
    return (
        f"Port scan: {ports} unique ports probed "
        f"(threshold {config.SCAN_FANOUT_THRESHOLD}), "
        f"{flows} flows, connection state '{state}'"
    )


def _explain_exfil(ev: Dict) -> str:
    ratio = ev.get("upload_download_ratio", 0)
    kb_out = ev.get("bytes_outbound", 0) / 1024
    z = ev.get("ratio_zscore", 0)
    return (
        f"Data exfiltration: outbound:inbound ratio {ratio:.1f} "
        f"(threshold {config.EXFIL_RATIO_THRESHOLD}), "
        f"{kb_out:.0f} KB outbound, z-score {z:.1f}"
    )
