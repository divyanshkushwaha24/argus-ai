"""
Argus AI — Standardized alert schema.

Every detector emits a Detection; fusion turns it into an Alert.
Both are plain dataclasses so they serialize cleanly to JSON/Postgres.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import config


@dataclass
class Detection:
    """Raw output of a single detector — one per suspicious flow."""

    timestamp: str                        # ISO-8601
    flow_id: str                          # Suricata flow identifier
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    threat_class: str                     # ddos | beacon | dns_tunnel | ja3_malware | portscan | exfil
    confidence: float                     # 0–1  (calibrated for ML; mapped for stat)
    evidence: dict = field(default_factory=dict)    # human-readable key→value
    raw_features: dict = field(default_factory=dict) # numeric features used

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Alert:
    """A Detection after fusion, explanation, and correlation."""

    # identity
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: Optional[str] = None

    # from Detection
    timestamp: str = ""
    flow_id: str = ""
    src_ip: str = ""
    src_port: int = 0
    dest_ip: str = ""
    dest_port: int = 0
    threat_class: str = ""
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)

    # from Fusion
    anomaly_score: float = 0.0
    severity_prior: float = 0.0
    recency: float = 1.0
    risk_score: int = 0                   # 0–100
    risk_level: str = "LOW"               # LOW | MEDIUM | HIGH | CRITICAL

    # from Explain
    explanation: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        # evidence is already a dict, make sure it's JSON-safe
        d["evidence"] = json.dumps(d["evidence"]) if isinstance(d["evidence"], dict) else d["evidence"]
        return d

    @staticmethod
    def from_detection(det: Detection, risk_score: int, risk_level: str,
                       anomaly_score: float = 0.0, recency: float = 1.0,
                       explanation: str = "",
                       incident_id: Optional[str] = None) -> "Alert":
        severity = config.SEVERITY_PRIORS.get(det.threat_class, 0.5)
        return Alert(
            timestamp=det.timestamp,
            flow_id=det.flow_id,
            src_ip=det.src_ip,
            src_port=det.src_port,
            dest_ip=det.dest_ip,
            dest_port=det.dest_port,
            threat_class=det.threat_class,
            confidence=det.confidence,
            evidence=det.evidence,
            anomaly_score=anomaly_score,
            severity_prior=severity,
            recency=recency,
            risk_score=risk_score,
            risk_level=risk_level,
            explanation=explanation,
            incident_id=incident_id,
        )


def risk_level_from_score(score: int) -> str:
    """Map a 0–100 risk score to a label."""
    for threshold, level in config.RISK_LEVELS:
        if score >= threshold:
            return level
    return "LOW"
