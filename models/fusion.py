"""
Argus AI — Risk fusion (Stage 6).

Every detector outputs a Detection with confidence P ∈ [0, 1].
Fusion combines it with anomaly score, severity prior, and recency
into a single risk score 0–100.

Formula:
  risk = (w_P × P + w_A × A + w_S × S + w_R × R) × 100

Worked example (weights 0.5, 0.2, 0.2, 0.1):
  P=0.90, A=0.60, S=0.70, R=0.30
  0.5×0.9 + 0.2×0.6 + 0.2×0.7 + 0.1×0.3 = 0.74 → risk 74 → HIGH
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Optional

import config
from models.alert_schema import Detection, Alert, risk_level_from_score
from models.anomaly import AnomalyModel


# Global anomaly model instance
_anomaly_model: Optional[AnomalyModel] = None


def _get_anomaly_model() -> AnomalyModel:
    global _anomaly_model
    if _anomaly_model is None:
        _anomaly_model = AnomalyModel()
        _anomaly_model.load()
    return _anomaly_model


def compute_recency(timestamp_str: str, now: Optional[datetime] = None) -> float:
    """Recency decay: R = exp(-age_minutes / half_life).

    Recent events get R ≈ 1.0; events from 30 min ago get R ≈ 0.37.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    try:
        ts = datetime.fromisoformat(timestamp_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age_minutes = max(0, (now - ts).total_seconds() / 60.0)
    except (ValueError, TypeError):
        age_minutes = 0
    return math.exp(-age_minutes / config.RECENCY_HALF_LIFE_MINUTES)


def fuse(detection_or_threat_class: Any, *args, **kwargs) -> Any:
    """Turn a Detection into a scored Alert, or fuse 4 signals into a 0-100 risk score.

    Supports dual invocation:
      1. Batch mode: fuse(detection: Detection, row=None, reference_time=None) -> Alert
      2. Streaming mode: fuse(threat_class: str, p: float, a: float, recency: float) -> int
    """
    if isinstance(detection_or_threat_class, str):
        threat_class = detection_or_threat_class
        p = float(args[0]) if len(args) > 0 else float(kwargs.get("p_detector", kwargs.get("p", 0.0)))
        a = float(args[1]) if len(args) > 1 else float(kwargs.get("a_anomaly", kwargs.get("a", 0.0)))
        r = float(args[2]) if len(args) > 2 else float(kwargs.get("recency", kwargs.get("r", 1.0)))

        w_P, w_A, w_S, w_R = config.FUSION_PARAMS.get(
            threat_class.lower(),
            config.FUSION_PARAMS.get(
                threat_class,
                (config.FUSION_WEIGHT_P, config.FUSION_WEIGHT_A,
                 config.FUSION_WEIGHT_S, config.FUSION_WEIGHT_R)
            )
        )
        S = config.SEVERITY_PRIORS.get(threat_class.lower(), config.SEVERITY_PRIORS.get(threat_class, 0.5))
        raw = w_P * p + w_A * a + w_S * S + w_R * r
        return int(round(min(100, max(0, raw * 100))))

    detection: Detection = detection_or_threat_class
    row = args[0] if len(args) > 0 else kwargs.get("row")
    reference_time = args[1] if len(args) > 1 else kwargs.get("reference_time")

    P = detection.confidence
    S = config.SEVERITY_PRIORS.get(detection.threat_class.lower(), config.SEVERITY_PRIORS.get(detection.threat_class, 0.5))

    # Anomaly score from Isolation Forest
    A = 0.0
    if row is not None:
        try:
            A = _get_anomaly_model().score(row)
        except Exception:
            A = 0.0

    # Recency
    R = compute_recency(detection.timestamp, reference_time)

    # Weighted sum → 0–100 using per-threat weights
    w_P, w_A, w_S, w_R = config.FUSION_PARAMS.get(
        detection.threat_class.lower(),
        config.FUSION_PARAMS.get(
            detection.threat_class,
            (config.FUSION_WEIGHT_P, config.FUSION_WEIGHT_A,
             config.FUSION_WEIGHT_S, config.FUSION_WEIGHT_R)
        )
    )
    raw = w_P * P + w_A * A + w_S * S + w_R * R
    risk_score = int(round(min(100, max(0, raw * 100))))
    risk_level = risk_level_from_score(risk_score)

    return Alert.from_detection(
        det=detection,
        risk_score=risk_score,
        risk_level=risk_level,
        anomaly_score=round(A, 4),
        recency=round(R, 4),
    )
