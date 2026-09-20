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
from typing import Optional

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


def fuse(detection: Detection, row=None, reference_time: Optional[datetime] = None) -> Alert:
    """Turn a Detection into a scored Alert.

    Parameters
    ----------
    detection : Detection
        Raw detector output.
    row : pd.Series, optional
        Original flow record (for anomaly scoring).
    reference_time : datetime, optional
        "Now" for recency computation.  Defaults to UTC now.
    """
    P = detection.confidence
    S = config.SEVERITY_PRIORS.get(detection.threat_class, 0.5)

    # Anomaly score from Isolation Forest
    A = 0.0
    if row is not None:
        try:
            A = _get_anomaly_model().score(row)
        except Exception:
            A = 0.0

    # Recency
    R = compute_recency(detection.timestamp, reference_time)

    # Weighted sum → 0–100
    raw = (
        config.FUSION_WEIGHT_P * P
        + config.FUSION_WEIGHT_A * A
        + config.FUSION_WEIGHT_S * S
        + config.FUSION_WEIGHT_R * R
    )
    risk_score = int(round(min(100, max(0, raw * 100))))
    risk_level = risk_level_from_score(risk_score)

    return Alert.from_detection(
        det=detection,
        risk_score=risk_score,
        risk_level=risk_level,
        anomaly_score=round(A, 4),
        recency=round(R, 4),
    )
