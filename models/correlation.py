"""
Argus AI — Incident correlation (Stage 7b).

Groups alerts from the same source IP within a time window into
incidents.  Combines individual risk scores using noisy-OR:

  incident_risk = 1 − Π(1 − rᵢ)

Example: alert risks [0.40, 0.42, 0.50, 0.70]
  → 1 - (0.60 × 0.58 × 0.50 × 0.30)
  → 1 - 0.0522 = 0.9478 ≈ 95%

This matches the desired escalation story: isolated low-risk alerts
combine into a high-risk incident.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

import config
from models.alert_schema import Alert, risk_level_from_score


def correlate_alerts(alerts: List[Alert]) -> List[Alert]:
    """Group alerts by entity (dest_ip for DDoS, src_ip for others) with a 10-minute gap merge, apply noisy-OR.

    Modifies alerts in-place (sets incident_id) and returns them.
    """
    if not alerts:
        return alerts

    # ── Group by entity IP (dest_ip for DDoS, src_ip for others) ──────
    by_entity: Dict[str, List[Alert]] = defaultdict(list)
    for alert in alerts:
        is_ddos = str(alert.threat_class).strip().lower() in ("ddos", "dos", "volumetric_ddos", "flood")
        entity = (alert.dest_ip or alert.src_ip) if is_ddos else alert.src_ip
        by_entity[entity].append(alert)

    # ── Merge within time window ─────────────────────────────────────
    for entity_ip, group in by_entity.items():
        # Sort by timestamp
        group.sort(key=lambda a: a.timestamp)
        incidents = _split_into_incidents(group)

        for incident_alerts in incidents:
            incident_id = str(uuid.uuid4())
            # Compute combined risk via noisy-OR
            combined_risk = _noisy_or([a.risk_score / 100.0 for a in incident_alerts])
            combined_risk_int = int(round(combined_risk * 100))
            combined_level = risk_level_from_score(combined_risk_int)

            for alert in incident_alerts:
                alert.incident_id = incident_id

    return alerts


def _split_into_incidents(sorted_alerts: List[Alert]) -> List[List[Alert]]:
    """Split a time-sorted list of alerts into incidents.

    A new incident starts when the gap between consecutive alerts
    exceeds INCIDENT_GAP_MINUTES.
    """
    if not sorted_alerts:
        return []

    gap_sec = config.INCIDENT_GAP_MINUTES * 60
    incidents = [[sorted_alerts[0]]]

    for alert in sorted_alerts[1:]:
        prev_ts = _parse_ts(incidents[-1][-1].timestamp)
        curr_ts = _parse_ts(alert.timestamp)

        if prev_ts and curr_ts and (curr_ts - prev_ts).total_seconds() > gap_sec:
            # Gap too large — start a new incident
            incidents.append([alert])
        else:
            incidents[-1].append(alert)

    return incidents


def _noisy_or(risks: List[float]) -> float:
    """Noisy-OR combination: 1 − Π(1 − rᵢ).

    Each risk is clamped to [0, 1).
    """
    product = 1.0
    for r in risks:
        r_clamped = max(0.0, min(0.999, r))
        product *= (1.0 - r_clamped)
    return 1.0 - product


def _parse_ts(ts_str: str) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp string."""
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def get_incident_summary(alerts: List[Alert]) -> List[Dict]:
    """Summarize incidents for the dashboard.

    Returns a list of dicts, one per incident, with:
      incident_id, src_ip, alert_count, combined_risk, risk_level,
      first_seen, last_seen, threat_classes
    """
    by_incident: Dict[str, List[Alert]] = defaultdict(list)
    for alert in alerts:
        if alert.incident_id:
            by_incident[alert.incident_id].append(alert)

    summaries = []
    for inc_id, inc_alerts in by_incident.items():
        risks = [a.risk_score / 100.0 for a in inc_alerts]
        combined = _noisy_or(risks)
        combined_int = int(round(combined * 100))

        timestamps = [a.timestamp for a in inc_alerts]
        threat_classes = list(set(a.threat_class for a in inc_alerts))

        first_alert = inc_alerts[0]
        is_ddos = str(first_alert.threat_class).strip().lower() in ("ddos", "dos", "volumetric_ddos", "flood")
        entity_ip = (first_alert.dest_ip or first_alert.src_ip) if is_ddos else first_alert.src_ip

        summaries.append({
            "incident_id": inc_id,
            "src_ip": entity_ip,
            "alert_count": len(inc_alerts),
            "combined_risk": combined_int,
            "risk_level": risk_level_from_score(combined_int),
            "first_seen": min(timestamps),
            "last_seen": max(timestamps),
            "threat_classes": threat_classes,
        })

    summaries.sort(key=lambda x: x["combined_risk"], reverse=True)
    return summaries
