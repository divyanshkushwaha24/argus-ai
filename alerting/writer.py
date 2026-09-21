"""
Argus AI — PostgreSQL alert writer.

Stage 8 storage boundary.

This module is the ONLY module responsible for inserting alerts
and incidents into PostgreSQL.

Rules:
- Supports both validated Pydantic models (alerting.schema) and pipeline dict contracts.
- Implements write_alert() and upsert_incident() required by consumer.py sink resolution.
- Idempotent writes via ON CONFLICT clauses.
- No SQLite fallback happens here (handled cleanly at db.py / JsonlSink layer).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from typing import Any, Optional
from uuid import UUID

import psycopg2
from psycopg2.extensions import connection as PostgreSQLConnection

import config
from alerting.schema import Alert, Incident


def _get_connection() -> PostgreSQLConnection:
    """
    Create a PostgreSQL connection using the configured DSN.

    Raises
    ------
    RuntimeError
        If POSTGRES_DSN is not configured.
    psycopg2.Error
        If PostgreSQL cannot be reached.
    """
    if not config.POSTGRES_DSN:
        raise RuntimeError(
            "POSTGRES_DSN is not configured. "
            "Set it in the project's .env file."
        )

    return psycopg2.connect(config.POSTGRES_DSN)


def _coerce_uuid(val: Any) -> UUID:
    """Safely coerce any identifier to a valid UUID."""
    if isinstance(val, UUID):
        return val
    try:
        return UUID(str(val))
    except (ValueError, TypeError):
        return uuid.uuid5(uuid.NAMESPACE_DNS, str(val))


def write_alert(alert: Alert | Mapping[str, Any]) -> None:
    """
    Insert one Alert into PostgreSQL.

    Accepts either an alerting.schema.Alert instance or a validated dictionary
    from the streaming detection pipeline (consumer.py).
    """
    if isinstance(alert, Alert):
        alert_id = str(alert.alert_id)
        timestamp = alert.timestamp
        flow_id = alert.flow_id
        threat_class = alert.threat_class.value if hasattr(alert.threat_class, "value") else str(alert.threat_class)
        confidence = float(alert.confidence)
        risk_score = int(alert.risk_score)
        severity = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        evidence = json.dumps(alert.evidence)
        incident_id = str(alert.incident_id) if alert.incident_id is not None else None
        src_ip = None
        dest_ip = None
        risk_level = severity
        explanation = None
    elif isinstance(alert, Mapping):
        if not alert.get("alert_id"):
            raise ValueError("alert mapping requires an 'alert_id'")
        alert_id = str(_coerce_uuid(alert["alert_id"]))
        timestamp = alert.get("timestamp") or alert.get("event_time")
        flow_id = str(alert.get("flow_id", "unknown"))
        tc = str(alert.get("threat_class", "unknown")).lower()
        threat_class = tc
        confidence = float(alert.get("confidence", 0.0))
        risk_score = int(alert.get("risk_score", 0))
        severity = str(alert.get("severity") or alert.get("risk_level") or "LOW").upper()
        ev = alert.get("evidence", [])
        evidence = json.dumps(ev if isinstance(ev, (list, dict)) else [str(ev)])
        inc_raw = alert.get("incident_id")
        incident_id = str(_coerce_uuid(inc_raw)) if inc_raw else None
        src_ip = alert.get("src_ip")
        dest_ip = alert.get("dst_ip") or alert.get("dest_ip")
        risk_level = severity
        explanation = alert.get("explanation")
    else:
        raise TypeError("write_alert() requires an alerting.schema.Alert instance or Mapping")

    connection = None
    try:
        connection = _get_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO public.alerts (
                    alert_id,
                    timestamp,
                    flow_id,
                    threat_class,
                    confidence,
                    risk_score,
                    severity,
                    evidence,
                    incident_id,
                    src_ip,
                    dest_ip,
                    risk_level,
                    explanation
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                ON CONFLICT (alert_id) DO NOTHING
                """,
                (
                    alert_id,
                    timestamp,
                    flow_id,
                    threat_class,
                    confidence,
                    risk_score,
                    severity,
                    evidence,
                    incident_id,
                    src_ip,
                    dest_ip,
                    risk_level,
                    explanation,
                ),
            )
        connection.commit()
    except Exception:
        if connection is not None:
            connection.rollback()
        raise
    finally:
        if connection is not None:
            connection.close()


def write_alerts(alerts: list[Alert | Mapping[str, Any]]) -> None:
    """Insert multiple alerts in sequence."""
    for alert in alerts:
        write_alert(alert)


def upsert_incident(incident: Incident | Mapping[str, Any]) -> None:
    """
    Insert or update one Incident in PostgreSQL.

    Accepts either an alerting.schema.Incident instance or an incident dictionary
    from the streaming pipeline (IncidentCorrelator in consumer.py).
    """
    if isinstance(incident, Incident):
        inc_id = str(incident.incident_id)
        source_ip = str(incident.source_ip)
        first_seen = incident.first_seen
        last_seen = incident.last_seen
        alert_count = incident.alert_count
        combined_risk = incident.combined_risk
        risk_level = incident.risk_level.value if hasattr(incident.risk_level, "value") else str(incident.risk_level)
        threat_classes = json.dumps([t.value if hasattr(t, "value") else str(t) for t in incident.threat_classes])
    elif isinstance(incident, Mapping):
        if not incident.get("incident_id"):
            raise ValueError("incident mapping requires an 'incident_id'")
        inc_id = str(_coerce_uuid(incident["incident_id"]))
        source_ip = str(incident.get("src_ip") or incident.get("source_ip") or "0.0.0.0")
        first_seen = incident.get("first_seen")
        last_seen = incident.get("last_seen")
        alert_count = int(incident.get("alert_count", 1))
        combined_risk = int(incident.get("risk_score") or incident.get("combined_risk") or 0)
        risk_level = str(incident.get("severity") or incident.get("risk_level") or "LOW").upper()
        tc = incident.get("threat_classes", [])
        threat_classes = json.dumps(list(tc) if isinstance(tc, (list, set, tuple)) else [str(tc)])
    else:
        raise TypeError("upsert_incident() requires an alerting.schema.Incident instance or Mapping")

    connection = None
    try:
        connection = _get_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO public.incidents (
                    incident_id,
                    source_ip,
                    first_seen,
                    last_seen,
                    alert_count,
                    combined_risk,
                    risk_level,
                    threat_classes
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                ON CONFLICT (incident_id) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    alert_count = EXCLUDED.alert_count,
                    combined_risk = EXCLUDED.combined_risk,
                    risk_level = EXCLUDED.risk_level,
                    threat_classes = EXCLUDED.threat_classes,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    inc_id,
                    source_ip,
                    first_seen,
                    last_seen,
                    alert_count,
                    combined_risk,
                    risk_level,
                    threat_classes,
                ),
            )
        connection.commit()
    except Exception:
        if connection is not None:
            connection.rollback()
        raise
    finally:
        if connection is not None:
            connection.close()


def write_incident(incident: Incident | Mapping[str, Any]) -> None:
    """Insert or update one incident (alias for upsert_incident)."""
    upsert_incident(incident)


def write_incidents(incidents: list[Incident | Mapping[str, Any]]) -> None:
    """Insert or update multiple incidents in sequence."""
    for incident in incidents:
        upsert_incident(incident)