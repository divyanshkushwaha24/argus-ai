"""
Argus AI — PostgreSQL alert writer.

Stage 8 storage boundary.

This module is the ONLY module responsible for inserting alerts
and incidents into PostgreSQL.

Rules:
- Only validated Pydantic models from alerting.schema are accepted.
- No raw dictionaries are accepted.
- No table creation or schema modification happens here.
- No SQLite fallback happens here.
- Invalid objects are rejected before any database connection is made.
"""

from __future__ import annotations

import json

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


def write_alert(alert: Alert) -> None:
    """
    Insert one validated Alert into PostgreSQL.

    Parameters
    ----------
    alert:
        A validated alerting.schema.Alert instance.

    Raises
    ------
    TypeError
        If the supplied object is not an Alert.
    RuntimeError
        If PostgreSQL configuration is missing.
    psycopg2.Error
        If PostgreSQL rejects the operation.
    """

    # Validate the object BEFORE touching the database.
    if not isinstance(alert, Alert):
        raise TypeError(
            "write_alert() requires an alerting.schema.Alert instance"
        )

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
                    incident_id
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                ON CONFLICT (alert_id) DO NOTHING
                """,
                (
                    str(alert.alert_id),
                    alert.timestamp,
                    alert.flow_id,
                    alert.threat_class.value,
                    alert.confidence,
                    alert.risk_score,
                    alert.severity.value,
                    json.dumps(alert.evidence),
                    (
                        str(alert.incident_id)
                        if alert.incident_id is not None
                        else None
                    ),
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


def write_alerts(alerts: list[Alert]) -> None:
    """
    Insert multiple validated alerts in one PostgreSQL transaction.

    Validation is performed for the entire list before any database
    insertion begins. Therefore, an invalid alert prevents the batch
    from being partially written.

    Parameters
    ----------
    alerts:
        A list containing only alerting.schema.Alert instances.
    """

    # Validate the complete batch BEFORE opening a database connection.
    for alert in alerts:
        if not isinstance(alert, Alert):
            raise TypeError(
                "write_alerts() requires every item to be an "
                "alerting.schema.Alert instance"
            )

    if not alerts:
        return

    connection = None

    try:
        connection = _get_connection()

        with connection.cursor() as cursor:
            for alert in alerts:
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
                        incident_id
                    )
                    VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s
                    )
                    ON CONFLICT (alert_id) DO NOTHING
                    """,
                    (
                        str(alert.alert_id),
                        alert.timestamp,
                        alert.flow_id,
                        alert.threat_class.value,
                        alert.confidence,
                        alert.risk_score,
                        alert.severity.value,
                        json.dumps(alert.evidence),
                        (
                            str(alert.incident_id)
                            if alert.incident_id is not None
                            else None
                        ),
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


def write_incident(incident: Incident) -> None:
    """
    Insert one validated Incident into PostgreSQL.

    Parameters
    ----------
    incident:
        A validated alerting.schema.Incident instance.
    """

    # Validate before touching the database.
    if not isinstance(incident, Incident):
        raise TypeError(
            "write_incident() requires an alerting.schema.Incident instance"
        )

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
                ON CONFLICT (incident_id) DO NOTHING
                """,
                (
                    str(incident.incident_id),
                    str(incident.source_ip),
                    incident.first_seen,
                    incident.last_seen,
                    incident.alert_count,
                    incident.combined_risk,
                    incident.risk_level.value,
                    json.dumps(
                        [threat.value for threat in incident.threat_classes]
                    ),
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


def write_incidents(incidents: list[Incident]) -> None:
    """
    Insert multiple validated incidents in one PostgreSQL transaction.

    Validation is performed before any database insertion begins.
    """

    # Validate the complete batch first.
    for incident in incidents:
        if not isinstance(incident, Incident):
            raise TypeError(
                "write_incidents() requires every item to be an "
                "alerting.schema.Incident instance"
            )

    if not incidents:
        return

    connection = None

    try:
        connection = _get_connection()

        with connection.cursor() as cursor:
            for incident in incidents:
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
                    ON CONFLICT (incident_id) DO NOTHING
                    """,
                    (
                        str(incident.incident_id),
                        str(incident.source_ip),
                        incident.first_seen,
                        incident.last_seen,
                        incident.alert_count,
                        incident.combined_risk,
                        incident.risk_level.value,
                        json.dumps(
                            [threat.value for threat in incident.threat_classes]
                        ),
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