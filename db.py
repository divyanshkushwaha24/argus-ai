"""
Argus AI — Database layer.

Postgres helpers for alert storage.  The dashboard reads from here;
the pipeline writes to here.  This is the only coupling between them
(good for the read-only architecture story).

Falls back to SQLite if Postgres isn't available (local dev convenience).
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Dict, List, Optional

import config
from models.alert_schema import Alert

# Try Postgres first, fall back to SQLite
try:
    import psycopg2
    import psycopg2.extras
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

# SQLite fallback path
SQLITE_PATH = "data/alerts.db"

_conn = None


def get_connection():
    """Get a database connection (Postgres or SQLite fallback)."""
    global _conn
    if _conn is not None:
        return _conn

    if HAS_POSTGRES:
        try:
            _conn = psycopg2.connect(config.POSTGRES_DSN)
            _conn.autocommit = True
            return _conn
        except Exception:
            pass

    # SQLite fallback
    os.makedirs(os.path.dirname(SQLITE_PATH) or ".", exist_ok=True)
    _conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    return _conn


def create_alerts_table():
    """Create the alerts table if it doesn't exist."""
    conn = get_connection()
    sql = """
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id        TEXT PRIMARY KEY,
        incident_id     TEXT,
        timestamp       TEXT,
        flow_id         TEXT,
        src_ip          TEXT,
        src_port        INTEGER,
        dest_ip         TEXT,
        dest_port       INTEGER,
        threat_class    TEXT,
        confidence      REAL,
        evidence        TEXT,
        anomaly_score   REAL,
        severity_prior  REAL,
        recency         REAL,
        risk_score      INTEGER,
        risk_level      TEXT,
        explanation     TEXT
    )
    """
    if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
        with conn.cursor() as cur:
            cur.execute(sql)
    else:
        conn.execute(sql)
        conn.commit()


def insert_alert(alert: Alert):
    """Insert one alert into the database."""
    conn = get_connection()
    evidence_str = json.dumps(alert.evidence) if isinstance(alert.evidence, dict) else str(alert.evidence)

    if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts
                (alert_id, incident_id, timestamp, flow_id, src_ip, src_port,
                 dest_ip, dest_port, threat_class, confidence, evidence,
                 anomaly_score, severity_prior, recency, risk_score, risk_level,
                 explanation)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (alert_id) DO NOTHING
            """, (
                alert.alert_id, alert.incident_id, alert.timestamp,
                alert.flow_id, alert.src_ip, alert.src_port,
                alert.dest_ip, alert.dest_port, alert.threat_class,
                alert.confidence, evidence_str,
                alert.anomaly_score, alert.severity_prior, alert.recency,
                alert.risk_score, alert.risk_level, alert.explanation,
            ))
    else:
        conn.execute("""
            INSERT OR IGNORE INTO alerts
            (alert_id, incident_id, timestamp, flow_id, src_ip, src_port,
             dest_ip, dest_port, threat_class, confidence, evidence,
             anomaly_score, severity_prior, recency, risk_score, risk_level,
             explanation)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            alert.alert_id, alert.incident_id, alert.timestamp,
            alert.flow_id, alert.src_ip, alert.src_port,
            alert.dest_ip, alert.dest_port, alert.threat_class,
            alert.confidence, evidence_str,
            alert.anomaly_score, alert.severity_prior, alert.recency,
            alert.risk_score, alert.risk_level, alert.explanation,
        ))
        conn.commit()


def insert_alerts_batch(alerts: List[Alert]):
    """Insert multiple alerts."""
    for alert in alerts:
        insert_alert(alert)


def get_recent_alerts(limit: int = 200) -> List[Dict]:
    """Fetch the most recent alerts for the dashboard."""
    conn = get_connection()

    if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT %s", (limit,)
            )
            return cur.fetchall()
    else:
        cur = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = cur.fetchall()
        return [dict(r) for r in rows]


def get_alert_stats() -> Dict:
    """Get summary statistics for the dashboard KPI cards."""
    conn = get_connection()

    if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*) as total FROM alerts")
            total = cur.fetchone()["total"]
            cur.execute("SELECT risk_level, COUNT(*) as cnt FROM alerts GROUP BY risk_level")
            by_level = {r["risk_level"]: r["cnt"] for r in cur.fetchall()}
            cur.execute("SELECT threat_class, COUNT(*) as cnt FROM alerts GROUP BY threat_class")
            by_threat = {r["threat_class"]: r["cnt"] for r in cur.fetchall()}
            cur.execute("SELECT COUNT(DISTINCT src_ip) as unique_sources FROM alerts")
            unique_sources = cur.fetchone()["unique_sources"]
    else:
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_level = {}
        for row in conn.execute("SELECT risk_level, COUNT(*) FROM alerts GROUP BY risk_level").fetchall():
            by_level[row[0]] = row[1]
        by_threat = {}
        for row in conn.execute("SELECT threat_class, COUNT(*) FROM alerts GROUP BY threat_class").fetchall():
            by_threat[row[0]] = row[1]
        unique_sources = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM alerts").fetchone()[0]

    return {
        "total_alerts": total,
        "by_risk_level": by_level,
        "by_threat_class": by_threat,
        "unique_source_ips": unique_sources,
    }


def clear_alerts():
    """Clear all alerts (for re-running pipeline)."""
    conn = get_connection()
    if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM alerts")
    else:
        conn.execute("DELETE FROM alerts")
        conn.commit()
