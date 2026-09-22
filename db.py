"""
Argus AI — Database layer.

Postgres helpers for alert storage.  The dashboard reads from here;
the pipeline writes to here.  This is the only coupling between them
(good for the read-only architecture story).

Falls back to SQLite if Postgres isn't available (local dev convenience).
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

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
            _conn = psycopg2.connect(config.POSTGRES_DSN, connect_timeout=2)
            _conn.autocommit = True
            return _conn
        except Exception:
            pass

    # SQLite fallback
    os.makedirs(os.path.dirname(SQLITE_PATH) or ".", exist_ok=True)
    _conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    return _conn


_table_initialized = False


def create_alerts_table():
    """Create the alerts table if it doesn't exist."""
    global _table_initialized
    if _table_initialized:
        return
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
        severity        TEXT,
        explanation     TEXT
    )
    """
    incidents_sql = """
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id     TEXT PRIMARY KEY,
        source_ip       TEXT NOT NULL,
        first_seen      TEXT,
        last_seen       TEXT,
        alert_count     INTEGER DEFAULT 0,
        combined_risk   INTEGER DEFAULT 0,
        risk_level      TEXT DEFAULT 'LOW',
        threat_classes  TEXT DEFAULT '[]',
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
    history_logs_sql = """
    CREATE TABLE IF NOT EXISTS history_logs (
        session_id        TEXT PRIMARY KEY,
        archived_at       TEXT,
        start_time        TEXT,
        end_time          TEXT,
        total_alerts      INTEGER DEFAULT 0,
        total_incidents   INTEGER DEFAULT 0,
        unique_source_ips INTEGER DEFAULT 0,
        unique_dest_ips   INTEGER DEFAULT 0,
        by_threat_class   TEXT DEFAULT '{}',
        by_risk_level     TEXT DEFAULT '{}',
        reason            TEXT,
        file_path         TEXT,
        alerts_json       TEXT,
        incidents_json    TEXT
    )
    """
    if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
        with conn.cursor() as cur:
            cur.execute(sql)
            cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS severity TEXT")
            cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS src_port INTEGER")
            cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dest_port INTEGER")
            cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS anomaly_score REAL")
            cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS severity_prior REAL")
            cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS recency REAL")
            cur.execute(incidents_sql)
            cur.execute(history_logs_sql)
    else:
        conn.execute(sql)
        try:
            cur = conn.execute("PRAGMA table_info(alerts)")
            cols = [r[1] for r in cur.fetchall()]
            if "severity" not in cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN severity TEXT")
        except Exception:
            pass
        conn.execute(incidents_sql)
        conn.execute(history_logs_sql)
        conn.commit()
    _table_initialized = True


def insert_alert(alert: Any):
    """Insert one alert into the database."""
    conn = get_connection()
    raw_evidence = getattr(alert, "evidence", None) if not isinstance(alert, dict) else alert.get("evidence")
    if isinstance(raw_evidence, (dict, list)):
        evidence_str = json.dumps(raw_evidence)
    else:
        evidence_str = str(raw_evidence or "")

    raw_risk = getattr(alert, "risk_level", None) if not isinstance(alert, dict) else alert.get("risk_level")
    if raw_risk is None:
        raw_risk = getattr(alert, "severity", None) if not isinstance(alert, dict) else alert.get("severity")
    if hasattr(raw_risk, "value"):
        raw_risk = raw_risk.value
    severity_val = str(raw_risk or "LOW").upper()

    def _get(field, alt=None, default=None):
        if isinstance(alert, dict):
            val = alert.get(field, alert.get(alt, default) if alt else default)
        else:
            val = getattr(alert, field, getattr(alert, alt, default) if alt else default)
        if hasattr(val, "value"):
            val = val.value
        return val

    aid = str(_get("alert_id", default=""))
    inc_id = _get("incident_id")
    if inc_id is not None:
        inc_id = str(inc_id)

    values = (
        aid,
        inc_id,
        _get("timestamp"),
        _get("flow_id"),
        _get("src_ip", "source_ip"),
        _get("src_port", "source_port"),
        _get("dest_ip"),
        _get("dest_port"),
        _get("threat_class"),
        _get("confidence"),
        evidence_str,
        _get("anomaly_score"),
        _get("severity_prior"),
        _get("recency"),
        _get("risk_score"),
        severity_val,
        severity_val,
        _get("explanation"),
    )

    if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts
                (alert_id, incident_id, timestamp, flow_id, src_ip, src_port,
                 dest_ip, dest_port, threat_class, confidence, evidence,
                 anomaly_score, severity_prior, recency, risk_score, risk_level,
                 severity, explanation)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (alert_id) DO NOTHING
            """, values)
    else:
        conn.execute("""
            INSERT OR IGNORE INTO alerts
            (alert_id, incident_id, timestamp, flow_id, src_ip, src_port,
             dest_ip, dest_port, threat_class, confidence, evidence,
             anomaly_score, severity_prior, recency, risk_score, risk_level,
             severity, explanation)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, values)
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


# ── Sessional Archival & History ──────────────────────────────────────
HISTORY_DIR = "data/history_logs"
ALT_HISTORY_DIR = "data/history"
INDEX_PATH = os.path.join(HISTORY_DIR, "sessions_index.json")
HISTORY_LOGS_FILE = os.path.join(HISTORY_DIR, "history_logs.json")
HISTORY_LOGS_CSV = os.path.join(HISTORY_DIR, "history_logs.csv")
ROOT_HISTORY_LOGS_FILE = "data/history_logs.json"


def _get_history_dir() -> str:
    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(ALT_HISTORY_DIR, exist_ok=True)
    return HISTORY_DIR


def clear_alerts():
    """Clear all alerts and incidents from active tables."""
    conn = get_connection()
    if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM alerts")
            cur.execute("DELETE FROM incidents")
    else:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM incidents")
        conn.commit()


def archive_and_reset_session(reason: str = "rerun_reset") -> Optional[Dict]:
    """
    Archives all active database alerts and incidents into:
    1. Database table `history_logs` (PostgreSQL and SQLite)
    2. Timestamped session file: data/history_logs/session_YYYYMMDD_HHMMSS.json
    3. Consolidated history log files:
       - data/history_logs/history_logs.json
       - data/history_logs/history_logs.csv
       - data/history_logs.json
    and clears the active alerts and incidents tables so threat counters start fresh from 0.

    Returns the session metadata dictionary if alerts were archived, or None if empty.
    """
    create_alerts_table()
    conn = get_connection()

    alerts_list: List[Dict] = []
    incidents_list: List[Dict] = []

    if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM alerts ORDER BY timestamp ASC")
            alerts_list = [dict(r) for r in cur.fetchall()]
            try:
                cur.execute("SELECT * FROM incidents ORDER BY created_at ASC")
                incidents_list = [dict(r) for r in cur.fetchall()]
            except Exception:
                incidents_list = []
    else:
        cur = conn.execute("SELECT * FROM alerts ORDER BY timestamp ASC")
        alerts_list = [dict(r) for r in cur.fetchall()]
        try:
            cur_inc = conn.execute("SELECT * FROM incidents")
            incidents_list = [dict(r) for r in cur_inc.fetchall()]
        except Exception:
            incidents_list = []

    if not alerts_list:
        return None

    now = datetime.now(timezone.utc)
    session_id = f"session_{now.strftime('%Y%m%d_%H%M%S')}"

    # Compute breakdown and summary statistics
    by_threat: Dict[str, int] = {}
    by_level: Dict[str, int] = {}
    src_ips = set()
    dst_ips = set()

    for a in alerts_list:
        tc = a.get("threat_class") or "unknown"
        by_threat[tc] = by_threat.get(tc, 0) + 1
        lvl = a.get("risk_level") or a.get("severity") or "LOW"
        by_level[lvl] = by_level.get(lvl, 0) + 1
        if a.get("src_ip"):
            src_ips.add(a["src_ip"])
        dest = a.get("dest_ip") or a.get("dst_ip")
        if dest:
            dst_ips.add(dest)

    first_ts = alerts_list[0].get("timestamp") or str(now)
    last_ts = alerts_list[-1].get("timestamp") or str(now)
    session_file_name = f"{session_id}.json"
    session_file_path = os.path.join(HISTORY_DIR, session_file_name)

    metadata = {
        "session_id": session_id,
        "archived_at": now.isoformat(),
        "start_time": str(first_ts),
        "end_time": str(last_ts),
        "total_alerts": len(alerts_list),
        "total_incidents": len(incidents_list),
        "by_threat_class": by_threat,
        "by_risk_level": by_level,
        "unique_source_ips": len(src_ips),
        "unique_dest_ips": len(dst_ips),
        "reason": reason,
        "file_name": session_file_name,
        "file_path": session_file_path,
    }

    session_payload = {
        "metadata": metadata,
        "alerts": alerts_list,
        "incidents": incidents_list,
    }

    # 1. Save to Database Table: history_logs
    try:
        alerts_json_str = json.dumps(alerts_list, default=str)
        incidents_json_str = json.dumps(incidents_list, default=str)
        by_threat_str = json.dumps(by_threat)
        by_level_str = json.dumps(by_level)

        if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO history_logs (
                        session_id, archived_at, start_time, end_time,
                        total_alerts, total_incidents, unique_source_ips, unique_dest_ips,
                        by_threat_class, by_risk_level, reason, file_path, alerts_json, incidents_json
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (session_id) DO UPDATE SET
                        total_alerts = EXCLUDED.total_alerts,
                        total_incidents = EXCLUDED.total_incidents,
                        alerts_json = EXCLUDED.alerts_json,
                        incidents_json = EXCLUDED.incidents_json
                """, (
                    session_id, now.isoformat(), str(first_ts), str(last_ts),
                    len(alerts_list), len(incidents_list), len(src_ips), len(dst_ips),
                    by_threat_str, by_level_str, reason, session_file_path,
                    alerts_json_str, incidents_json_str
                ))
            conn.commit()
        else:
            conn.execute("""
                INSERT OR REPLACE INTO history_logs (
                    session_id, archived_at, start_time, end_time,
                    total_alerts, total_incidents, unique_source_ips, unique_dest_ips,
                    by_threat_class, by_risk_level, reason, file_path, alerts_json, incidents_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                session_id, now.isoformat(), str(first_ts), str(last_ts),
                len(alerts_list), len(incidents_list), len(src_ips), len(dst_ips),
                by_threat_str, by_level_str, reason, session_file_path,
                alerts_json_str, incidents_json_str
            ))
            conn.commit()
    except Exception as exc:
        print(f"⚠️  Failed to persist to database table history_logs: {exc}")

    # 2. Save individual session JSON
    _get_history_dir()
    for dir_path in [HISTORY_DIR, ALT_HISTORY_DIR]:
        try:
            target_f = os.path.join(dir_path, session_file_name)
            with open(target_f, "w", encoding="utf-8") as f:
                json.dump(session_payload, f, indent=2, default=str)
        except Exception as exc:
            print(f"⚠️  Failed to write session archive {target_f}: {exc}")

    # 3. Update index files: sessions_index.json & history_logs.json
    try:
        index_entries = []
        if os.path.exists(INDEX_PATH):
            try:
                with open(INDEX_PATH, "r", encoding="utf-8") as f:
                    index_entries = json.load(f)
            except Exception:
                index_entries = []
        # Prepend new session
        index_entries = [metadata] + [e for e in index_entries if e.get("session_id") != session_id]

        for p in [INDEX_PATH, os.path.join(ALT_HISTORY_DIR, "sessions_index.json"), HISTORY_LOGS_FILE, ROOT_HISTORY_LOGS_FILE]:
            try:
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(index_entries, f, indent=2, default=str)
            except Exception:
                pass
    except Exception as exc:
        print(f"⚠️  Failed to update history index files: {exc}")

    # 4. Generate tabular overview CSV: data/history_logs/history_logs.csv
    try:
        import csv
        with open(HISTORY_LOGS_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "session_id", "archived_at", "total_alerts", "total_incidents",
                "unique_attackers", "unique_targets", "top_threats", "risk_breakdown", "reason", "file_path"
            ])
            for entry in index_entries:
                threats_s = "; ".join(f"{k}:{v}" for k, v in entry.get("by_threat_class", {}).items())
                risks_s = "; ".join(f"{k}:{v}" for k, v in entry.get("by_risk_level", {}).items())
                writer.writerow([
                    entry.get("session_id"),
                    entry.get("archived_at"),
                    entry.get("total_alerts", 0),
                    entry.get("total_incidents", 0),
                    entry.get("unique_source_ips", 0),
                    entry.get("unique_dest_ips", 0),
                    threats_s,
                    risks_s,
                    entry.get("reason"),
                    entry.get("file_path") or entry.get("file_name"),
                ])
    except Exception:
        pass

    # Clear active database tables
    clear_alerts()
    return metadata


def get_history_logs_from_db() -> List[Dict]:
    """Retrieve all rows from the database history_logs table."""
    create_alerts_table()
    conn = get_connection()
    try:
        if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT session_id, archived_at, start_time, end_time,
                           total_alerts, total_incidents, unique_source_ips, unique_dest_ips,
                           by_threat_class, by_risk_level, reason, file_path
                    FROM history_logs
                    ORDER BY archived_at DESC
                """)
                rows = [dict(r) for r in cur.fetchall()]
        else:
            cur = conn.execute("""
                SELECT session_id, archived_at, start_time, end_time,
                       total_alerts, total_incidents, unique_source_ips, unique_dest_ips,
                       by_threat_class, by_risk_level, reason, file_path
                FROM history_logs
                ORDER BY archived_at DESC
            """)
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]

        for r in rows:
            if isinstance(r.get("by_threat_class"), str):
                try:
                    r["by_threat_class"] = json.loads(r["by_threat_class"])
                except Exception:
                    pass
            if isinstance(r.get("by_risk_level"), str):
                try:
                    r["by_risk_level"] = json.loads(r["by_risk_level"])
                except Exception:
                    pass
        return rows
    except Exception as exc:
        print(f"⚠️  Failed to query history_logs table: {exc}")
        return []


def list_archived_sessions() -> List[Dict]:
    """Return all archived session metadata entries, latest first (queries DB table and files)."""
    # 1. Try querying the database history_logs table
    db_rows = get_history_logs_from_db()
    if db_rows:
        return db_rows

    # 2. Check JSON index files
    _get_history_dir()
    for idx_f in [INDEX_PATH, HISTORY_LOGS_FILE, ROOT_HISTORY_LOGS_FILE, os.path.join(ALT_HISTORY_DIR, "sessions_index.json")]:
        if os.path.exists(idx_f):
            try:
                with open(idx_f, "r", encoding="utf-8") as f:
                    entries = json.load(f)
                    if isinstance(entries, list) and len(entries) > 0:
                        return sorted(entries, key=lambda x: x.get("archived_at", ""), reverse=True)
            except Exception:
                pass

    # 3. Fallback: scan directory files
    sessions = []
    for d in [HISTORY_DIR, ALT_HISTORY_DIR]:
        if os.path.exists(d):
            for fname in os.listdir(d):
                if fname.startswith("session_") and fname.endswith(".json"):
                    fpath = os.path.join(d, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            meta = data.get("metadata")
                            if meta and meta.get("session_id") not in [s.get("session_id") for s in sessions]:
                                sessions.append(meta)
                    except Exception:
                        pass
    return sorted(sessions, key=lambda x: x.get("archived_at", ""), reverse=True)


def get_archived_session(session_id: str) -> Optional[Dict]:
    """Load full historical session data (metadata, alerts, incidents) by session_id."""
    # 1. Try files
    for d in [HISTORY_DIR, ALT_HISTORY_DIR]:
        session_file = os.path.join(d, f"{session_id}.json")
        if os.path.exists(session_file):
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

    # 2. Try DB history_logs table
    conn = get_connection()
    try:
        if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT alerts_json, incidents_json, by_threat_class, by_risk_level, * FROM history_logs WHERE session_id = %s", (session_id,))
                row = cur.fetchone()
        else:
            cur = conn.execute("SELECT alerts_json, incidents_json, by_threat_class, by_risk_level, * FROM history_logs WHERE session_id = ?", (session_id,))
            row = cur.fetchone()
            if row:
                cols = [d[0] for d in cur.description]
                row = dict(zip(cols, row))

        if row:
            alerts = json.loads(row["alerts_json"]) if isinstance(row.get("alerts_json"), str) else (row.get("alerts_json") or [])
            incidents = json.loads(row["incidents_json"]) if isinstance(row.get("incidents_json"), str) else (row.get("incidents_json") or [])
            meta = {k: v for k, v in row.items() if k not in ("alerts_json", "incidents_json")}
            return {"metadata": meta, "alerts": alerts, "incidents": incidents}
    except Exception as exc:
        print(f"⚠️  Failed to fetch archived session from DB: {exc}")

    return None


def delete_archived_session(session_id: str) -> bool:
    """Delete an archived session from database table history_logs and files."""
    # 1. Delete from DB table
    conn = get_connection()
    try:
        if HAS_POSTGRES and isinstance(conn, psycopg2.extensions.connection):
            with conn.cursor() as cur:
                cur.execute("DELETE FROM history_logs WHERE session_id = %s", (session_id,))
        else:
            conn.execute("DELETE FROM history_logs WHERE session_id = ?", (session_id,))
            conn.commit()
    except Exception:
        pass

    # 2. Delete files
    for d in [HISTORY_DIR, ALT_HISTORY_DIR]:
        session_file = os.path.join(d, f"{session_id}.json")
        if os.path.exists(session_file):
            try:
                os.remove(session_file)
            except OSError:
                pass

    # 3. Update indices
    for idx_f in [INDEX_PATH, os.path.join(ALT_HISTORY_DIR, "sessions_index.json"), HISTORY_LOGS_FILE, ROOT_HISTORY_LOGS_FILE]:
        if os.path.exists(idx_f):
            try:
                with open(idx_f, "r", encoding="utf-8") as f:
                    entries = json.load(f)
                entries = [e for e in entries if e.get("session_id") != session_id]
                with open(idx_f, "w", encoding="utf-8") as f:
                    json.dump(entries, f, indent=2, default=str)
            except Exception:
                pass
    return True

