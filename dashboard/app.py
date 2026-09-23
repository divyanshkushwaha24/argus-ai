"""
Argus AI - Threat Intelligence Dashboard.

A minimal, professional telemetry dashboard:
- Crisp technical layout with clean typography (Inter and JetBrains Mono)
- Multi-view navigation: Live Telemetry, Session History, Detection Signatures
- Real-time auto-refresh and session archival controls
- Data persistence via PostgreSQL/SQLite history_logs and raw alerts tables
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime

# Add project root to path so imports work when running from dashboard/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd
import plotly.express as px

from db import (
    get_connection,
    create_alerts_table,
    get_recent_alerts,
    get_alert_stats,
    archive_and_reset_session,
    list_archived_sessions,
    get_archived_session,
    delete_archived_session,
    get_history_logs_from_db,
)

# ── Page config ──────────────────────────────────────────────────────
st.set_page_config(
    page_title="Argus - Threat Telemetry",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom Minimalist CSS ────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Hide sidebar completely */
    [data-testid="stSidebar"], section[data-testid="stSidebar"], div[data-testid="stSidebarCollapsedControl"] {
        display: none !important;
    }

    /* Global theme */
    .stApp {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        background-color: #f8fafc !important;
        color: #0f172a !important;
    }

    header[data-testid="stHeader"] {
        background: transparent !important;
    }

    .block-container {
        padding-top: 1.5rem !important;
        padding-bottom: 2rem !important;
        max-width: 96% !important;
    }

    h1, h2, h3, h4 {
        font-family: 'Inter', sans-serif !important;
        font-weight: 600 !important;
        letter-spacing: -0.02em !important;
        color: #0f172a !important;
    }

    p, span, label, .stMarkdown p {
        color: #475569;
    }

    code, pre, .mono-text {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Top Navigation Deck */
    .top-deck {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 4px;
        padding: 16px 20px;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    .brand-title {
        font-size: 1.15rem;
        font-weight: 700;
        letter-spacing: -0.01em;
        color: #0f172a;
        margin: 0;
        line-height: 1.2;
    }

    .brand-subtitle {
        font-size: 0.78rem;
        color: #64748b;
        margin-top: 2px;
        font-family: 'JetBrains Mono', monospace;
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 500;
        letter-spacing: 0.04em;
        border: 1px solid #e2e8f0;
        background: #f8fafc;
        color: #334155;
    }

    .status-indicator-live {
        width: 6px;
        height: 6px;
        border-radius: 1px;
        background-color: #16a34a;
    }

    .status-indicator-paused {
        width: 6px;
        height: 6px;
        border-radius: 1px;
        background-color: #94a3b8;
    }

    /* Minimalist KPI Cards */
    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 12px;
        margin-bottom: 16px;
    }

    .kpi-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 4px;
        padding: 14px 16px;
        position: relative;
    }

    .kpi-label {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.68rem;
        font-weight: 500;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 6px;
    }

    .kpi-value {
        font-family: 'Inter', sans-serif;
        font-size: 1.85rem;
        font-weight: 600;
        line-height: 1.1;
        letter-spacing: -0.02em;
        font-variant-numeric: tabular-nums;
    }

    .val-total    { color: #0f172a; }
    .val-critical { color: #dc2626; }
    .val-high     { color: #ea580c; }
    .val-medium   { color: #0284c7; }
    .val-sources  { color: #16a34a; }

    /* Section Headings */
    .section-title {
        font-family: 'Inter', sans-serif;
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #334155;
        margin: 16px 0 10px 0;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .section-num {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.68rem;
        color: #64748b;
        background: #f1f5f9;
        padding: 2px 6px;
        border-radius: 3px;
        border: 1px solid #e2e8f0;
    }

    /* Playbook Card */
    .doc-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 4px;
        padding: 16px;
        margin-bottom: 12px;
    }

    /* Strict button override: square/minimal radius */
    .stButton>button, div[data-testid="stBaseButton-primary"] button, div[data-testid="stBaseButton-secondary"] button {
        font-family: 'Inter', sans-serif !important;
        font-weight: 500 !important;
        font-size: 0.82rem !important;
        letter-spacing: 0.02em !important;
        border-radius: 4px !important;
        padding: 0.35rem 0.85rem !important;
        border: 1px solid #e2e8f0 !important;
        box-shadow: none !important;
    }

    /* Table styling */
    div[data-testid="stDataFrame"] {
        border-radius: 4px !important;
        border: 1px solid #e2e8f0 !important;
        background: #ffffff !important;
    }

    /* Footer bar */
    .footer-bar {
        margin-top: 36px;
        padding: 14px;
        border-top: 1px solid #e2e8f0;
        text-align: center;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        color: #64748b;
    }
</style>
""", unsafe_allow_html=True)


# ── Threat Colors & Helpers ──────────────────────────────────────────
THREAT_COLORS = {
    "ddos": "#dc2626",
    "DDOS": "#dc2626",
    "beacon": "#d97706",
    "c2_beaconing": "#d97706",
    "C2_BEACONING": "#d97706",
    "dns_tunnel": "#475569",
    "dga_dns_tunneling": "#475569",
    "DGA_DNS_TUNNELING": "#475569",
    "ja3_malware": "#ea580c",
    "encrypted_malware": "#ea580c",
    "ENCRYPTED_MALWARE": "#ea580c",
    "portscan": "#0284c7",
    "recon_port_scan": "#0284c7",
    "RECON_PORT_SCAN": "#0284c7",
    "exfil": "#16a34a",
    "data_exfiltration": "#16a34a",
    "DATA_EXFILTRATION": "#16a34a",
}


def format_evidence(evidence_str) -> str:
    """Safely format evidence from JSON, list, tuple, or string."""
    if not evidence_str:
        return ""
    try:
        if isinstance(evidence_str, str):
            ev = json.loads(evidence_str)
        else:
            ev = evidence_str
        if isinstance(ev, dict):
            reason = ev.get("reason", "")
            return reason if reason else str(ev)[:120]
        elif isinstance(ev, (list, tuple)):
            return "; ".join(str(x) for x in ev)[:120]
        return str(ev)[:120]
    except Exception:
        return str(evidence_str)[:120]


def render_kpi_cards(stats: dict):
    """Render top 5 metrics in minimal cards."""
    by_level = stats.get("by_risk_level", {})
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(f"""
        <div class="kpi-card" style="border-top: 2px solid #0f172a;">
            <div class="kpi-label">Total Events</div>
            <div class="kpi-value val-total">{stats.get('total_alerts', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="kpi-card" style="border-top: 2px solid #dc2626;">
            <div class="kpi-label">Critical</div>
            <div class="kpi-value val-critical">{by_level.get('CRITICAL', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="kpi-card" style="border-top: 2px solid #ea580c;">
            <div class="kpi-label">High Risk</div>
            <div class="kpi-value val-high">{by_level.get('HIGH', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="kpi-card" style="border-top: 2px solid #0284c7;">
            <div class="kpi-label">Medium Risk</div>
            <div class="kpi-value val-medium">{by_level.get('MEDIUM', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown(f"""
        <div class="kpi-card" style="border-top: 2px solid #16a34a;">
            <div class="kpi-label">Unique Sources</div>
            <div class="kpi-value val-sources">{stats.get('unique_source_ips', 0)}</div>
        </div>
        """, unsafe_allow_html=True)


def render_charts(df: pd.DataFrame, key_prefix: str = "live"):
    """Render threat distribution and risk score histogram with clean light styling."""
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown('<div class="section-title"><span class="section-num">01</span> Threat Distribution</div>',
                    unsafe_allow_html=True)
        if "threat_class" in df.columns and not df.empty:
            threat_counts = df["threat_class"].value_counts()
            fig = px.pie(
                values=threat_counts.values,
                names=threat_counts.index,
                color=threat_counts.index,
                color_discrete_map=THREAT_COLORS,
                hole=0.6,
            )
            fig.update_layout(
                paper_bgcolor="#ffffff",
                plot_bgcolor="#ffffff",
                font_color="#334155",
                font_family="Inter, -apple-system, sans-serif",
                margin=dict(t=15, b=15, l=15, r=15),
                height=280,
                legend=dict(
                    orientation="h",
                    y=-0.15,
                    font=dict(size=11, family="Inter, sans-serif", color="#475569"),
                ),
            )
            fig.update_traces(
                textposition='inside',
                textinfo='label+percent',
                insidetextfont=dict(family="JetBrains Mono, monospace", size=10, color="#ffffff"),
                marker=dict(line=dict(color='#ffffff', width=1.5)),
            )
            st.plotly_chart(fig, use_container_width=True, key=f"{key_prefix}_pie")

    with col_right:
        st.markdown('<div class="section-title"><span class="section-num">02</span> Risk Score Histogram</div>',
                    unsafe_allow_html=True)
        if "risk_score" in df.columns and not df.empty:
            fig = px.histogram(
                df, x="risk_score",
                nbins=20,
                color_discrete_sequence=["#0f172a"],
                labels={"risk_score": "Risk Score", "count": "Count"},
            )
            fig.update_layout(
                paper_bgcolor="#ffffff",
                plot_bgcolor="#ffffff",
                font_color="#334155",
                font_family="Inter, -apple-system, sans-serif",
                margin=dict(t=15, b=30, l=40, r=15),
                height=280,
                xaxis=dict(
                    gridcolor="#f1f5f9",
                    linecolor="#e2e8f0",
                    tickfont=dict(family="JetBrains Mono, monospace", size=10, color="#64748b"),
                    title_font=dict(family="Inter, sans-serif", size=11, color="#334155"),
                ),
                yaxis=dict(
                    gridcolor="#f1f5f9",
                    linecolor="#e2e8f0",
                    tickfont=dict(family="JetBrains Mono, monospace", size=10, color="#64748b"),
                    title_font=dict(family="Inter, sans-serif", size=11, color="#334155"),
                ),
                bargap=0.15,
            )
            st.plotly_chart(fig, use_container_width=True, key=f"{key_prefix}_hist")


def render_alerts_table(df: pd.DataFrame, key_prefix: str = "live"):
    """Render filterable alert event feed."""
    st.markdown('<div class="section-title"><span class="section-num">03</span> Event Feed</div>',
                unsafe_allow_html=True)

    filter_c1, filter_c2, filter_c3 = st.columns([1.5, 1.5, 2])

    with filter_c1:
        all_threats = sorted(df["threat_class"].dropna().unique().tolist()) if "threat_class" in df.columns else []
        selected_threats = st.multiselect(
            "Threat Vector",
            options=all_threats,
            default=[],
            placeholder="All Vectors",
            key=f"{key_prefix}_filter_threat",
        )

    with filter_c2:
        all_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        available_levels = [lvl for lvl in all_levels if "risk_level" in df.columns and lvl in df["risk_level"].values]
        selected_levels = st.multiselect(
            "Severity Level",
            options=available_levels,
            default=[],
            placeholder="All Levels",
            key=f"{key_prefix}_filter_level",
        )

    with filter_c3:
        search_ip = st.text_input(
            "Search IP",
            placeholder="Filter source or destination IP...",
            key=f"{key_prefix}_filter_ip",
        )

    filtered = df.copy()
    if selected_threats:
        filtered = filtered[filtered["threat_class"].isin(selected_threats)]
    if selected_levels and "risk_level" in filtered.columns:
        filtered = filtered[filtered["risk_level"].isin(selected_levels)]
    if search_ip:
        ip_mask = False
        if "src_ip" in filtered.columns:
            ip_mask |= filtered["src_ip"].astype(str).str.contains(search_ip, na=False)
        if "dest_ip" in filtered.columns:
            ip_mask |= filtered["dest_ip"].astype(str).str.contains(search_ip, na=False)
        filtered = filtered[ip_mask]

    display_cols = [
        "timestamp", "src_ip", "dest_ip", "threat_class",
        "confidence", "risk_score", "risk_level", "evidence", "explanation",
    ]
    display_cols = [c for c in display_cols if c in filtered.columns]

    if not filtered.empty:
        display_df = filtered[display_cols].copy()
        if "confidence" in display_df.columns:
            display_df["confidence"] = display_df["confidence"].apply(
                lambda x: f"{float(x):.2f}" if pd.notna(x) else ""
            )
        if "timestamp" in display_df.columns:
            display_df["timestamp"] = display_df["timestamp"].apply(
                lambda x: str(x)[:19] if x else ""
            )
        if "evidence" in display_df.columns:
            display_df["evidence"] = display_df["evidence"].apply(format_evidence)

        def highlight_risk(row):
            level = str(row.get("risk_level", "LOW")).upper()
            colors = {
                "CRITICAL": "background-color: #fee2e2; color: #991b1b; font-weight: 500;",
                "HIGH":     "background-color: #ffedd5; color: #9a3412; font-weight: 500;",
                "MEDIUM":   "background-color: #e0f2fe; color: #075985; font-weight: 500;",
                "LOW":      "background-color: #f0fdf4; color: #166534; font-weight: 500;",
            }
            return [colors.get(level, "")] * len(row)

        styled = display_df.style.apply(highlight_risk, axis=1)
        st.dataframe(styled, use_container_width=True, height=380)
        st.caption(f"Showing {len(filtered)} of {len(df)} recorded events")
    else:
        st.info("No events match the selected filters.")


def render_incidents_cluster(df: pd.DataFrame):
    """Render correlated incident groups."""
    if "incident_id" in df.columns and df["incident_id"].notna().any():
        valid_inc = df[df["incident_id"].notna() & (df["incident_id"] != "") & (df["incident_id"] != "None")]
        if not valid_inc.empty:
            st.markdown('<div class="section-title"><span class="section-num">04</span> Correlated Incidents</div>',
                        unsafe_allow_html=True)

            incidents = valid_inc.groupby("incident_id").agg({
                "src_ip": "first",
                "alert_id": "count",
                "risk_score": "max",
                "risk_level": "first",
                "threat_class": lambda x: ", ".join(sorted(set(str(v) for v in x if v))),
                "timestamp": ["min", "max"],
            }).reset_index()

            incidents.columns = [
                "Incident ID", "Source IP", "Events", "Peak Risk",
                "Severity", "Associated Vectors", "First Seen", "Last Seen",
            ]
            incidents = incidents.sort_values("Peak Risk", ascending=False)
            incidents["Incident ID"] = incidents["Incident ID"].apply(
                lambda x: str(x)[:8] + "..." if x else ""
            )
            st.dataframe(incidents, use_container_width=True, height=220)


# ── Main Application ─────────────────────────────────────────────────
def main():
    now_str = datetime.now().strftime("%H:%M:%S")

    # Initialize tables
    create_alerts_table()

    # Session State for View Navigation (live, history, intel)
    if "active_view" not in st.session_state:
        st.session_state["active_view"] = "live"
    if "auto_refresh" not in st.session_state:
        st.session_state["auto_refresh"] = True

    # ── Top Control Deck ─────────────────────────────────────────────
    st.markdown("""
    <div class="top-deck">
        <div>
            <div class="brand-title">ARGUS <span style="font-weight: 400; color: #64748b;">/ Threat Telemetry</span></div>
            <div class="brand-subtitle">Network anomaly detection and incident correlation</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Action Bar: Views & Controls
    nav_c1, nav_c2, nav_c3, ctrl_c1, ctrl_c2, ctrl_c3 = st.columns([1.5, 1.6, 1.8, 1.4, 1.8, 1.5])

    with nav_c1:
        is_live = st.session_state["active_view"] == "live"
        if st.button("Live Telemetry", key="btn_view_live", use_container_width=True, type="primary" if is_live else "secondary"):
            st.session_state["active_view"] = "live"
            st.rerun()

    with nav_c2:
        is_hist = st.session_state["active_view"] == "history"
        if st.button("Session History", key="btn_view_history", use_container_width=True, type="primary" if is_hist else "secondary"):
            st.session_state["active_view"] = "history"
            st.rerun()

    with nav_c3:
        is_intel = st.session_state["active_view"] == "intel"
        if st.button("Detection Signatures", key="btn_view_intel", use_container_width=True, type="primary" if is_intel else "secondary"):
            st.session_state["active_view"] = "intel"
            st.rerun()

    with ctrl_c1:
        if st.session_state["active_view"] == "live":
            auto_refresh = st.checkbox("Auto-refresh (2s)", value=st.session_state["auto_refresh"], key="auto_refresh_toggle")
            st.session_state["auto_refresh"] = auto_refresh
        else:
            st.markdown('<span style="font-size:0.75rem; color:#64748b; font-family:monospace; line-height:2.4;">Sync paused</span>', unsafe_allow_html=True)
            auto_refresh = False

    with ctrl_c2:
        if st.button("Snapshot Session", use_container_width=True, help="Archive active alerts to history_logs and reset live view"):
            archived = archive_and_reset_session(reason="manual_ui_snapshot")
            if archived:
                st.success(f"Archived {archived['total_alerts']} alerts to {archived['file_name']}.")
                time.sleep(1)
                st.rerun()
            else:
                st.info("No active alerts to archive.")

    with ctrl_c3:
        is_active = (st.session_state["active_view"] == "live" and st.session_state["auto_refresh"])
        indicator_class = "status-indicator-live" if is_active else "status-indicator-paused"
        status_label = f"SYNCED {now_str} UTC" if is_active else "PAUSED"
        st.markdown(f"""
        <div style="text-align: right; padding-top: 4px;">
            <span class="status-badge"><span class="{indicator_class}"></span> {status_label}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<hr style='border: none; border-top: 1px solid #e2e8f0; margin: 12px 0 16px 0;'>", unsafe_allow_html=True)

    # ── VIEW 1: LIVE TELEMETRY STREAM ─────────────────────────────────
    if st.session_state["active_view"] == "live":
        stats = get_alert_stats()
        alerts_raw = get_recent_alerts(limit=500)

        # KPI Metrics Cards
        render_kpi_cards(stats)
        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

        if alerts_raw:
            df = pd.DataFrame(alerts_raw)
            render_charts(df, key_prefix="live")
            st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
            render_alerts_table(df, key_prefix="live")
            render_incidents_cluster(df)
        else:
            st.markdown("""
            <div style="text-align: center; padding: 48px 24px; background: #ffffff; border-radius: 4px; border: 1px dashed #cbd5e1; margin-top: 16px;">
                <h4 style="margin: 0; color: #0f172a; font-size: 1rem;">No Active Telemetry</h4>
                <p style="color: #64748b; font-size: 0.85rem; max-width: 520px; margin: 8px auto 0 auto;">
                    Active threat database contains 0 events. Run <code>python run_realtime.py</code> in your terminal to start streaming network packets.
                </p>
            </div>
            """, unsafe_allow_html=True)

        # Status Footer
        st.markdown(f"""
        <div class="footer-bar">
            Argus Detection Engine | Database: Active | Synced: {now_str} UTC
        </div>
        """, unsafe_allow_html=True)

        # Auto-refresh loop
        if st.session_state["auto_refresh"]:
            time.sleep(2.0)
            st.rerun()

    # ── VIEW 2: HISTORICAL AUDIT LOGS ─────────────────────────────────
    elif st.session_state["active_view"] == "history":
        sessions = list_archived_sessions()

        if not sessions:
            st.markdown("""
            <div style="text-align: center; padding: 48px 24px; background: #ffffff; border-radius: 4px; border: 1px dashed #cbd5e1; margin-top: 16px;">
                <h4 style="margin: 0; color: #0f172a; font-size: 1rem;">No Archived Sessions Found</h4>
                <p style="color: #64748b; font-size: 0.85rem; max-width: 520px; margin: 8px auto 0 auto;">
                    Sessions are recorded into table <code>history_logs</code> and <code>data/history_logs/</code> whenever you restart <code>run_realtime.py</code> or click <b>Snapshot Session</b>.
                </p>
            </div>
            """, unsafe_allow_html=True)
        else:
            # 1. Database Table Overview: history_logs
            st.markdown('<div class="section-title"><span class="section-num">01</span> Session Archive (history_logs)</div>', unsafe_allow_html=True)

            summary_rows = []
            for s in sessions:
                by_threat = s.get("by_threat_class", {})
                threat_str = ", ".join(f"{k}: {v}" for k, v in by_threat.items()) if isinstance(by_threat, dict) else str(by_threat)
                by_risk = s.get("by_risk_level", {})
                risk_str = ", ".join(f"{k}: {v}" for k, v in by_risk.items()) if isinstance(by_risk, dict) else str(by_risk)

                summary_rows.append({
                    "Session ID": s.get("session_id"),
                    "Archived At (UTC)": str(s.get("archived_at", ""))[:19].replace("T", " "),
                    "Total Alerts": s.get("total_alerts", 0),
                    "Incidents": s.get("total_incidents", 0),
                    "Attackers": s.get("unique_source_ips", 0),
                    "Targets": s.get("unique_dest_ips", 0),
                    "Threat Vectors": threat_str,
                    "Risk Breakdown": risk_str,
                    "Reason": s.get("reason", "archive"),
                    "File Path": s.get("file_path") or f"data/history_logs/{s.get('file_name', '')}",
                })

            df_summary = pd.DataFrame(summary_rows)
            st.dataframe(df_summary, use_container_width=True, height=220)

            # Master file download actions
            master_c1, master_c2 = st.columns(2)
            with master_c1:
                st.download_button(
                    label="Download history_logs.csv",
                    data=df_summary.to_csv(index=False),
                    file_name="history_logs.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
            with master_c2:
                st.download_button(
                    label="Download history_logs.json",
                    data=json.dumps(sessions, indent=2, default=str),
                    file_name="history_logs.json",
                    mime="application/json",
                    use_container_width=True,
                )

            st.markdown("<hr style='border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;'>", unsafe_allow_html=True)

            # 2. Deep Session Forensic Inspector
            st.markdown('<div class="section-title"><span class="section-num">02</span> Session Details</div>', unsafe_allow_html=True)

            session_options = [s["session_id"] for s in sessions]

            def session_format_func(sid: str) -> str:
                s = next((item for item in sessions if item.get("session_id") == sid), None)
                if not s:
                    return sid
                arch_ts = str(s.get("archived_at", ""))[:19].replace("T", " ")
                tot = s.get("total_alerts", 0)
                by_lvl = s.get("by_risk_level", {})
                crit_high = (by_lvl.get("CRITICAL", 0) if isinstance(by_lvl, dict) else 0) + (by_lvl.get("HIGH", 0) if isinstance(by_lvl, dict) else 0)
                reason = s.get("reason", "archive")
                return f"{sid} ({arch_ts} UTC) | {tot} events [{crit_high} High/Crit] | {reason}"

            selected_sid = st.selectbox(
                "Select Archived Session:",
                options=session_options,
                format_func=session_format_func,
                key="historical_session_picker",
            )

            sess_payload = get_archived_session(selected_sid)
            if sess_payload:
                meta = sess_payload.get("metadata", {})
                hist_alerts = sess_payload.get("alerts", [])

                top_c1, top_c2, top_c3 = st.columns([2.2, 1.2, 1.2])

                with top_c1:
                    start_str = str(meta.get("start_time", ""))[:19]
                    end_str = str(meta.get("end_time", ""))[:19]
                    st.markdown(f"""
                    <div style="background: #ffffff; padding: 12px 16px; border-radius: 4px; border: 1px solid #e2e8f0; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #334155; line-height: 1.6;">
                        <span style="color:#0f172a; font-weight:600;">SESSION:</span> {meta.get('session_id')}<br>
                        <span style="color:#0f172a; font-weight:600;">ARCHIVED:</span> {str(meta.get('archived_at'))[:19].replace('T', ' ')} UTC<br>
                        <span style="color:#0f172a; font-weight:600;">WINDOW:</span> {start_str} to {end_str}<br>
                        <span style="color:#0f172a; font-weight:600;">REASON:</span> {meta.get('reason')} | <strong>FILE:</strong> data/history_logs/{meta.get('file_name', f'{selected_sid}.json')}
                    </div>
                    """, unsafe_allow_html=True)

                df_hist = pd.DataFrame(hist_alerts) if hist_alerts else pd.DataFrame()

                with top_c2:
                    st.download_button(
                        label="Download Session JSON",
                        data=json.dumps(sess_payload, indent=2, default=str),
                        file_name=f"{selected_sid}.json",
                        mime="application/json",
                        use_container_width=True,
                    )
                    if not df_hist.empty:
                        st.download_button(
                            label="Download Alerts CSV",
                            data=df_hist.to_csv(index=False),
                            file_name=f"{selected_sid}_alerts.csv",
                            mime="text/csv",
                            use_container_width=True,
                        )

                with top_c3:
                    with st.expander("Delete Session"):
                        st.caption("Permanently delete this archived session log?")
                        if st.button("Confirm Delete", type="primary", use_container_width=True, key=f"del_{selected_sid}"):
                            if delete_archived_session(selected_sid):
                                st.success("Session deleted successfully.")
                                time.sleep(1)
                                st.rerun()

                st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

                # Render Historical Analytics
                render_kpi_cards(meta)
                st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

                if not df_hist.empty:
                    render_charts(df_hist, key_prefix=f"hist_{selected_sid}")
                    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
                    render_alerts_table(df_hist, key_prefix=f"hist_{selected_sid}")
                    render_incidents_cluster(df_hist)
                else:
                    st.info("This session contains 0 alert records.")
            else:
                st.error("Failed to load archived session data.")

        # Bottom Status Footer
        st.markdown("""
        <div class="footer-bar">
            Argus Archive Store | Database: Connected
        </div>
        """, unsafe_allow_html=True)

    # ── VIEW 3: THREAT MATRIX & PLAYBOOKS ─────────────────────────────
    elif st.session_state["active_view"] == "intel":
        st.markdown('<div class="section-title"><span class="section-num">01</span> Detection Signatures &amp; Response Criteria</div>', unsafe_allow_html=True)

        vectors = [
            {
                "title": "DDoS Flood Detection",
                "tag": "ddos",
                "color": "#dc2626",
                "desc": "Detects high-volume distributed SYN, UDP, and ICMP floods by tracking flow rate z-scores and source-IP Shannon entropy.",
                "thresholds": "Rate z-score > 3.0 | IP Entropy > 4.5 bits | Sustained packet bursts",
                "action": "Trigger ingress rate-limiting and route malicious source subnets via Flowspec."
            },
            {
                "title": "C2 Periodic Beaconing",
                "tag": "beacon",
                "color": "#d97706",
                "desc": "Identifies Command-and-Control malware agents beaconing to external endpoints at fixed intervals with low jitter.",
                "thresholds": "Inter-arrival Interval CV < 0.20 | Min 5 pulses | Fixed payload sizes",
                "action": "Isolate host, capture volatile memory, and block destination IP/FQDN on perimeter firewall."
            },
            {
                "title": "DGA & DNS Tunneling",
                "tag": "dns_tunnel",
                "color": "#475569",
                "desc": "Flags DNS exfiltration tunnels and Domain Generation Algorithms (DGA) using character n-gram frequencies and query entropy.",
                "thresholds": "Subdomain Entropy > 3.8 | Length > 28 chars | TXT record payload anomalies",
                "action": "Sinkhole malicious domain at recursive resolver and inspect client query logs."
            },
            {
                "title": "Encrypted Malware / JA3 Fingerprint",
                "tag": "ja3_malware",
                "color": "#ea580c",
                "desc": "Classifies malicious TLS sessions via JA3 ClientHello fingerprinting matched against active threat intelligence and Random Forest TLS models.",
                "thresholds": "Known Cobalt Strike / Trickbot JA3 hashes | Self-signed cert | Cipher suite anomalies",
                "action": "Terminate active TLS sessions at gateway and dispatch endpoint containment."
            },
            {
                "title": "Reconnaissance Port Scans",
                "tag": "portscan",
                "color": "#0284c7",
                "desc": "Spots horizontal and vertical network reconnaissance scanners probing internal network boundaries.",
                "thresholds": "Unique Port Fanout > 15 ports in 30s | High SYN-to-ACK ratio",
                "action": "Quarantine source IP at switch access port and monitor for lateral traversal."
            },
            {
                "title": "Data Exfiltration Over TLS/HTTP",
                "tag": "exfil",
                "color": "#16a34a",
                "desc": "Uncovers data theft and abnormal egress volumes by calculating outbound/inbound byte ratios and duration anomalies.",
                "thresholds": "Egress Payload > 5 MB | Out/In Byte Ratio > 10:1 | Off-hours transmission",
                "action": "Sever external socket connection and notify security team for forensic audit."
            },
        ]

        pcol1, pcol2 = st.columns(2)
        for i, vec in enumerate(vectors):
            target_col = pcol1 if i % 2 == 0 else pcol2
            with target_col:
                st.markdown(f"""
                <div class="doc-card" style="border-left: 3px solid {vec['color']};">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-weight:600; font-size:0.95rem; color:#0f172a;">{vec['title']}</span>
                        <span style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; font-weight:600; color:{vec['color']}; background:#f8fafc; border:1px solid #e2e8f0; padding:2px 6px; border-radius:3px;">{vec['tag'].upper()}</span>
                    </div>
                    <p style="margin:8px 0; font-size:0.83rem; color:#475569; line-height:1.5;">{vec['desc']}</p>
                    <div style="font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:#334155; background:#f8fafc; border:1px solid #e2e8f0; padding:6px 8px; border-radius:3px; margin:8px 0;">
                        <span style="color:{vec['color']}; font-weight:500;">CRITERIA:</span> {vec['thresholds']}
                    </div>
                    <div style="font-size:0.78rem; color:#475569;">
                        <strong style="color:#0f172a;">Response Procedure:</strong> {vec['action']}
                    </div>
                </div>
                """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
