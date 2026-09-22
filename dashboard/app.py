"""
Argus AI — Real-Time Threat Intelligence & SOC Dashboard.

A high-fidelity cybersecurity operations center dashboard featuring:
- Full-bleed dark cyber-defense aesthetic (deep obsidian, neon cyans, cyber crimson, glowing accents)
- Seamless top navigation (🔴 Live Telemetry, 📜 Historical Audit Logs, 🛡️ Threat Matrix & Playbooks)
- Zero-clutter header control deck (live auto-refresh toggle, session snapshot, real-time pulse beacon)
- Dual-mode operation: real-time streaming telemetry and comprehensive historical session inspection
- Direct access to PostgreSQL/SQLite `history_logs` table, JSON/CSV exports, and forensics
"""

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
    page_title="Argus AI // Cyber Defense SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS for High-Tech Cyber SOC Theme ─────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');

    /* 1. HIDE DULL SIDEBAR COMPLETELY */
    [data-testid="stSidebar"], section[data-testid="stSidebar"], div[data-testid="stSidebarCollapsedControl"] {
        display: none !important;
    }

    /* 2. Global Cyber Dark Theme */
    .stApp {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        background: radial-gradient(circle at 50% 0%, #0d1527 0%, #070a13 70%, #05070c 100%) !important;
        color: #e2e8f0 !important;
    }

    header[data-testid="stHeader"] {
        background: transparent !important;
    }

    .block-container {
        padding-top: 1.2rem !important;
        padding-bottom: 2rem !important;
        max-width: 96% !important;
    }

    h1, h2, h3, h4, .main-header h1, .section-header {
        font-family: 'Space Grotesk', sans-serif !important;
        letter-spacing: -0.02em;
        color: #f8fafc !important;
    }

    p, span, label, .stMarkdown p {
        color: #94a3b8;
    }

    code, pre, .mono-text {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* 3. Top Cyber Navbar & Control Deck */
    .soc-nav-card {
        background: rgba(15, 23, 42, 0.75);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 12px 20px;
        margin-bottom: 18px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    .soc-brand {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .soc-logo-icon {
        font-size: 1.8rem;
        filter: drop-shadow(0 0 10px rgba(0, 242, 254, 0.6));
    }

    .soc-title {
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 700;
        font-size: 1.35rem;
        letter-spacing: -0.02em;
        background: linear-gradient(135deg, #ffffff 30%, #38bdf8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        line-height: 1.1;
    }

    .soc-subtitle {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.7rem;
        color: #00f2fe;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        margin-top: 2px;
    }

    .status-beacon {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 4px 12px;
        border-radius: 9999px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.06em;
        text-transform: uppercase;
    }

    .beacon-live {
        background: rgba(16, 185, 129, 0.12);
        color: #34d399;
        border: 1px solid rgba(52, 211, 153, 0.3);
        box-shadow: 0 0 12px rgba(52, 211, 153, 0.2);
    }

    .beacon-paused {
        background: rgba(245, 158, 11, 0.12);
        color: #fbbf24;
        border: 1px solid rgba(251, 191, 36, 0.3);
    }

    .pulse-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #10b981;
        box-shadow: 0 0 8px #10b981;
        animation: pulse 1.5s infinite;
    }

    @keyframes pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1.1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    /* 4. Futuristic Glassmorphism KPI Cards */
    .kpi-deck {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 14px;
        margin-bottom: 20px;
    }

    .cyber-card {
        background: rgba(15, 23, 42, 0.65);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.07);
        border-radius: 10px;
        padding: 16px 18px;
        position: relative;
        overflow: hidden;
        transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
    }

    .cyber-card:hover {
        transform: translateY(-2px);
        border-color: rgba(56, 189, 248, 0.3);
        box-shadow: 0 6px 20px -2px rgba(0, 0, 0, 0.5);
    }

    .cyber-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
    }

    .card-total::before    { background: linear-gradient(90deg, #38bdf8, #00f2fe); }
    .card-critical::before { background: linear-gradient(90deg, #f43f5e, #ff0055); }
    .card-high::before     { background: linear-gradient(90deg, #fb923c, #f97316); }
    .card-medium::before   { background: linear-gradient(90deg, #38bdf8, #0284c7); }
    .card-sources::before  { background: linear-gradient(90deg, #34d399, #10b981); }

    .kpi-title {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 600;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 6px;
    }

    .kpi-num {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 2.2rem;
        font-weight: 700;
        line-height: 1;
        letter-spacing: -0.02em;
    }

    .num-total    { color: #f8fafc; }
    .num-critical { color: #ff3366; text-shadow: 0 0 16px rgba(255, 51, 102, 0.4); }
    .num-high     { color: #fb923c; text-shadow: 0 0 16px rgba(251, 146, 60, 0.3); }
    .num-medium   { color: #38bdf8; text-shadow: 0 0 16px rgba(56, 189, 248, 0.3); }
    .num-sources  { color: #34d399; text-shadow: 0 0 16px rgba(52, 211, 153, 0.3); }

    /* 5. Section Headers */
    .section-header {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 0.95rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        color: #f1f5f9;
        margin-top: 14px;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .section-tag {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.68rem;
        font-weight: 700;
        color: #00f2fe;
        background: rgba(0, 242, 254, 0.1);
        padding: 3px 8px;
        border-radius: 4px;
        border: 1px solid rgba(0, 242, 254, 0.25);
    }

    /* 6. Threat Playbook Card */
    .playbook-card {
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 12px;
    }

    /* Streamlit widget overrides for high-contrast dark theme */
    div[data-testid="stDataFrame"] {
        border-radius: 8px;
        overflow: hidden;
        border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .stButton>button {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        letter-spacing: 0.02em;
        border-radius: 8px;
        transition: all 0.2s ease;
    }
</style>
""", unsafe_allow_html=True)


# ── Threat Palette & Helper Functions ────────────────────────────────
THREAT_COLORS = {
    "ddos": "#ff3366",
    "DDOS": "#ff3366",
    "beacon": "#f59e0b",
    "c2_beaconing": "#f59e0b",
    "C2_BEACONING": "#f59e0b",
    "dns_tunnel": "#a855f7",
    "dga_dns_tunneling": "#a855f7",
    "DGA_DNS_TUNNELING": "#a855f7",
    "ja3_malware": "#f97316",
    "encrypted_malware": "#f97316",
    "ENCRYPTED_MALWARE": "#f97316",
    "portscan": "#00f2fe",
    "recon_port_scan": "#00f2fe",
    "RECON_PORT_SCAN": "#00f2fe",
    "exfil": "#10b981",
    "data_exfiltration": "#10b981",
    "DATA_EXFILTRATION": "#10b981",
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
    """Render top 5 high-impact cybersecurity KPI cards."""
    by_level = stats.get("by_risk_level", {})
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(f"""
        <div class="cyber-card card-total">
            <div class="kpi-title">TOTAL THREATS</div>
            <div class="kpi-num num-total">{stats.get('total_alerts', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="cyber-card card-critical">
            <div class="kpi-title">CRITICAL SEVERITY</div>
            <div class="kpi-num num-critical">{by_level.get('CRITICAL', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="cyber-card card-high">
            <div class="kpi-title">HIGH RISK</div>
            <div class="kpi-num num-high">{by_level.get('HIGH', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="cyber-card card-medium">
            <div class="kpi-title">MEDIUM RISK</div>
            <div class="kpi-num num-medium">{by_level.get('MEDIUM', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown(f"""
        <div class="cyber-card card-sources">
            <div class="kpi-title">UNIQUE ATTACKERS</div>
            <div class="kpi-num num-sources">{stats.get('unique_source_ips', 0)}</div>
        </div>
        """, unsafe_allow_html=True)


def render_charts(df: pd.DataFrame, key_prefix: str = "live"):
    """Render threat distribution donut chart and risk score histogram with cyber dark theme."""
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown('<div class="section-header"><span class="section-tag">01 // TELEMETRY</span> Threat Vector Distribution</div>',
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
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#cbd5e1",
                font_family="JetBrains Mono, monospace",
                margin=dict(t=10, b=10, l=10, r=10),
                height=290,
                legend=dict(
                    orientation="h",
                    y=-0.15,
                    font=dict(size=11, family="JetBrains Mono, monospace", color="#cbd5e1"),
                ),
            )
            fig.update_traces(
                textposition='inside',
                textinfo='label+percent',
                insidetextfont=dict(family="JetBrains Mono, monospace", size=11, color="#ffffff"),
                marker=dict(line=dict(color='#0b0f19', width=2)),
            )
            st.plotly_chart(fig, use_container_width=True, key=f"{key_prefix}_pie")

    with col_right:
        st.markdown('<div class="section-header"><span class="section-tag">02 // SPECTRUM</span> Threat Severity Spectrum</div>',
                    unsafe_allow_html=True)
        if "risk_score" in df.columns and not df.empty:
            fig = px.histogram(
                df, x="risk_score",
                nbins=20,
                color_discrete_sequence=["#ff0055"],
                labels={"risk_score": "CALIBRATED RISK SCORE", "count": "THREAT FREQUENCY"},
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#cbd5e1",
                font_family="JetBrains Mono, monospace",
                margin=dict(t=10, b=30, l=40, r=10),
                height=290,
                xaxis=dict(
                    gridcolor="rgba(255, 255, 255, 0.06)",
                    tickfont=dict(family="JetBrains Mono, monospace", size=10, color="#94a3b8"),
                    title_font=dict(family="JetBrains Mono, monospace", size=10, color="#cbd5e1"),
                ),
                yaxis=dict(
                    gridcolor="rgba(255, 255, 255, 0.06)",
                    tickfont=dict(family="JetBrains Mono, monospace", size=10, color="#94a3b8"),
                    title_font=dict(family="JetBrains Mono, monospace", size=10, color="#cbd5e1"),
                ),
                bargap=0.15,
            )
            st.plotly_chart(fig, use_container_width=True, key=f"{key_prefix}_hist")


def render_alerts_table(df: pd.DataFrame, key_prefix: str = "live"):
    """Render filterable and styled cyber alert stream."""
    st.markdown('<div class="section-header"><span class="section-tag">03 // STREAM</span> Live Threat Telemetry Feed</div>',
                unsafe_allow_html=True)

    filter_c1, filter_c2, filter_c3 = st.columns([1.5, 1.5, 2])

    with filter_c1:
        all_threats = sorted(df["threat_class"].dropna().unique().tolist()) if "threat_class" in df.columns else []
        selected_threats = st.multiselect(
            "Threat Vector Filter",
            options=all_threats,
            default=[],
            placeholder="All Vectors (DDoS, Beacon, Scan, etc.)",
            key=f"{key_prefix}_filter_threat",
        )

    with filter_c2:
        all_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        available_levels = [lvl for lvl in all_levels if "risk_level" in df.columns and lvl in df["risk_level"].values]
        selected_levels = st.multiselect(
            "Severity Filter",
            options=available_levels,
            default=[],
            placeholder="All Severities",
            key=f"{key_prefix}_filter_level",
        )

    with filter_c3:
        search_ip = st.text_input(
            "IP Address Quick Filter",
            placeholder="Search attacker or destination IP...",
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
                "CRITICAL": "background-color: rgba(239, 68, 68, 0.2); color: #fca5a5; font-weight: 600;",
                "HIGH":     "background-color: rgba(249, 115, 22, 0.2); color: #fdba74; font-weight: 600;",
                "MEDIUM":   "background-color: rgba(14, 165, 233, 0.2); color: #7dd3fc; font-weight: 600;",
                "LOW":      "background-color: rgba(16, 185, 129, 0.2); color: #86efac; font-weight: 600;",
            }
            return [colors.get(level, "")] * len(row)

        styled = display_df.style.apply(highlight_risk, axis=1)
        st.dataframe(styled, use_container_width=True, height=380)
        st.caption(f"Displaying {len(filtered)} of {len(df)} ingested threat signals")
    else:
        st.info("No threat alerts match your current filter criteria.")


def render_incidents_cluster(df: pd.DataFrame):
    """Render correlated multi-stage incident clusters."""
    if "incident_id" in df.columns and df["incident_id"].notna().any():
        valid_inc = df[df["incident_id"].notna() & (df["incident_id"] != "") & (df["incident_id"] != "None")]
        if not valid_inc.empty:
            st.markdown('<div class="section-header"><span class="section-tag">04 // ATTACK GRAPHS</span> Correlated Incident Campaigns</div>',
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
                "Incident ID", "Attacker IP", "Alert Volume", "Peak Risk",
                "Severity", "Associated Threats", "First Active", "Last Active",
            ]
            incidents = incidents.sort_values("Peak Risk", ascending=False)
            incidents["Incident ID"] = incidents["Incident ID"].apply(
                lambda x: str(x)[:8] + "..." if x else ""
            )
            st.dataframe(incidents, use_container_width=True, height=220)


# ── Main Dashboard Application ───────────────────────────────────────
def main():
    now_str = datetime.now().strftime("%H:%M:%S")

    # Initialize tables
    create_alerts_table()

    # Session State for View Navigation (live, history, intel)
    if "active_view" not in st.session_state:
        st.session_state["active_view"] = "live"
    if "auto_refresh" not in st.session_state:
        st.session_state["auto_refresh"] = True

    # ── TOP CONTROL DECK & NAVIGATION BAR ─────────────────────────────
    st.markdown("""
    <div class="soc-nav-card">
        <div class="soc-brand">
            <span class="soc-logo-icon">🛡️</span>
            <div>
                <div class="soc-title">ARGUS AI <span style="font-weight: 300; opacity: 0.8;">// CYBER DEFENSE SOC</span></div>
                <div class="soc-subtitle">Zero-Intrusion Streaming Detection &bull; Calibrated Bayesian Risk Engine</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Clean Top Action Bar: View Switchers + Controls
    nav_c1, nav_c2, nav_c3, ctrl_c1, ctrl_c2, ctrl_c3 = st.columns([1.6, 1.8, 1.8, 1.4, 1.8, 1.6])

    with nav_c1:
        is_live = st.session_state["active_view"] == "live"
        if st.button("🔴 LIVE TELEMETRY", key="btn_view_live", use_container_width=True, type="primary" if is_live else "secondary"):
            st.session_state["active_view"] = "live"
            st.rerun()

    with nav_c2:
        is_hist = st.session_state["active_view"] == "history"
        if st.button("📜 HISTORY LOGS", key="btn_view_history", use_container_width=True, type="primary" if is_hist else "secondary"):
            st.session_state["active_view"] = "history"
            st.rerun()

    with nav_c3:
        is_intel = st.session_state["active_view"] == "intel"
        if st.button("🛡️ THREAT MATRIX", key="btn_view_intel", use_container_width=True, type="primary" if is_intel else "secondary"):
            st.session_state["active_view"] = "intel"
            st.rerun()

    with ctrl_c1:
        if st.session_state["active_view"] == "live":
            auto_refresh = st.checkbox("⚡ Auto-Sync (2s)", value=st.session_state["auto_refresh"], key="auto_refresh_toggle")
            st.session_state["auto_refresh"] = auto_refresh
        else:
            st.markdown('<span style="font-size:0.75rem; color:#64748b; font-family:monospace; line-height:2.4;">⏸️ Auto-Sync Halted</span>', unsafe_allow_html=True)
            auto_refresh = False

    with ctrl_c2:
        if st.button("💾 Snapshot Session", use_container_width=True, help="Archive current active alerts to history_logs and reset live counters to 0"):
            archived = archive_and_reset_session(reason="manual_ui_snapshot")
            if archived:
                st.success(f"Archived {archived['total_alerts']} alerts to {archived['file_name']}!")
                time.sleep(1)
                st.rerun()
            else:
                st.info("No active alerts to archive.")

    with ctrl_c3:
        pulse_class = "beacon-live" if (st.session_state["active_view"] == "live" and st.session_state["auto_refresh"]) else "beacon-paused"
        pulse_icon = '<div class="pulse-dot"></div>' if (st.session_state["active_view"] == "live" and st.session_state["auto_refresh"]) else '<span>⏸️</span>'
        pulse_text = f"PULSE {now_str}" if (st.session_state["active_view"] == "live" and st.session_state["auto_refresh"]) else "STANDBY"
        st.markdown(f"""
        <div style="text-align: right; padding-top: 4px;">
            <span class="status-beacon {pulse_class}">{pulse_icon} {pulse_text}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<hr style='border: none; border-top: 1px solid rgba(255,255,255,0.08); margin: 12px 0 20px 0;'>", unsafe_allow_html=True)

    # ── VIEW 1: LIVE TELEMETRY STREAM ─────────────────────────────────
    if st.session_state["active_view"] == "live":
        stats = get_alert_stats()
        alerts_raw = get_recent_alerts(limit=500)

        # 5 High-Impact KPI Cards
        render_kpi_cards(stats)
        st.markdown("<br>", unsafe_allow_html=True)

        if alerts_raw:
            df = pd.DataFrame(alerts_raw)
            render_charts(df, key_prefix="live")
            st.markdown("<br>", unsafe_allow_html=True)
            render_alerts_table(df, key_prefix="live")
            render_incidents_cluster(df)
        else:
            st.markdown("""
            <div style="text-align: center; padding: 60px 24px; background: rgba(15, 23, 42, 0.4); border-radius: 12px; border: 1px dashed rgba(255, 255, 255, 0.1); margin-top: 16px;">
                <span style="font-size: 2.8rem;">📡</span>
                <h3 style="margin-top: 14px; color: #f8fafc;">Live Sessional Ingestion Ready</h3>
                <p style="color: #94a3b8; font-size: 0.95rem; max-width: 620px; margin: 8px auto;">
                    Active threat database is currently clean at 0 alerts. Run <code>python run_realtime.py</code> in your terminal to begin streaming real-time network traffic.
                </p>
            </div>
            """, unsafe_allow_html=True)

        # Bottom Status Footer
        st.markdown(f"""
        <div style="margin-top: 40px; padding: 16px; border-top: 1px solid rgba(255,255,255,0.06); text-align: center; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #64748b;">
            ARGUS AI // DEFENSE ENCLAVE &bull; PASSIVE INGESTION RUNTIME &bull; LAST PULSE: {now_str} UTC
        </div>
        """, unsafe_allow_html=True)

        # Live Auto-Refresh Loop (ONLY runs on Live tab)
        if st.session_state["auto_refresh"]:
            time.sleep(2.0)
            st.rerun()

    # ── VIEW 2: HISTORICAL AUDIT LOGS ─────────────────────────────────
    elif st.session_state["active_view"] == "history":
        sessions = list_archived_sessions()

        if not sessions:
            st.markdown("""
            <div style="text-align: center; padding: 60px 24px; background: rgba(15, 23, 42, 0.4); border-radius: 12px; border: 1px dashed rgba(255, 255, 255, 0.1); margin-top: 16px;">
                <span style="font-size: 2.8rem;">📭</span>
                <h3 style="margin-top: 14px; color: #f8fafc;">No Archived Sessions Found</h3>
                <p style="color: #94a3b8; font-size: 0.95rem; max-width: 620px; margin: 8px auto;">
                    Sessions are automatically archived into database table <code>history_logs</code> and <code>data/history_logs/</code> whenever you stop or restart <code>run_realtime.py</code> or click <b>"Snapshot Session"</b>.
                </p>
            </div>
            """, unsafe_allow_html=True)
        else:
            # 1. Database Table Overview: history_logs
            st.markdown('<div class="section-header"><span class="section-tag">01 // DATABASE TABLE</span> PostgreSQL / SQLite Table `history_logs`</div>', unsafe_allow_html=True)

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
                    label="📥 Download Master history_logs.csv",
                    data=df_summary.to_csv(index=False),
                    file_name="history_logs.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
            with master_c2:
                st.download_button(
                    label="📥 Download Master history_logs.json",
                    data=json.dumps(sessions, indent=2, default=str),
                    file_name="history_logs.json",
                    mime="application/json",
                    use_container_width=True,
                )

            st.markdown("<hr style='border: none; border-top: 1px solid rgba(255,255,255,0.08); margin: 24px 0;'>", unsafe_allow_html=True)

            # 2. Deep Session Forensic Inspector
            st.markdown('<div class="section-header"><span class="section-tag">02 // FORENSIC INSPECTOR</span> Deep Session Forensic Breakdown</div>', unsafe_allow_html=True)

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
                return f"{sid} ({arch_ts} UTC) — {tot} Threats [{crit_high} High/Crit] — [{reason}]"

            selected_sid = st.selectbox(
                "Select Archived Session to Inspect:",
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
                    <div style="background: rgba(15, 23, 42, 0.7); padding: 14px 18px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.08); font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: #cbd5e1; line-height: 1.6;">
                        <span style="color:#00f2fe; font-weight:700;">SESSION:</span> {meta.get('session_id')}<br>
                        <span style="color:#00f2fe; font-weight:700;">ARCHIVED:</span> {str(meta.get('archived_at'))[:19].replace('T', ' ')} UTC<br>
                        <span style="color:#00f2fe; font-weight:700;">TIMEFRAME:</span> {start_str} ──► {end_str}<br>
                        <span style="color:#00f2fe; font-weight:700;">REASON:</span> {meta.get('reason')} &bull; <strong>FILE:</strong> data/history_logs/{meta.get('file_name', f'{selected_sid}.json')}
                    </div>
                    """, unsafe_allow_html=True)

                df_hist = pd.DataFrame(hist_alerts) if hist_alerts else pd.DataFrame()

                with top_c2:
                    st.download_button(
                        label="📥 Download Session JSON",
                        data=json.dumps(sess_payload, indent=2, default=str),
                        file_name=f"{selected_sid}.json",
                        mime="application/json",
                        use_container_width=True,
                    )
                    if not df_hist.empty:
                        st.download_button(
                            label="📥 Download Alerts CSV",
                            data=df_hist.to_csv(index=False),
                            file_name=f"{selected_sid}_alerts.csv",
                            mime="text/csv",
                            use_container_width=True,
                        )

                with top_c3:
                    with st.expander("🗑️ Delete Session"):
                        st.caption("Permanently delete this archived session log?")
                        if st.button("Confirm Delete", type="primary", use_container_width=True, key=f"del_{selected_sid}"):
                            if delete_archived_session(selected_sid):
                                st.success("Session deleted successfully.")
                                time.sleep(1)
                                st.rerun()

                st.markdown("<br>", unsafe_allow_html=True)

                # Render Historical Analytics
                render_kpi_cards(meta)
                st.markdown("<br>", unsafe_allow_html=True)

                if not df_hist.empty:
                    render_charts(df_hist, key_prefix=f"hist_{selected_sid}")
                    st.markdown("<br>", unsafe_allow_html=True)
                    render_alerts_table(df_hist, key_prefix=f"hist_{selected_sid}")
                    render_incidents_cluster(df_hist)
                else:
                    st.info("This session contains 0 alert records.")
            else:
                st.error("Failed to load archived session data.")

        # Bottom Status Footer
        st.markdown("""
        <div style="margin-top: 40px; padding: 16px; border-top: 1px solid rgba(255,255,255,0.06); text-align: center; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #64748b;">
            ARGUS AI // HISTORICAL FORENSIC AUDIT ENGINE &bull; IMMUTABLE LOGS ENCLAVE
        </div>
        """, unsafe_allow_html=True)

    # ── VIEW 3: THREAT MATRIX & PLAYBOOKS ─────────────────────────────
    elif st.session_state["active_view"] == "intel":
        st.markdown('<div class="section-header"><span class="section-tag">INTEL // PLAYBOOKS</span> Detection Models &amp; Threat Vectors</div>', unsafe_allow_html=True)

        vectors = [
            {
                "title": "DDoS Flood Detection",
                "tag": "ddos",
                "color": "#ff3366",
                "desc": "Detects high-volume distributed SYN, UDP, and ICMP floods by tracking flow rate z-scores and source-IP Shannon entropy.",
                "thresholds": "Rate z-score > 3.0 &bull; IP Entropy > 4.5 bits &bull; Sustained packet bursts",
                "action": "Trigger perimeter rate-limiting and blackhole malicious source subnets via BGP Flowspec."
            },
            {
                "title": "C2 Periodic Beaconing",
                "tag": "beacon",
                "color": "#f59e0b",
                "desc": "Identifies stealthy Command-and-Control malware agents beaconing out to external command servers at regular intervals with low jitter.",
                "thresholds": "Inter-arrival Interval CV < 0.20 &bull; Min 5 pulses &bull; Fixed payload sizes",
                "action": "Isolate host immediately, capture memory dump, and block destination IP/FQDN on firewall."
            },
            {
                "title": "DGA & DNS Tunneling",
                "tag": "dns_tunnel",
                "color": "#a855f7",
                "desc": "Flags DNS exfiltration tunnels and Domain Generation Algorithms (DGA) using character n-gram frequencies and Shannon entropy.",
                "thresholds": "Subdomain Entropy > 3.8 &bull; Length > 28 chars &bull; TXT record anomalies",
                "action": "Sinkhole malicious domain at recursive DNS resolver and inspect client query logs."
            },
            {
                "title": "Encrypted Malware / JA3 Fingerprinting",
                "tag": "ja3_malware",
                "color": "#f97316",
                "desc": "Classifies malicious encrypted TLS sessions via JA3 ClientHello fingerprinting matched against active threat intelligence blocklists and Random Forest TLS models.",
                "thresholds": "Known Cobalt Strike / Trickbot JA3 hashes &bull; Self-signed TLS cert &bull; Cipher suite anomalies",
                "action": "Terminate active TLS sessions at gateway and dispatch EDR containment sensor."
            },
            {
                "title": "Reconnaissance Port Scans",
                "tag": "portscan",
                "color": "#00f2fe",
                "desc": "Spots horizontal and vertical network reconnaissance scanners probing internal network boundaries.",
                "thresholds": "Unique Port Fanout > 15 ports in 30s &bull; High SYN-to-ACK ratio",
                "action": "Quarantine source IP at switch access port and monitor for lateral movement."
            },
            {
                "title": "Data Exfiltration Over TLS/HTTP",
                "tag": "exfil",
                "color": "#10b981",
                "desc": "Uncovers data theft and abnormal egress volumes by calculating outbound/inbound byte ratios and duration anomalies.",
                "thresholds": "Egress Payload > 5 MB &bull; Out/In Byte Ratio > 10:1 &bull; Off-hours transmission",
                "action": "Sever external socket connection and notify Data Loss Prevention (DLP) team for forensic audit."
            },
        ]

        pcol1, pcol2 = st.columns(2)
        for i, vec in enumerate(vectors):
            target_col = pcol1 if i % 2 == 0 else pcol2
            with target_col:
                st.markdown(f"""
                <div class="playbook-card" style="border-left: 4px solid {vec['color']};">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <h4 style="margin:0; font-size:1.05rem; color:#f8fafc;">{vec['title']}</h4>
                        <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; font-weight:700; color:{vec['color']}; background:rgba(255,255,255,0.06); padding:2px 8px; border-radius:4px;">{vec['tag'].upper()}</span>
                    </div>
                    <p style="margin:8px 0; font-size:0.85rem; color:#94a3b8; line-height:1.5;">{vec['desc']}</p>
                    <div style="font-family:'JetBrains Mono',monospace; font-size:0.75rem; color:#cbd5e1; background:rgba(0,0,0,0.3); padding:8px 10px; border-radius:6px; margin:8px 0;">
                        <span style="color:{vec['color']};">CRITERIA:</span> {vec['thresholds']}
                    </div>
                    <div style="font-size:0.8rem; color:#38bdf8;">
                        <strong>SOC Playbook:</strong> {vec['action']}
                    </div>
                </div>
                """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
