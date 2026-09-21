"""
Argus AI — Threat Intelligence Dashboard (Streamlit).

Polls the database every 2 seconds for new alerts.
Strictly read-only — never touches the pipeline.

Usage:
    pip install streamlit plotly
    streamlit run dashboard/app.py
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

from db import get_connection, create_alerts_table, get_recent_alerts, get_alert_stats

# ── Page config ──────────────────────────────────────────────────────
st.set_page_config(
    page_title="Argus AI — Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS for minimalist Redis.io inspired theme ───────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap');

    /* Global Typography & Palette (Redis.io Light Theme) */
    .stApp {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        background-color: #f8fafc !important;
        color: #1e293b !important;
    }

    header[data-testid="stHeader"] {
        background-color: #f8fafc !important;
    }

    h1, h2, h3, h4, .main-header h1, .section-header {
        font-family: 'Space Grotesk', -apple-system, sans-serif !important;
        letter-spacing: -0.025em;
        color: #0f172a !important;
    }

    p, span, label, .stMarkdown p {
        color: #334155;
    }

    code, pre, .mono-text {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Minimalist KPI Cards (Redis.io style) */
    .kpi-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 18px 20px;
        text-align: left;
        position: relative;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.04), 0 1px 2px -1px rgba(0, 0, 0, 0.04);
        transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .kpi-card:hover {
        border-color: #cbd5e1;
        box-shadow: 0 4px 12px -2px rgba(0, 0, 0, 0.08);
    }
    .kpi-label {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 600;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 6px;
    }
    .kpi-value {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 2.2rem;
        font-weight: 700;
        line-height: 1.1;
        letter-spacing: -0.03em;
    }
    .kpi-critical { color: #dc2626; }
    .kpi-high     { color: #ea580c; }
    .kpi-medium   { color: #0284c7; }
    .kpi-low      { color: #059669; }
    .kpi-total    { color: #0f172a; }

    /* Alert table risk level badges */
    .risk-critical {
        background: #fee2e2;
        color: #991b1b;
        border: 1px solid #fca5a5;
        padding: 3px 8px;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        font-size: 0.72rem;
    }
    .risk-high {
        background: #ffedd5;
        color: #9a3412;
        border: 1px solid #fdba74;
        padding: 3px 8px;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        font-size: 0.72rem;
    }
    .risk-medium {
        background: #e0f2fe;
        color: #075985;
        border: 1px solid #7dd3fc;
        padding: 3px 8px;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        font-size: 0.72rem;
    }
    .risk-low {
        background: #dcfce7;
        color: #166534;
        border: 1px solid #86efac;
        padding: 3px 8px;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        font-size: 0.72rem;
    }

    /* Header Bar */
    .main-header {
        padding: 24px 0 20px 0;
        margin-bottom: 20px;
        border-bottom: 1px solid #e2e8f0;
    }
    .telemetry-badge {
        display: inline-flex;
        align-items: center;
        gap: 7px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.7rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #475569;
        background: #f1f5f9;
        border: 1px solid #e2e8f0;
        border-radius: 9999px;
        padding: 3px 11px;
        margin-bottom: 12px;
    }
    .status-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background-color: #10b981;
        box-shadow: 0 0 6px rgba(16, 185, 129, 0.4);
    }
    .main-header h1 {
        font-size: 2.1rem;
        font-weight: 700;
        color: #0f172a !important;
        margin: 0 0 6px 0;
        line-height: 1.2;
    }
    .main-header p {
        color: #64748b !important;
        font-size: 0.9rem;
        font-weight: 400;
        margin: 0;
    }

    /* Section headers */
    .section-header {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 1.05rem;
        font-weight: 600;
        color: #0f172a !important;
        margin: 28px 0 14px 0;
        padding-bottom: 8px;
        border-bottom: 1px solid #e2e8f0;
    }
    .section-tag {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.68rem;
        color: #dc2626;
        background: #fef2f2;
        border: 1px solid #fecaca;
        border-radius: 4px;
        padding: 2px 7px;
        font-weight: 600;
        letter-spacing: 0.04em;
    }

    /* Tables & Frames */
    div[data-testid="stDataFrame"] {
        border: 1px solid #e2e8f0 !important;
        border-radius: 8px !important;
        overflow: hidden;
        background: #ffffff !important;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.03);
    }
    div[data-testid="stDataFrame"] table {
        font-family: 'JetBrains Mono', monospace !important;
        background: #ffffff !important;
        color: #0f172a !important;
    }

    /* Streamlit controls & inputs */
    div[data-baseweb="select"] > div {
        background-color: #ffffff !important;
        border-color: #cbd5e1 !important;
        border-radius: 6px !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.85rem !important;
        color: #0f172a !important;
    }
    div[data-baseweb="tag"] {
        background-color: #f1f5f9 !important;
        color: #1e293b !important;
        border-radius: 4px !important;
        border: 1px solid #e2e8f0 !important;
    }
    div[data-baseweb="tag"] span {
        color: #1e293b !important;
    }
    label[data-testid="stWidgetLabel"] p {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.72rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.06em !important;
        color: #475569 !important;
        font-weight: 600 !important;
    }

    /* Footer */
    .footer-bar {
        text-align: center;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        color: #64748b;
        padding: 32px 0 16px 0;
        margin-top: 48px;
        border-top: 1px solid #e2e8f0;
        line-height: 1.7;
    }
    .footer-bar span {
        color: #0f172a;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


# ── Helper functions ─────────────────────────────────────────────────
def risk_badge(level: str) -> str:
    """Render a colored badge for risk level."""
    css_class = f"risk-{level.lower()}" if level else "risk-low"
    return f'<span class="{css_class}">{level}</span>'


def format_evidence(evidence_str) -> str:
    """Format evidence JSON for display."""
    if not evidence_str:
        return ""
    try:
        if isinstance(evidence_str, str):
            ev = json.loads(evidence_str)
        else:
            ev = evidence_str
        reason = ev.get("reason", "")
        return reason if reason else str(ev)[:100]
    except (json.JSONDecodeError, TypeError):
        return str(evidence_str)[:100]


# ── Main dashboard ───────────────────────────────────────────────────
def main():
    now_str = datetime.now().strftime("%H:%M:%S")

    # Sidebar controls
    with st.sidebar:
        st.markdown("### ⚙️ Telemetry Stream")
        auto_refresh = st.checkbox("Live Auto-Refresh (2s)", value=True, help="Automatically refresh threat telemetry every 2 seconds")
        st.caption(f"Last updated: {now_str}")

    # Header
    pulse_dot = '<span class="status-dot"></span>' if auto_refresh else '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#94a3b8;margin-right:6px;"></span>'
    stream_state = f"LIVE STREAM &bull; PULSE {now_str}" if auto_refresh else "STREAM PAUSED"
    st.markdown(f"""
    <div class="main-header">
        <div class="telemetry-badge">
            {pulse_dot} {stream_state} &bull; READ-ONLY ENCLAVE
        </div>
        <h1>ARGUS AI <span style="font-weight: 400; color: #64748b;">// Threat Intelligence</span></h1>
        <p>Passive network telemetry &bull; Zero-intrusion streaming detection &bull; Air-gapped enclave buffer</p>
    </div>
    """, unsafe_allow_html=True)

    # Initialize DB
    create_alerts_table()

    # Fetch data
    stats = get_alert_stats()
    alerts_raw = get_recent_alerts(limit=500)

    # ── KPI Cards ────────────────────────────────────────────────────
    by_level = stats.get("by_risk_level", {})
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Total Alerts</div>
            <div class="kpi-value kpi-total">{stats.get('total_alerts', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Critical</div>
            <div class="kpi-value kpi-critical">{by_level.get('CRITICAL', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">High</div>
            <div class="kpi-value kpi-high">{by_level.get('HIGH', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Medium</div>
            <div class="kpi-value kpi-medium">{by_level.get('MEDIUM', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Unique Sources</div>
            <div class="kpi-value kpi-low">{stats.get('unique_source_ips', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts Row ───────────────────────────────────────────────────
    if alerts_raw:
        df = pd.DataFrame(alerts_raw)

        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown('<div class="section-header"><span class="section-tag">01 // TELEMETRY</span> Threat Distribution</div>',
                        unsafe_allow_html=True)
            if "threat_class" in df.columns:
                threat_counts = df["threat_class"].value_counts()
                # Redis-inspired threat palette
                colors = {
                    "ddos": "#ef4444",
                    "beacon": "#f59e0b",
                    "dns_tunnel": "#a855f7",
                    "ja3_malware": "#f97316",
                    "portscan": "#0284c7",
                    "exfil": "#10b981",
                }
                import plotly.express as px
                fig = px.pie(
                    values=threat_counts.values,
                    names=threat_counts.index,
                    color=threat_counts.index,
                    color_discrete_map=colors,
                    hole=0.55,
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#475569",
                    font_family="Inter, sans-serif",
                    margin=dict(t=10, b=10, l=10, r=10),
                    height=280,
                    legend=dict(
                        orientation="h",
                        y=-0.15,
                        font=dict(size=10, family="JetBrains Mono, monospace", color="#475569"),
                    ),
                )
                fig.update_traces(
                    textposition='inside',
                    textinfo='label+percent',
                    insidetextfont=dict(family="JetBrains Mono, monospace", size=11, color="#ffffff"),
                    marker=dict(line=dict(color='#ffffff', width=2)),
                )
                st.plotly_chart(fig, width="stretch")

        with col_right:
            st.markdown('<div class="section-header"><span class="section-tag">02 // SPECTRUM</span> Risk Score Distribution</div>',
                        unsafe_allow_html=True)
            if "risk_score" in df.columns:
                import plotly.express as px
                fig = px.histogram(
                    df, x="risk_score",
                    nbins=20,
                    color_discrete_sequence=["#ef4444"],
                    labels={"risk_score": "RISK SCORE", "count": "COUNT"},
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#475569",
                    font_family="Inter, sans-serif",
                    margin=dict(t=10, b=30, l=40, r=10),
                    height=280,
                    xaxis=dict(
                        gridcolor="rgba(0, 0, 0, 0.05)",
                        tickfont=dict(family="JetBrains Mono, monospace", size=10, color="#64748b"),
                        title_font=dict(family="JetBrains Mono, monospace", size=10, color="#475569"),
                    ),
                    yaxis=dict(
                        gridcolor="rgba(0, 0, 0, 0.05)",
                        tickfont=dict(family="JetBrains Mono, monospace", size=10, color="#64748b"),
                        title_font=dict(family="JetBrains Mono, monospace", size=10, color="#475569"),
                    ),
                    bargap=0.15,
                )
                st.plotly_chart(fig, width="stretch")

        # ── Alert Table ──────────────────────────────────────────────
        st.markdown('<div class="section-header"><span class="section-tag">03 // REAL-TIME FEED</span> Live Alerts</div>',
                    unsafe_allow_html=True)

        # Filters
        filter_col1, filter_col2, filter_col3 = st.columns(3)
        with filter_col1:
            threat_filter = st.multiselect(
                "Threat Class",
                options=sorted(df["threat_class"].unique()) if "threat_class" in df.columns else [],
                default=[],
                key="threat_filter",
            )
        with filter_col2:
            level_filter = st.multiselect(
                "Risk Level",
                options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                default=[],
                key="level_filter",
            )
        with filter_col3:
            min_score = st.slider("Min Risk Score", 0, 100, 0, key="min_score")

        # Apply filters
        filtered = df.copy()
        if threat_filter:
            filtered = filtered[filtered["threat_class"].isin(threat_filter)]
        if level_filter:
            filtered = filtered[filtered["risk_level"].isin(level_filter)]
        if min_score > 0:
            filtered = filtered[filtered["risk_score"] >= min_score]

        # Display columns
        display_cols = [
            "timestamp", "src_ip", "dest_ip", "threat_class",
            "confidence", "risk_score", "risk_level", "evidence", "explanation",
        ]
        display_cols = [c for c in display_cols if c in filtered.columns]

        if not filtered.empty:
            # Format for display
            display_df = filtered[display_cols].copy()
            if "confidence" in display_df.columns:
                display_df["confidence"] = display_df["confidence"].apply(
                    lambda x: f"{x:.2f}" if pd.notna(x) else ""
                )
            if "timestamp" in display_df.columns:
                display_df["timestamp"] = display_df["timestamp"].apply(
                    lambda x: str(x)[:19] if x else ""
                )
            if "evidence" in display_df.columns:
                display_df["evidence"] = display_df["evidence"].apply(format_evidence)

            # Color code by risk level with subtle light-mode Redis-like tints
            def highlight_risk(row):
                level = row.get("risk_level", "LOW")
                colors = {
                    "CRITICAL": "background-color: #fef2f2; color: #991b1b; font-weight: 500;",
                    "HIGH":     "background-color: #fff7ed; color: #9a3412; font-weight: 500;",
                    "MEDIUM":   "background-color: #f0f9ff; color: #075985; font-weight: 500;",
                    "LOW":      "background-color: #f0fdf4; color: #166534; font-weight: 500;",
                }
                color = colors.get(level, "")
                return [color] * len(row)

            styled = display_df.style.apply(highlight_risk, axis=1)
            st.dataframe(styled, width="stretch", height=400)

            st.caption(f"Showing {len(filtered)} of {len(df)} alerts")
        else:
            st.info("No alerts match your filters.")

        # ── Incident Summary ─────────────────────────────────────────
        if "incident_id" in df.columns and df["incident_id"].notna().any():
            st.markdown('<div class="section-header"><span class="section-tag">04 // CORRELATION</span> Incident Clusters</div>',
                        unsafe_allow_html=True)

            incidents = df.groupby("incident_id").agg({
                "src_ip": "first",
                "alert_id": "count",
                "risk_score": "max",
                "risk_level": "first",
                "threat_class": lambda x: ", ".join(sorted(set(x))),
                "timestamp": ["min", "max"],
            }).reset_index()

            incidents.columns = [
                "Incident ID", "Source IP", "Alert Count", "Max Risk",
                "Risk Level", "Threat Types", "First Seen", "Last Seen",
            ]
            incidents = incidents.sort_values("Max Risk", ascending=False)

            # Truncate incident ID for display
            incidents["Incident ID"] = incidents["Incident ID"].apply(
                lambda x: str(x)[:8] + "..." if x else ""
            )

            st.dataframe(incidents, width="stretch", height=250)

    else:
        st.info(
            "📭 No alerts yet. Run `python pipeline.py` to populate the alert database."
        )

    # ── Auto-refresh / Status Footer ─────────────────────────────────
    status_label = f"LIVE STREAM ACTIVE &bull; LAST PULSE: {now_str}" if auto_refresh else "LIVE STREAM PAUSED"
    st.markdown(f"""
    <div class="footer-bar">
        <span>ARGUS AI</span> &bull; READ-ONLY ENCLAVE &bull; PASSIVE INGEST ENGINE<br>
        {status_label} &bull; AIR-GAPPED FROM PRODUCTION FABRIC
    </div>
    """, unsafe_allow_html=True)

    if auto_refresh:
        time.sleep(2.0)
        st.rerun()


if __name__ == "__main__":
    main()
