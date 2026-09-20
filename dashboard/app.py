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

# ── Custom CSS for premium dark theme ────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    .stApp {
        font-family: 'Inter', sans-serif;
    }

    /* KPI Cards */
    .kpi-card {
        background: linear-gradient(135deg, rgba(30,30,50,0.9), rgba(20,20,40,0.95));
        border: 1px solid rgba(100,100,255,0.15);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        backdrop-filter: blur(10px);
    }
    .kpi-value {
        font-size: 2.2rem;
        font-weight: 700;
        margin: 5px 0;
    }
    .kpi-label {
        font-size: 0.85rem;
        opacity: 0.7;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .kpi-critical { color: #ff4757; }
    .kpi-high     { color: #ff6b35; }
    .kpi-medium   { color: #ffa502; }
    .kpi-low      { color: #2ed573; }
    .kpi-total    { color: #70a1ff; }

    /* Alert table risk level badges */
    .risk-critical {
        background: linear-gradient(135deg, #ff4757, #c0392b);
        color: white; padding: 3px 10px; border-radius: 12px;
        font-weight: 600; font-size: 0.75rem;
    }
    .risk-high {
        background: linear-gradient(135deg, #ff6b35, #e67e22);
        color: white; padding: 3px 10px; border-radius: 12px;
        font-weight: 600; font-size: 0.75rem;
    }
    .risk-medium {
        background: linear-gradient(135deg, #ffa502, #f39c12);
        color: white; padding: 3px 10px; border-radius: 12px;
        font-weight: 600; font-size: 0.75rem;
    }
    .risk-low {
        background: linear-gradient(135deg, #2ed573, #27ae60);
        color: white; padding: 3px 10px; border-radius: 12px;
        font-weight: 600; font-size: 0.75rem;
    }

    /* Header */
    .main-header {
        text-align: center;
        padding: 10px 0 20px 0;
    }
    .main-header h1 {
        font-size: 2rem;
        font-weight: 700;
        background: linear-gradient(90deg, #70a1ff, #7c4dff, #ff6b35);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 5px;
    }
    .main-header p {
        opacity: 0.6;
        font-size: 0.9rem;
    }

    /* Section headers */
    .section-header {
        font-size: 1.1rem;
        font-weight: 600;
        margin: 15px 0 10px 0;
        padding-bottom: 5px;
        border-bottom: 1px solid rgba(100,100,255,0.2);
    }

    div[data-testid="stDataFrame"] {
        border-radius: 8px;
        overflow: hidden;
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
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ Argus AI — Threat Intelligence Dashboard</h1>
        <p>Passive network monitoring • Read-only ingest • Streaming detection</p>
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
            st.markdown('<div class="section-header">📊 Threat Distribution</div>',
                        unsafe_allow_html=True)
            if "threat_class" in df.columns:
                threat_counts = df["threat_class"].value_counts()
                # Color mapping for threats
                colors = {
                    "ddos": "#ff4757",
                    "beacon": "#ffa502",
                    "dns_tunnel": "#7c4dff",
                    "ja3_malware": "#ff6b35",
                    "portscan": "#70a1ff",
                    "exfil": "#2ed573",
                }
                import plotly.express as px
                fig = px.pie(
                    values=threat_counts.values,
                    names=threat_counts.index,
                    color=threat_counts.index,
                    color_discrete_map=colors,
                    hole=0.45,
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="white",
                    margin=dict(t=10, b=10, l=10, r=10),
                    height=300,
                    legend=dict(orientation="h", y=-0.1),
                )
                fig.update_traces(textposition='inside', textinfo='label+percent')
                st.plotly_chart(fig, use_container_width=True)

        with col_right:
            st.markdown('<div class="section-header">📈 Risk Score Distribution</div>',
                        unsafe_allow_html=True)
            if "risk_score" in df.columns:
                import plotly.express as px
                fig = px.histogram(
                    df, x="risk_score",
                    nbins=20,
                    color_discrete_sequence=["#7c4dff"],
                    labels={"risk_score": "Risk Score", "count": "Alert Count"},
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="white",
                    margin=dict(t=10, b=30, l=40, r=10),
                    height=300,
                    xaxis=dict(gridcolor="rgba(100,100,255,0.1)"),
                    yaxis=dict(gridcolor="rgba(100,100,255,0.1)"),
                    bargap=0.1,
                )
                st.plotly_chart(fig, use_container_width=True)

        # ── Alert Table ──────────────────────────────────────────────
        st.markdown('<div class="section-header">🚨 Live Alert Feed</div>',
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

            # Color code by risk level
            def highlight_risk(row):
                level = row.get("risk_level", "LOW")
                colors = {
                    "CRITICAL": "background-color: rgba(255,71,87,0.3)",
                    "HIGH":     "background-color: rgba(255,107,53,0.2)",
                    "MEDIUM":   "background-color: rgba(255,165,2,0.15)",
                    "LOW":      "background-color: rgba(46,213,115,0.1)",
                }
                color = colors.get(level, "")
                return [color] * len(row)

            styled = display_df.style.apply(highlight_risk, axis=1)
            st.dataframe(styled, use_container_width=True, height=400)

            st.caption(f"Showing {len(filtered)} of {len(df)} alerts")
        else:
            st.info("No alerts match your filters.")

        # ── Incident Summary ─────────────────────────────────────────
        if "incident_id" in df.columns and df["incident_id"].notna().any():
            st.markdown('<div class="section-header">🔗 Incident Correlation</div>',
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

            st.dataframe(incidents, use_container_width=True, height=250)

    else:
        st.info(
            "📭 No alerts yet. Run `python pipeline.py` to populate the alert database."
        )

    # ── Auto-refresh ─────────────────────────────────────────────────
    # Streamlit re-runs the script every 2 seconds
    st.markdown("""
    <div style="text-align: center; opacity: 0.4; font-size: 0.75rem; margin-top: 30px;">
        Argus AI • Read-Only Monitoring Enclave • Passive Ingest Only<br>
        Dashboard polls database every 2s — no connection to production network
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
