import streamlit as st
import pandas as pd
from typing import List, Optional, Dict
from dashboard.styles import COLORS

def render_header(theme: str):
    """Render application header."""
    c = COLORS[theme]
    
    mode = "DEMO" if st.session_state.get('data_source_radio') == "Demo Data" else "LIVE"
    
    st.markdown(f"""
        <div class="main-header">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h1 class="main-title">TOR-UNVEIL</h1>
                    <p class="main-subtitle">Forensic Traffic Correlation & Guard Node Identification</p>
                </div>
                <div style="text-align: right;">
                    <div class="status-badge">
                        <span class="status-dot"></span>
                        <span>{mode} MODE</span>
                    </div>
                    <p style="color: {c['text_muted']}; font-size: 0.8rem; margin-top: 8px;">
                        {st.session_state.get('last_refresh', pd.Timestamp.now()).strftime('%Y-%m-%d %H:%M:%S')}
                    </p>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)

def render_alert_banner(high_count: int, theme: str):
    """Render alert banner for high-risk flows."""
    if high_count > 0:
        st.markdown(f"""
            <div class="alert-banner">
                <span class="alert-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg></span>
                <div class="alert-content">
                    <div class="alert-title">ACTIVE HIGH-RISK ALERTS</div>
                    <div class="alert-desc">
                        {high_count} flow(s) require immediate investigation. 
                        Strong correlation patterns detected.
                    </div>
                </div>
                <div class="alert-count">{high_count}</div>
            </div>
        """, unsafe_allow_html=True)

def render_metrics(df: pd.DataFrame, theme: str):
    """Render metric cards."""
    c = COLORS[theme]
    
    total = len(df)
    high_risk = len(df[df['risk_level'] == 'HIGH'])
    avg_risk = df['final_risk_score'].mean()
    anomaly_pct = len(df[df['anomaly_score'] > 0.5]) / total * 100 if total > 0 else 0
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">{total:,}</div>
                <div class="metric-label">Total Flows</div>
            </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value" style="color: {c['danger']};">{high_risk}</div>
                <div class="metric-label">High-Risk Alerts</div>
            </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">{avg_risk:.1%}</div>
                <div class="metric-label">Avg Risk Score</div>
            </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">{anomaly_pct:.1f}%</div>
                <div class="metric-label">Anomaly Rate</div>
            </div>
        """, unsafe_allow_html=True)

def render_flow_table(df: pd.DataFrame, risk_filter: List[str], threshold: float) -> Optional[str]:
    """Render interactive flow table and return selected flow ID."""
    
    # Apply filters
    filtered = df[df['risk_level'].isin(risk_filter)]
    filtered = filtered[filtered['final_risk_score'] >= threshold]
    filtered = filtered.sort_values('final_risk_score', ascending=False)
    
    if len(filtered) == 0:
        st.info("No flows match the current filters.")
        return None
    
    # Display table
    display_cols = ['flow_id', 'timestamp', 'final_risk_score', 'risk_level', 'correlation_score', 'anomaly_score']
    available_cols = [c for c in display_cols if c in filtered.columns]
    
    st.dataframe(
        filtered[available_cols],
        width="stretch",
        hide_index=True
    )
    
    # Selection
    selected = st.selectbox(
        "Select Flow for Investigation",
        options=filtered['flow_id'].tolist(),
        index=0
    )
    
    return selected

def render_footer(theme: str):
    """Render footer with legal disclaimer."""
    c = COLORS[theme]
    
    st.markdown(f"""
        <div class="footer">
            <p class="footer-text">
                <span class="footer-legal">Legal & Ethical Notice</span><br><br>
                This system analyzes <strong>encrypted traffic metadata only</strong>. 
                No content inspection or user identification is performed. 
                Correlation analysis provides investigative leads only and does not 
                constitute proof of identity or activity.<br><br>
                All use must comply with applicable laws, court orders, and departmental policies.
                Unauthorized surveillance or misuse is strictly prohibited.<br><br>
                <em style="color: {c['text_muted']};">TOR-UNVEIL v1.0 | For Authorized Use Only | © 2024</em>
            </p>
        </div>
    """, unsafe_allow_html=True)
