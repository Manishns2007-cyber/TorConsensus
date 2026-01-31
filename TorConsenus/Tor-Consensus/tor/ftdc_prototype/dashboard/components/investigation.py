import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from typing import Dict
from dashboard.styles import COLORS, RISK_COLORS

def create_risk_gauge(score: float, theme: str) -> go.Figure:
    """Create a risk gauge chart."""
    c = COLORS[theme]
    
    color = RISK_COLORS['HIGH'] if score >= 0.7 else RISK_COLORS['MEDIUM'] if score >= 0.4 else RISK_COLORS['LOW']
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score * 100,
        number={'suffix': '%', 'font': {'size': 24, 'color': c['text']}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': c['border']},
            'bar': {'color': color},
            'bgcolor': c['bg_card'],
            'borderwidth': 2,
            'bordercolor': c['border'],
            'steps': [
                {'range': [0, 40], 'color': 'rgba(63,185,80,0.2)'},
                {'range': [40, 70], 'color': 'rgba(210,153,34,0.2)'},
                {'range': [70, 100], 'color': 'rgba(248,81,73,0.2)'}
            ]
        }
    ))
    
    fig.update_layout(
        height=200,
        margin=dict(l=20, r=20, t=30, b=20),
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color=c['text'])
    )
    return fig

def render_investigation_panel(flow_data: pd.Series, importance: Dict[str, float], theme: str):
    """Render detailed investigation panel."""
    c = COLORS[theme]
    
    risk_score = flow_data['final_risk_score']
    risk_level = flow_data['risk_level']
    
    st.markdown(f"""
        <div style="background: {c['bg_card']}; border: 1px solid {c['border']}; 
                    border-radius: 12px; padding: 20px; margin: 16px 0;">
            <h3 style="color: {c['accent']}; margin-bottom: 16px; font-weight: 600;">
                Flow Investigation: {flow_data['flow_id']}
            </h3>
        </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        # Risk gauge
        fig_gauge = create_risk_gauge(risk_score, theme)
        st.plotly_chart(fig_gauge, width="stretch", key="investigation_gauge")
        
        # Risk badge
        color = RISK_COLORS[risk_level]
        st.markdown(f"""
            <div style="background: {color}; color: white; text-align: center; 
                        padding: 8px 16px; border-radius: 8px; font-weight: bold;">
                {risk_level} RISK
            </div>
        """, unsafe_allow_html=True)
    
    with col2:
        # Key metrics
        st.markdown(f"<h4 style='color: {c['text']};'>Flow Details</h4>", unsafe_allow_html=True)
        
        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric("Correlation", f"{flow_data['correlation_score']:.3f}")
            st.metric("Burst Align", f"{flow_data['burst_alignment_score']:.3f}")
        with m2:
            st.metric("Time Lag", f"{flow_data['peak_time_lag']:.0f} ms")
            st.metric("Duration", f"{flow_data['flow_duration']:.1f} s")
        with m3:
            st.metric("Packet Rate", f"{flow_data['packet_rate_mean']:.1f}")
            st.metric("Anomaly", f"{flow_data['anomaly_score']:.3f}")
    
    # Additional info
    st.markdown(f"""
        <div style="background: {c['bg_secondary']}; border-radius: 8px; padding: 16px; margin-top: 16px;">
            <p style="color: {c['text_muted']}; margin: 0 0 8px 0;">
                <strong>Timestamp:</strong> {flow_data['timestamp']}
            </p>
            <p style="color: {c['text_muted']}; margin: 0 0 8px 0;">
                <strong>Relay:</strong> {flow_data.get('relay_fingerprint', 'N/A')} 
                ({flow_data.get('relay_country', 'Unknown')})
            </p>
            <p style="color: {c['text_muted']}; margin: 0;">
                <strong>Protocol:</strong> {flow_data.get('protocol', 'N/A')} | 
                <strong>Source:</strong> {flow_data.get('source_ip', 'N/A')} → 
                <strong>Dest:</strong> {flow_data.get('dest_ip', 'N/A')}
            </p>
        </div>
    """, unsafe_allow_html=True)
