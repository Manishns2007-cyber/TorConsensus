import streamlit as st
import pandas as pd
from datetime import datetime
from dashboard.styles import COLORS

def render_sidebar(theme: str):
    """Render sidebar controls."""
    c = COLORS[theme]
    
    with st.sidebar:
        st.markdown(f"<h2 style='color: {c['text']}; font-weight: 600;'>Control Panel</h2>", 
                    unsafe_allow_html=True)
        
        # Theme toggle
        new_theme = st.toggle("Dark Mode", value=(theme == 'dark'))
        if (new_theme and theme != 'dark') or (not new_theme and theme != 'light'):
            st.session_state.theme = 'dark' if new_theme else 'light'
            st.rerun()
        
        st.markdown("---")
        
        # Risk threshold
        risk_threshold = st.slider(
            "Risk Score Threshold",
            min_value=0.0,
            max_value=1.0,
            value=0.0,
            step=0.05,
            help="Show flows with risk score above this threshold"
        )
        
        st.markdown("---")
        
        # Risk level filter
        st.markdown(f"<p style='color: {c['text']}; font-weight: 600;'>Risk Level Filter</p>", 
                    unsafe_allow_html=True)
        
        risk_filter = []
        if st.checkbox("HIGH", value=True):
            risk_filter.append('HIGH')
        if st.checkbox("MEDIUM", value=True):
            risk_filter.append('MEDIUM')
        if st.checkbox("LOW", value=True):
            risk_filter.append('LOW')
        
        st.markdown("---")
        
        # Time range
        time_range = st.selectbox(
            "Time Range",
            ["Last 1 Hour", "Last 6 Hours", "Last 24 Hours", "All Data"],
            index=3
        )
        
        st.markdown("---")
        
        # Data source
        st.markdown(f"<p style='color: {c['text']}; font-weight: 600;'>Data Source</p>", 
                    unsafe_allow_html=True)
        
        data_source = st.radio(
            "Load from:",
            ["Demo Data", "Upload CSV", "Upload PCAP"],
            label_visibility="collapsed",
            key="data_source_radio"
        )
        
        uploaded_file = None
        uploaded_pcap = None
        
        # File upload section - always show based on selection
        if data_source == "Upload CSV":
            st.markdown("---")
            st.markdown(f"<p style='color: {c['accent']}; font-weight: 600;'>Upload CSV File</p>", 
                        unsafe_allow_html=True)
            uploaded_file = st.file_uploader(
                "Choose CSV file",
                type=['csv'],
                key="csv_uploader",
                help="Upload a CSV file with traffic flow data"
            )
            if uploaded_file:
                st.success(f"Loaded: {uploaded_file.name}")
                
        elif data_source == "Upload PCAP":
            st.markdown("---")
            st.markdown(f"<p style='color: {c['warning']}; font-weight: 600;'>Upload PCAP File</p>", 
                        unsafe_allow_html=True)
            uploaded_pcap = st.file_uploader(
                "Choose PCAP file",
                type=['pcap', 'pcapng', 'cap'],
                key="pcap_uploader",
                help="Upload a PCAP/PCAPNG file for TOR traffic analysis"
            )
            if uploaded_pcap:
                file_size = len(uploaded_pcap.getvalue()) / 1024 / 1024
                st.success(f"Loaded: {uploaded_pcap.name} ({file_size:.2f} MB)")
                st.info("Click anywhere or wait for analysis to begin...")
        
        st.markdown("---")
        
        # Refresh
        if st.button("Refresh", width="stretch"):
            st.cache_data.clear()
            st.session_state.last_refresh = datetime.now()
            st.rerun()
        
        st.caption(f"Last: {st.session_state.last_refresh.strftime('%H:%M:%S')}")
        
        return risk_threshold, risk_filter, time_range, data_source, uploaded_file, uploaded_pcap
