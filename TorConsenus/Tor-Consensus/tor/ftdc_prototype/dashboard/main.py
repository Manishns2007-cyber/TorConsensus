import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime
import sys
import os

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import modular components
from dashboard.styles import COLORS, get_css
from dashboard.data_loader import (
    init_session_state, load_demo_data, get_trainer, 
    run_inference, process_pcap_file
)
from dashboard.components.ui import (
    render_header, render_alert_banner, render_metrics, 
    render_flow_table, render_footer
)
from dashboard.components.sidebar import render_sidebar
from dashboard.components.investigation import render_investigation_panel
from dashboard.components.pcap_ui import (
    render_pcap_summary, render_nodes_table
)
from dashboard.components.origin_tab import render_origin_ip_tab
from dashboard.visualizations import (
    create_risk_timeline, create_correlation_scatter, 
    create_risk_distribution, create_feature_importance,
    create_protocol_distribution, create_port_histogram,
    create_traffic_timeline, create_bytes_distribution,
    create_network_graph
)

def main():
    """Main application entry point."""
    st.set_page_config(
        page_title="TOR-UNVEIL | Traffic Analysis",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Initialize
    init_session_state()
    theme = st.session_state.theme
    c = COLORS[theme]
    
    # Inject CSS
    st.markdown(get_css(theme), unsafe_allow_html=True)
    
    # Sidebar controls
    risk_threshold, risk_filter, time_range, data_source, uploaded_file, uploaded_pcap = render_sidebar(theme)
    
    # Header
    render_header(theme)
    
    # Load data
    df = None
    pcap_metadata = None
    nodes_df = None
    connections = None
    
    if data_source == "Demo Data":
        with st.spinner("Loading demo data..."):
            df = load_demo_data()
            
    elif data_source == "Upload CSV":
        if uploaded_file is not None:
            try:
                df = pd.read_csv(uploaded_file)
                if 'timestamp' in df.columns:
                    df['timestamp'] = pd.to_datetime(df['timestamp'])
                st.success(f"CSV loaded successfully: {len(df)} rows")
            except Exception as e:
                st.error(f"Error loading CSV: {e}")
                render_footer(theme)
                return
        else:
            st.info("Upload a CSV file from the sidebar to begin analysis.")
            render_footer(theme)
            return
            
    elif data_source == "Upload PCAP":
        if uploaded_pcap is not None:
            with st.spinner("Analyzing PCAP file..."):
                result = process_pcap_file(uploaded_pcap)
                if result[0] is None:
                    st.error("Failed to process PCAP file.")
                    render_footer(theme)
                    return
                df, pcap_metadata, nodes_df, connections = result
                st.session_state.pcap_metadata = pcap_metadata
                st.session_state.pcap_nodes = nodes_df
                st.session_state.pcap_connections = connections
        else:
            st.info("Upload a PCAP file from the sidebar to begin analysis.")
            render_footer(theme)
            return
    
    if df is None:
        st.info("Select a data source from the sidebar to begin analysis.")
        render_footer(theme)
        return

    # Load trainer
    trainer = get_trainer()
    
    # Run inference if needed
    if 'final_risk_score' not in df.columns:
        with st.spinner("Running ML risk analysis..."):
            df = run_inference(df, trainer)
            if 'predicted_risk_score' in df.columns:
                df['final_risk_score'] = df['predicted_risk_score']
                df['risk_level'] = df['predicted_risk_level']
    
    # Ensure anomaly_score exists
    if 'anomaly_score' not in df.columns:
        df['anomaly_score'] = np.random.uniform(0.1, 0.5, len(df))
    
    # Count alerts
    high_risk_count = len(df[df['risk_level'] == 'HIGH'])
    
    # Alert banner
    render_alert_banner(high_risk_count, theme)
    
    # TABBED INTERFACE
    if data_source == "Upload PCAP" and pcap_metadata:
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
            "Overview", "Summary", "Nodes", "Network", "Flow Details", "Origin IP"
        ])
        
        with tab1:
            render_metrics(df, theme)
            col1, col2 = st.columns(2)
            with col1:
                st.plotly_chart(create_risk_timeline(df, theme), width="stretch", key="timeline_pcap")
            with col2:
                st.plotly_chart(create_correlation_scatter(df, theme), width="stretch", key="scatter_pcap")
            col3, col4 = st.columns(2)
            with col3:
                st.plotly_chart(create_risk_distribution(df, theme), width="stretch", key="dist_pcap")
            with col4:
                if trainer.feature_importance:
                    st.plotly_chart(create_feature_importance(trainer.feature_importance, theme), width="stretch", key="importance_pcap")
        
        with tab2:
            render_pcap_summary(pcap_metadata, theme)
            col1, col2 = st.columns(2)
            with col1:
                st.plotly_chart(create_protocol_distribution(pcap_metadata, theme), width="stretch", key="protocol")
            with col2:
                st.plotly_chart(create_port_histogram(pcap_metadata, theme), width="stretch", key="ports")
            st.plotly_chart(create_traffic_timeline(df.copy(), theme), width="stretch", key="traffic_time")
            if 'total_bytes' in df.columns:
                st.plotly_chart(create_bytes_distribution(df, theme), width="stretch", key="bytes_dist")
        
        with tab3:
            if nodes_df is not None:
                render_nodes_table(nodes_df, theme)
        
        with tab4:
            if connections and nodes_df is not None:
                st.plotly_chart(create_network_graph(connections, nodes_df, theme), width="stretch", key="network")
        
        with tab5:
            selected_flow_id = render_flow_table(df, risk_filter, risk_threshold)
            if selected_flow_id:
                flow_data = df[df['flow_id'] == selected_flow_id].iloc[0]
                render_investigation_panel(flow_data, trainer.feature_importance, theme)
        
        with tab6:
            render_origin_ip_tab(df, theme, COLORS)
    
    else:
        # Standard view
        render_metrics(df, theme)
        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(create_risk_timeline(df, theme), width="stretch", key="timeline")
        with col2:
            st.plotly_chart(create_correlation_scatter(df, theme), width="stretch", key="scatter")
        col3, col4 = st.columns(2)
        with col3:
            st.plotly_chart(create_risk_distribution(df, theme), width="stretch", key="dist")
        with col4:
            if trainer.feature_importance:
                st.plotly_chart(create_feature_importance(trainer.feature_importance, theme), width="stretch", key="importance")
        
        st.markdown("---")
        selected_flow_id = render_flow_table(df, risk_filter, risk_threshold)
        if selected_flow_id:
            flow_data = df[df['flow_id'] == selected_flow_id].iloc[0]
            render_investigation_panel(flow_data, trainer.feature_importance, theme)
        
        st.markdown("---")
        render_origin_ip_tab(df, theme, COLORS)
    
    render_footer(theme)

if __name__ == "__main__":
    main()
