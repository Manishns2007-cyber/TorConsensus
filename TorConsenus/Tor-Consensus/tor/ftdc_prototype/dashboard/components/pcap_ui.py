import streamlit as st
import pandas as pd
from dashboard.styles import COLORS

def render_pcap_summary(metadata: dict, theme: str):
    """Render PCAP metadata summary."""
    c = COLORS[theme]
    
    st.markdown(f"""
        <div style="background: {c['bg_card']}; border: 1px solid {c['border']}; 
                    border-radius: 12px; padding: 24px; margin-bottom: 24px;">
            <h3 style="color: {c['accent']}; margin-bottom: 16px; font-weight: 600;">PCAP Summary</h3>
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Filename", metadata.get('filename', 'Unknown'))
    with col2:
        size_mb = metadata.get('file_size', 0) / 1024 / 1024
        st.metric("File Size", f"{size_mb:.2f} MB")
    with col3:
        duration = metadata.get('capture_duration', 0)
        dur_str = f"{duration:.1f}s" if duration < 60 else f"{duration/60:.1f}m"
        st.metric("Duration", dur_str)
    with col4:
        st.metric("Unique IPs", f"{metadata.get('unique_src_count', 0) + metadata.get('unique_dst_count', 0)}")
    
    st.markdown("</div>", unsafe_allow_html=True)
    
    # TOR indicators
    tor_ind = metadata.get('tor_indicators', {})
    if tor_ind:
        st.markdown(f"""
            <div style="background: {c['bg_card']}; border: 1px solid {c['border']}; 
                        border-radius: 12px; padding: 20px; margin-bottom: 20px;">
                <h3 style="color: {c['warning']}; margin-bottom: 16px; font-weight: 600;">TOR Indicators</h3>
        """, unsafe_allow_html=True)
        
        t1, t2, t3 = st.columns(3)
        with t1:
            st.metric("Port 443 (HTTPS/TOR)", f"{tor_ind.get('port_443_traffic', 0):,}")
            st.metric("Long-lived Conns", f"{tor_ind.get('long_lived_connections', 0)}")
        with t2:
            st.metric("Port 9001 (TOR OR)", f"{tor_ind.get('port_9001_traffic', 0):,}")
            st.metric("Encrypted Payloads", f"{tor_ind.get('encrypted_payloads', 0):,}")
        with t3:
            st.metric("Port 9030 (TOR Dir)", f"{tor_ind.get('port_9030_traffic', 0):,}")
            
            # TOR probability
            tor_score = 0
            if tor_ind.get('port_443_traffic', 0) > 0:
                tor_score += 0.3
            if tor_ind.get('port_9001_traffic', 0) > 0:
                tor_score += 0.4
            if tor_ind.get('encrypted_payloads', 0) > 10:
                tor_score += 0.2
            if tor_ind.get('long_lived_connections', 0) > 5:
                tor_score += 0.1
            
            if tor_score > 0.5:
                st.error(f"TOR Likelihood: {tor_score*100:.0f}%")
            elif tor_score > 0.2:
                st.warning(f"TOR Likelihood: {tor_score*100:.0f}%")
            else:
                st.success(f"TOR Likelihood: {tor_score*100:.0f}%")
        
        st.markdown("</div>", unsafe_allow_html=True)

def render_nodes_table(nodes_df: pd.DataFrame, theme: str):
    """Render network nodes table."""
    c = COLORS[theme]
    
    if nodes_df is None or len(nodes_df) == 0:
        st.info("No node data available")
        return
    
    st.markdown(f"<h3 style='color: {c['text']}; font-weight: 600;'>Network Nodes ({len(nodes_df)})</h3>", 
                unsafe_allow_html=True)
    
    # Style the dataframe
    display_cols = ['ip_address', 'node_type', 'outbound_flows', 'inbound_flows', 'total_bytes']
    display_df = nodes_df[display_cols].copy() if all(col in nodes_df.columns for col in display_cols) else nodes_df.copy()
    
    # Format bytes
    if 'total_bytes' in display_df.columns:
        display_df['total_bytes'] = display_df['total_bytes'].apply(
            lambda x: f"{x/1024:.1f} KB" if x < 1024*1024 else f"{x/1024/1024:.2f} MB"
        )
    
    st.dataframe(
        display_df,
        width="stretch",
        height=300,
        column_config={
            'ip_address': st.column_config.TextColumn('IP Address', width='medium'),
            'node_type': st.column_config.TextColumn('Type', width='small'),
            'outbound_flows': st.column_config.NumberColumn('Outbound', width='small'),
            'inbound_flows': st.column_config.NumberColumn('Inbound', width='small'),
            'total_bytes': st.column_config.TextColumn('Data Volume', width='small')
        },
        hide_index=True
    )
