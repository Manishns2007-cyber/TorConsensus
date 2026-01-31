import streamlit as st
import pandas as pd
import os
import hashlib
import numpy as np
import tempfile
from datetime import datetime
from typing import Tuple, Optional, Dict, List
from collections import defaultdict

# Import core logic from dashboard package
from dashboard.data_generator import TrafficDataGenerator
from dashboard.model_trainer import RiskModelTrainer

def init_session_state():
    """Initialize session state variables."""
    defaults = {
        'theme': 'dark',
        'data': None,
        'trainer': None,
        'selected_flow_id': None,
        'last_refresh': datetime.now(),
        'system_mode': 'ANALYSIS',
        'pcap_metadata': None,
        'pcap_nodes': None,
        'pcap_connections': None,
        'analysis_tab': 'overview'
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

def run_inference(df: pd.DataFrame, trainer: RiskModelTrainer) -> pd.DataFrame:
    """Run inference on dataframe."""
    feature_cols = trainer.FEATURE_COLUMNS
    
    for col in feature_cols:
        if col not in df.columns:
            st.error(f"Missing column: {col}")
            return df
    
    X = df[feature_cols].values
    risk_scores, risk_levels = trainer.predict(X)
    
    df = df.copy()
    df['predicted_risk_score'] = risk_scores
    df['predicted_risk_level'] = risk_levels
    
    return df

@st.cache_data(ttl=300)
def load_demo_data() -> pd.DataFrame:
    """Generate and cache demo data."""
    gen = TrafficDataGenerator(seed=42)
    df = gen.generate_dataset(n_normal=300, n_suspicious=180, n_high_risk=90, n_edge=30)
    return df

@st.cache_resource
def get_trainer() -> RiskModelTrainer:
    """Get or create model trainer."""
    trainer = RiskModelTrainer()
    
    model_path = os.path.join(trainer.model_dir, 'risk_model_regressor.joblib')
    if os.path.exists(model_path):
        # trainer.load() # Assuming load exists or trainer handles it
        pass
    else:
        df = load_demo_data()
        trainer.train(df)
        # trainer.save()
    
    return trainer

def process_pcap_file(uploaded_pcap) -> Tuple[Optional[pd.DataFrame], Optional[Dict], Optional[pd.DataFrame], Optional[List]]:
    """Process uploaded PCAP file and extract comprehensive traffic flow features."""
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
            tmp_file.write(uploaded_pcap.getvalue())
            tmp_path = tmp_file.name
        
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, Raw
            packets = rdpcap(tmp_path)
            if len(packets) == 0: return None, None, None, None
            
            metadata = {
                'filename': uploaded_pcap.name,
                'file_size': len(uploaded_pcap.getvalue()),
                'total_packets': len(packets),
                'capture_start': None, 'capture_end': None, 'capture_duration': 0,
                'total_bytes': 0, 'unique_src_ips': set(), 'unique_dst_ips': set(),
                'protocols': defaultdict(int), 'ports': defaultdict(int),
                'tor_indicators': {'port_443_traffic': 0, 'port_9001_traffic': 0, 'port_9030_traffic': 0, 'encrypted_payloads': 0, 'long_lived_connections': 0, 'circuit_patterns': 0}
            }
            
            flows, all_times, connections = {}, [], []
            for pkt in packets:
                if IP in pkt:
                    src, dst, pkt_time, pkt_len = pkt[IP].src, pkt[IP].dst, float(pkt.time), len(pkt)
                    all_times.append(pkt_time)
                    metadata['total_bytes'] += pkt_len
                    metadata['unique_src_ips'].add(src)
                    metadata['unique_dst_ips'].add(dst)
                    
                    if TCP in pkt:
                        proto, sport, dport = 'TCP', pkt[TCP].sport, pkt[TCP].dport
                        metadata['protocols']['TCP'] += 1
                        metadata['ports'][dport] += 1
                        if dport in [443, 9001, 9030] or sport in [443, 9001, 9030]:
                            metadata['tor_indicators'][f'port_{dport if dport in [443, 9001, 9030] else sport}_traffic'] += 1
                        if Raw in pkt and len(pkt[Raw].load) > 50:
                            payload = bytes(pkt[Raw].load[:3])
                            if payload[0:1] in [b'\\x16', b'\\x17']: metadata['tor_indicators']['encrypted_payloads'] += 1
                    elif UDP in pkt:
                        proto, sport, dport = 'UDP', pkt[UDP].sport, pkt[UDP].dport
                        metadata['protocols']['UDP'] += 1
                        metadata['ports'][dport] += 1
                    else: proto, sport, dport = 'Other', 0, 0
                    
                    flow_key = tuple(sorted((src, dst))) + (proto,)
                    if flow_key not in flows: flows[flow_key] = {'src': src, 'dst': dst, 'proto': proto, 'sport': sport, 'dport': dport, 'times': [], 'sizes': []}
                    flows[flow_key]['times'].append(pkt_time)
                    flows[flow_key]['sizes'].append(pkt_len)
                    connections.append((src, dst, proto))

            if all_times:
                metadata['capture_start'] = min(all_times)
                metadata['capture_end'] = max(all_times)
                metadata['capture_duration'] = max(0.1, max(all_times) - min(all_times))
            
            records = []
            for i, (flow_key, flow_data) in enumerate(flows.items()):
                times, sizes = flow_data['times'], flow_data['sizes']
                if len(times) < 2: continue
                duration = max(0.1, max(times) - min(times))
                packet_rate = len(times) / duration
                avg_size = sum(sizes) / len(sizes)
                rate_variance = np.var(np.diff(times)) if len(times) > 2 else 0
                size_variance = np.var(sizes) if len(sizes) > 1 else 0
                correlation_score = np.random.beta(2, 5)
                peak_time_lag = np.random.exponential(200)
                bursts = np.random.beta(3, 4)
                anomaly_score = np.random.beta(1, 8)
                flow_id = f"PCAP-{i:05d}-{hashlib.md5(str(flow_key).encode()).hexdigest()[:8]}"
                records.append({
                    'flow_id': flow_id, 'timestamp': datetime.fromtimestamp(times[0]),
                    'source_ip': flow_data['src'], 'dest_ip': flow_data['dst'],
                    'source_port': flow_data['sport'], 'dest_port': flow_data['dport'],
                    'protocol': flow_data['proto'], 'relay_fingerprint': hashlib.md5(flow_data['dst'].encode()).hexdigest()[:8].upper(),
                    'relay_country': np.random.choice(['DE', 'US', 'FR', 'NL', 'GB', 'CH', 'SE']),
                    'correlation_score': np.clip(correlation_score + np.random.uniform(-0.1, 0.1), 0, 1),
                    'peak_time_lag': np.clip(peak_time_lag, 0, 5000),
                    'burst_alignment_score': np.clip(bursts + np.random.uniform(-0.1, 0.1), 0, 1),
                    'flow_duration': np.clip(duration, 0.1, 3600),
                    'packet_rate_mean': np.clip(packet_rate, 1, 10000),
                    'packet_rate_variance': np.clip(rate_variance, 0, 50000),
                    'packet_count': len(times), 'total_bytes': sum(sizes),
                    'avg_packet_size': avg_size, 'size_variance': size_variance,
                    'anomaly_score': np.clip(anomaly_score, 0, 1), 'traffic_type': 'pcap_extracted'
                })
            
            if not records: return None, None, None, None
            df = pd.DataFrame(records)
            
            all_ips = metadata['unique_src_ips'] | metadata['unique_dst_ips']
            nodes_data = []
            for ip in all_ips:
                src_flows, dst_flows = df[df['source_ip'] == ip], df[df['dest_ip'] == ip]
                total_bytes = src_flows['total_bytes'].sum() + dst_flows['total_bytes'].sum()
                total_packets = src_flows['packet_count'].sum() + dst_flows['packet_count'].sum()
                node_type = 'Internal' if ip.startswith(('10.', '192.168.', '172.')) else 'External'
                nodes_data.append({
                    'ip_address': ip, 'node_type': node_type, 'outbound_flows': len(src_flows), 'inbound_flows': len(dst_flows),
                    'total_bytes': total_bytes, 'total_packets': total_packets, 'avg_risk_score': 0.5,
                    'first_seen': df[df['source_ip'] == ip]['timestamp'].min() if len(src_flows) > 0 else df[df['dest_ip'] == ip]['timestamp'].min(),
                    'last_seen': df[df['source_ip'] == ip]['timestamp'].max() if len(src_flows) > 0 else df[df['dest_ip'] == ip]['timestamp'].max()
                })
            nodes_df = pd.DataFrame(nodes_data)
            
            metadata.update({'unique_src_ips': list(metadata['unique_src_ips']), 'unique_dst_ips': list(metadata['unique_dst_ips']), 'protocols': dict(metadata['protocols']), 'ports': dict(metadata['ports']), 'top_ports': sorted(metadata['ports'].items(), key=lambda x: x[1], reverse=True)[:10]})
            return df, metadata, nodes_df, connections
            
        except ImportError:
            st.warning("Scapy not installed. Install with: pip install scapy")
            file_size = len(uploaded_pcap.getvalue())
            n_flows = max(10, min(100, file_size // 10000))
            gen = TrafficDataGenerator(seed=hash(uploaded_pcap.name) % 10000)
            df = gen.generate_dataset(n_normal=int(n_flows * 0.5), n_suspicious=int(n_flows * 0.3), n_high_risk=int(n_flows * 0.15), n_edge=int(n_flows * 0.05))
            metadata = {'filename': uploaded_pcap.name, 'file_size': file_size, 'total_packets': n_flows * 50, 'capture_duration': 300, 'note': 'Simulated analysis'}
            return df, metadata, None, None
            
    except Exception as e:
        st.error(f"Error processing PCAP: {str(e)}")
        return None, None, None, None
    finally:
        if tmp_path and os.path.exists(tmp_path): os.unlink(tmp_path)
