import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
from typing import Dict, List
from dashboard.styles import COLORS, RISK_COLORS

def create_risk_timeline(df: pd.DataFrame, theme: str) -> go.Figure:
    """Create risk score timeline chart."""
    c = COLORS[theme]
    
    df_sorted = df.sort_values('timestamp').copy()
    colors = df_sorted['risk_level'].map(RISK_COLORS).tolist()
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df_sorted['timestamp'],
        y=df_sorted['final_risk_score'],
        mode='lines+markers',
        name='Risk Score',
        line=dict(color=c['accent'], width=2),
        marker=dict(
            size=6,
            color=colors,
            line=dict(width=1, color=c['bg_card'])
        ),
        hovertemplate=(
            '<b>%{customdata[0]}</b><br>'
            'Time: %{x}<br>'
            'Risk: %{y:.2f}<br>'
            'Level: %{customdata[1]}<br>'
            '<extra></extra>'
        ),
        customdata=df_sorted[['flow_id', 'risk_level']].values
    ))
    
    fig.add_hline(y=0.7, line_dash="dash", line_color=c['danger'], 
                  annotation_text="HIGH", annotation_position="right",
                  annotation_font_color=c['danger'])
    fig.add_hline(y=0.4, line_dash="dash", line_color=c['warning'],
                  annotation_text="MEDIUM", annotation_position="right",
                  annotation_font_color=c['warning'])
    
    fig.update_layout(
        title=dict(text='Risk Score Timeline', font=dict(size=14, color=c['text'])),
        xaxis_title='Time',
        yaxis_title='Risk Score',
        height=320,
        margin=dict(l=60, r=40, t=50, b=50),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor=c['bg_card'],
        font=dict(color=c['text']),
        xaxis=dict(gridcolor=c['border'], linecolor=c['border'], tickfont=dict(size=10)),
        yaxis=dict(gridcolor=c['border'], linecolor=c['border'], range=[0, 1], tickformat='.0%', tickfont=dict(size=10)),
        showlegend=False
    )
    return fig

def create_correlation_scatter(df: pd.DataFrame, theme: str) -> go.Figure:
    """Create correlation vs anomaly scatter plot."""
    c = COLORS[theme]
    fig = go.Figure()
    for level in ['LOW', 'MEDIUM', 'HIGH']:
        mask = df['risk_level'] == level
        fig.add_trace(go.Scatter(
            x=df.loc[mask, 'correlation_score'],
            y=df.loc[mask, 'anomaly_score'],
            mode='markers',
            name=level,
            marker=dict(size=8, color=RISK_COLORS[level], opacity=0.7, line=dict(width=1, color=c['bg_card'])),
            hovertemplate=('<b>%{customdata[0]}</b><br>Correlation: %{x:.3f}<br>Anomaly: %{y:.3f}<br>Risk: %{customdata[1]:.2f}<br><extra></extra>'),
            customdata=df.loc[mask, ['flow_id', 'final_risk_score']].values
        ))
    fig.update_layout(
        title=dict(text='Correlation vs Anomaly Analysis', font=dict(size=14, color=c['text'])),
        xaxis_title='Correlation Score',
        yaxis_title='Anomaly Score',
        height=320,
        margin=dict(l=60, r=40, t=50, b=50),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor=c['bg_card'],
        font=dict(color=c['text']),
        xaxis=dict(gridcolor=c['border'], linecolor=c['border'], range=[0, 1]),
        yaxis=dict(gridcolor=c['border'], linecolor=c['border'], range=[0, 1]),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1, bgcolor='rgba(0,0,0,0)')
    )
    return fig

def create_risk_distribution(df: pd.DataFrame, theme: str) -> go.Figure:
    """Create risk level distribution chart."""
    c = COLORS[theme]
    risk_counts = df['risk_level'].value_counts()
    levels = ['LOW', 'MEDIUM', 'HIGH']
    counts = [risk_counts.get(l, 0) for l in levels]
    colors = [RISK_COLORS[l] for l in levels]
    fig = go.Figure(go.Pie(
        labels=levels,
        values=counts,
        hole=0.65,
        marker=dict(colors=colors, line=dict(color=c['bg_card'], width=2)),
        textinfo='label+percent',
        textposition='outside',
        textfont=dict(size=11, color=c['text']),
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>'
    ))
    total = sum(counts)
    fig.add_annotation(text=f"<b>{total}</b><br><span style='font-size:11px'>Total</span>", x=0.5, y=0.5, font=dict(size=20, color=c['text']), showarrow=False)
    fig.update_layout(title=dict(text='Risk Distribution', font=dict(size=14, color=c['text'])), height=280, margin=dict(l=20, r=20, t=50, b=20), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color=c['text']), showlegend=False)
    return fig

def create_feature_importance(importance: Dict[str, float], theme: str) -> go.Figure:
    """Create feature importance bar chart."""
    c = COLORS[theme]
    sorted_items = sorted(importance.items(), key=lambda x: x[1], reverse=True)
    features = [item[0].replace('_', ' ').title() for item in sorted_items]
    values = [item[1] for item in sorted_items]
    fig = go.Figure(go.Bar(
        y=features,
        x=values,
        orientation='h',
        marker=dict(color=values, colorscale=[[0, c['accent']], [1, c['accent_secondary']]], line=dict(width=0)),
        hovertemplate='<b>%{y}</b><br>Importance: %{x:.3f}<extra></extra>'
    ))
    fig.update_layout(title=dict(text='Feature Importance', font=dict(size=14, color=c['text'])), xaxis_title='Importance', height=280, margin=dict(l=140, r=20, t=50, b=40), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor=c['bg_card'], font=dict(color=c['text']), xaxis=dict(gridcolor=c['border'], linecolor=c['border']), yaxis=dict(gridcolor=c['border'], linecolor=c['border'], autorange='reversed', tickfont=dict(size=10)))
    return fig

def create_risk_gauge(score: float, theme: str) -> go.Figure:
    """Create risk score gauge."""
    c = COLORS[theme]
    color = RISK_COLORS['HIGH'] if score >= 0.7 else (RISK_COLORS['MEDIUM'] if score >= 0.4 else RISK_COLORS['LOW'])
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score * 100,
        number={'suffix': '%', 'font': {'size': 32, 'color': c['text']}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': c['border'], 'tickfont': {'size': 10, 'color': c['text_muted']}},
            'bar': {'color': color, 'thickness': 0.8},
            'bgcolor': c['bg_secondary'],
            'borderwidth': 2,
            'bordercolor': c['border'],
            'steps': [
                {'range': [0, 40], 'color': 'rgba(63, 185, 80, 0.2)'},
                {'range': [40, 70], 'color': 'rgba(210, 153, 34, 0.2)'},
                {'range': [70, 100], 'color': 'rgba(248, 81, 73, 0.2)'}
            ]
        }
    ))
    fig.update_layout(height=180, margin=dict(l=20, r=20, t=20, b=20), paper_bgcolor='rgba(0,0,0,0)', font=dict(color=c['text']))
    return fig

def create_feature_bars(row: pd.Series, importance: Dict[str, float], theme: str) -> go.Figure:
    """Create feature contribution bars for a specific flow."""
    c = COLORS[theme]
    feature_cols = ['correlation_score', 'burst_alignment_score', 'peak_time_lag', 'flow_duration', 'packet_rate_mean', 'packet_rate_variance']
    normalized = []
    for col in feature_cols:
        val = row.get(col, 0)
        if col == 'peak_time_lag': norm = 1 - min(1, val / 2000)
        elif col == 'flow_duration': norm = min(1, val / 600)
        elif col == 'packet_rate_mean': norm = min(1, val / 5000)
        elif col == 'packet_rate_variance': norm = min(1, val / 10000)
        else: norm = val
        normalized.append(norm)
    contributions = [n * importance.get(f, 0.1) for n, f in zip(normalized, feature_cols)]
    features = [f.replace('_', ' ').title() for f in feature_cols]
    fig = go.Figure(go.Bar(
        y=features,
        x=contributions,
        orientation='h',
        marker=dict(color=[c['accent'] if contrib > 0.1 else c['text_muted'] for contrib in contributions], line=dict(width=0)),
        hovertemplate='<b>%{y}</b><br>Contribution: %{x:.3f}<extra></extra>'
    ))
    fig.update_layout(title=dict(text='Feature Contributions', font=dict(size=12, color=c['text'])), height=220, margin=dict(l=130, r=20, t=40, b=30), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor=c['bg_card'], font=dict(color=c['text'], size=10), xaxis=dict(gridcolor=c['border'], linecolor=c['border']), yaxis=dict(gridcolor=c['border'], autorange='reversed'))
    return fig

def create_network_graph(connections: List, nodes_df: pd.DataFrame, theme: str) -> go.Figure:
    """Create an interactive network graph visualization."""
    c = COLORS[theme]
    if not connections or nodes_df is None or len(nodes_df) == 0:
        fig = go.Figure()
        fig.add_annotation(text="No connection data available", x=0.5, y=0.5, showarrow=False)
        return fig
    unique_ips = list(set([conn[0] for conn in connections] + [conn[1] for conn in connections]))
    n_nodes = len(unique_ips)
    angles = np.linspace(0, 2*np.pi, n_nodes, endpoint=False)
    radius = 2
    pos = {ip: (radius * np.cos(angle), radius * np.sin(angle)) for ip, angle in zip(unique_ips, angles)}
    edge_x, edge_y = [], []
    for conn in connections[:100]:
        src, dst = conn[0], conn[1]
        if src in pos and dst in pos:
            x0, y0 = pos[src]
            x1, y1 = pos[dst]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
    node_x = [pos[ip][0] for ip in unique_ips if ip in pos]
    node_y = [pos[ip][1] for ip in unique_ips if ip in pos]
    node_colors, node_sizes, node_text = [], [], []
    for ip in unique_ips:
        if ip in pos:
            node_info = nodes_df[nodes_df['ip_address'] == ip]
            if len(node_info) > 0:
                row = node_info.iloc[0]
                node_colors.append(c['accent'] if row['node_type'] == 'Internal' else c['warning'])
                node_sizes.append(10 + min(30, row['total_flows'] * 2) if 'total_flows' in row else 15)
                node_text.append(f"{ip}<br>Flows: {row.get('outbound_flows', 0) + row.get('inbound_flows', 0)}")
            else:
                node_colors.append(c['text_muted'])
                node_sizes.append(12)
                node_text.append(ip)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode='lines', line=dict(width=0.5, color=c['border']), hoverinfo='none', showlegend=False))
    fig.add_trace(go.Scatter(x=node_x, y=node_y, mode='markers+text', marker=dict(size=node_sizes, color=node_colors, line=dict(width=1, color=c['bg_card'])), text=[ip.split('.')[-1] for ip in unique_ips if ip in pos], textposition='top center', textfont=dict(size=8, color=c['text']), hovertext=node_text, hoverinfo='text', showlegend=False))
    fig.update_layout(title=dict(text='Network Topology', font=dict(size=14, color=c['text'])), showlegend=False, hovermode='closest', height=400, margin=dict(l=20, r=20, t=50, b=20), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor=c['bg_card'], xaxis=dict(showgrid=False, zeroline=False, showticklabels=False), yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
    return fig

def create_protocol_distribution(metadata: Dict, theme: str) -> go.Figure:
    """Create protocol distribution pie chart."""
    c = COLORS[theme]
    protocols = metadata.get('protocols', {})
    if not protocols:
        fig = go.Figure()
        fig.add_annotation(text="No protocol data", x=0.5, y=0.5, showarrow=False)
        return fig
    labels, values = list(protocols.keys()), list(protocols.values())
    colors = [c['accent'], c['warning'], c['success'], c['danger']][:len(labels)]
    fig = go.Figure(go.Pie(labels=labels, values=values, hole=0.5, marker=dict(colors=colors, line=dict(color=c['bg_card'], width=2)), textinfo='label+percent', textposition='outside', textfont=dict(size=11, color=c['text'])))
    fig.update_layout(title=dict(text='Protocol Distribution', font=dict(size=14, color=c['text'])), height=300, margin=dict(l=20, r=20, t=50, b=20), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color=c['text']), showlegend=False)
    return fig

def create_port_histogram(metadata: Dict, theme: str) -> go.Figure:
    """Create top ports bar chart."""
    c = COLORS[theme]
    top_ports = metadata.get('top_ports', [])
    if not top_ports:
        fig = go.Figure()
        fig.add_annotation(text="No port data", x=0.5, y=0.5, showarrow=False)
        return fig
    ports = [str(p[0]) for p in top_ports[:10]]
    counts = [p[1] for p in top_ports[:10]]
    colors = [c['danger'] if p[0] in [443, 9001, 9030, 9050, 9051] else c['accent'] for p in top_ports[:10]]
    fig = go.Figure(go.Bar(x=ports, y=counts, marker=dict(color=colors, line=dict(width=0)), hovertemplate='Port %{x}<br>Count: %{y}<extra></extra>'))
    fig.update_layout(title=dict(text='Top Destination Ports', font=dict(size=14, color=c['text'])), xaxis_title='Port', yaxis_title='Packet Count', height=300, margin=dict(l=60, r=20, t=50, b=50), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor=c['bg_card'], font=dict(color=c['text']), xaxis=dict(gridcolor=c['border'], linecolor=c['border'], type='category'), yaxis=dict(gridcolor=c['border'], linecolor=c['border']))
    return fig

def create_traffic_timeline(df: pd.DataFrame, theme: str) -> go.Figure:
    """Create packet timeline visualization."""
    c = COLORS[theme]
    if 'timestamp' not in df.columns:
        fig = go.Figure()
        fig.add_annotation(text="No timestamp data", x=0.5, y=0.5, showarrow=False)
        return fig
    df_sorted = df.sort_values('timestamp').copy()
    df_sorted['ts'] = pd.to_datetime(df_sorted['timestamp'])
    df_sorted.set_index('ts', inplace=True)
    try: packet_counts = df_sorted.resample('1s').size()
    except: packet_counts = df_sorted.groupby(df_sorted.index).size()
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=packet_counts.index, y=packet_counts.values, mode='lines', fill='tozeroy', line=dict(color=c['accent'], width=1), fillcolor=f"rgba({int(c['accent'][1:3], 16)}, {int(c['accent'][3:5], 16)}, {int(c['accent'][5:7], 16)}, 0.3)", hovertemplate='Time: %{x}<br>Flows: %{y}<extra></extra>'))
    fig.update_layout(title=dict(text='Traffic Timeline', font=dict(size=14, color=c['text'])), xaxis_title='Time', yaxis_title='Flow Count', height=250, margin=dict(l=60, r=20, t=50, b=50), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor=c['bg_card'], font=dict(color=c['text']), xaxis=dict(gridcolor=c['border'], linecolor=c['border']), yaxis=dict(gridcolor=c['border'], linecolor=c['border']))
    return fig

def create_bytes_distribution(df: pd.DataFrame, theme: str) -> go.Figure:
    """Create bytes distribution histogram."""
    c = COLORS[theme]
    if 'total_bytes' not in df.columns:
        fig = go.Figure()
        fig.add_annotation(text="No bytes data", x=0.5, y=0.5, showarrow=False)
        return fig
    fig = go.Figure(go.Histogram(x=df['total_bytes'], nbinsx=30, marker=dict(color=c['accent'], line=dict(width=1, color=c['bg_card'])), hovertemplate='Bytes: %{x}<br>Count: %{y}<extra></extra>'))
    fig.update_layout(title=dict(text='Flow Size Distribution', font=dict(size=14, color=c['text'])), xaxis_title='Bytes per Flow', yaxis_title='Count', height=250, margin=dict(l=60, r=20, t=50, b=50), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor=c['bg_card'], font=dict(color=c['text']), xaxis=dict(gridcolor=c['border'], linecolor=c['border']), yaxis=dict(gridcolor=c['border'], linecolor=c['border']))
    return fig
