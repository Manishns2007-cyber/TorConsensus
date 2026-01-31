"""Interactive visualizations for TOR analysis: network paths, timelines, heatmaps.

Uses Plotly for rich interactive charts and matplotlib for static reports.
"""
import os
import json
import base64
from io import BytesIO
from datetime import datetime

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False


def plot_density_overlay(exit_density, guard_density, outpath):
    """Static matplotlib version for backwards compatibility."""
    exit_arr = np.array(exit_density)
    guard_arr = np.array(guard_density)
    n = max(len(exit_arr), len(guard_arr))
    if len(exit_arr) != n:
        exit_arr = np.interp(np.linspace(0, 1, n), np.linspace(0, 1, len(exit_arr)), exit_arr)
    if len(guard_arr) != n:
        guard_arr = np.interp(np.linspace(0, 1, n), np.linspace(0, 1, len(guard_arr)), guard_arr)

    plt.figure(figsize=(6, 3))
    x = np.linspace(0, 1, n)
    plt.plot(x, exit_arr, label='Exit', color='tab:blue')
    plt.plot(x, guard_arr, label='Guard', color='tab:orange')
    plt.fill_between(x, exit_arr, alpha=0.15, color='tab:blue')
    plt.fill_between(x, guard_arr, alpha=0.15, color='tab:orange')
    plt.legend()
    plt.xlabel('Normalized time')
    plt.ylabel('Normalized packet density')
    plt.tight_layout()
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    plt.savefig(outpath)
    plt.close()


def generate_html_report(analysis_id, result, outpath, image_paths=None):
    """Generate HTML report with embedded visuals."""
    image_paths = image_paths or []
    now = datetime.utcnow().isoformat() + 'Z'
    lines = [
        "<html><head><meta charset='utf-8'><title>FTDC Report</title></head><body>",
        f"<h1>FTDC Analysis {analysis_id}</h1>",
        f"<p><strong>Timestamp (UTC):</strong> {now}</p>",
        "<div style='background:#fff3cd;padding:8px;border:1px solid #ffeeba;margin-bottom:1rem;'><strong>Disclaimer:</strong> Probabilistic correlation only; no identification.</div>",
        "<h2>Summary</h2>",
        f"<pre>{json.dumps(result, indent=2)}</pre>"
    ]
    if image_paths:
        lines.append("<h2>Visuals</h2>")
        for path in image_paths:
            lines.append(f"<div><img src='{path}' style='max-width:800px;width:100%'/></div>")
    lines.append("</body></html>")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, 'w') as handle:
        handle.write('\n'.join(lines))
    return outpath


def create_network_path_diagram(paths, output_path=None):
    """Create an interactive TOR network diagram showing Guard -> Middle -> Exit paths with Sankey-style flow."""
    if not PLOTLY_AVAILABLE or not paths:
        return None
    
    try:
        # Collect unique nodes for each hop
        guard_nodes = {}  # fingerprint -> {nickname, ip, country, confidence}
        middle_nodes = {}
        exit_nodes = {}
        
        # Process paths and collect node info
        for p in paths[:10]:
            nodes = p.get('path', [])
            conf = p.get('confidence', 0.5)
            if len(nodes) >= 3:
                # Guard node
                g = nodes[0]
                g_fp = (g.get('fingerprint') or 'unknown')[:12]
                if g_fp not in guard_nodes:
                    guard_nodes[g_fp] = {
                        'nickname': g.get('nickname', ''),
                        'ip': g.get('ip', ''),
                        'country': g.get('country', ''),
                        'confidence': conf
                    }
                else:
                    guard_nodes[g_fp]['confidence'] = max(guard_nodes[g_fp]['confidence'], conf)
                
                # Middle node
                m = nodes[1]
                m_fp = (m.get('fingerprint') or 'unknown')[:12]
                if m_fp not in middle_nodes:
                    middle_nodes[m_fp] = {
                        'nickname': m.get('nickname', ''),
                        'ip': m.get('ip', ''),
                        'country': m.get('country', '')
                    }
                
                # Exit node
                e = nodes[2]
                e_fp = (e.get('fingerprint') or 'unknown')[:12]
                if e_fp not in exit_nodes:
                    exit_nodes[e_fp] = {
                        'nickname': e.get('nickname', ''),
                        'ip': e.get('ip', ''),
                        'country': e.get('country', '')
                    }
        
        if not guard_nodes and not middle_nodes and not exit_nodes:
            return None
        
        # Create Sankey diagram for accurate TOR flow visualization
        # Build node labels and colors
        all_labels = []
        all_colors = []
        node_customdata = []
        
        # Guard nodes (green)
        guard_list = list(guard_nodes.keys())
        for fp in guard_list:
            info = guard_nodes[fp]
            label = f"🛡️ {info['nickname'] or fp[:8]}"
            all_labels.append(label)
            all_colors.append('#27ae60')
            node_customdata.append(f"Guard: {fp}<br>IP: {info['ip']}<br>Country: {info['country']}<br>Confidence: {info['confidence']:.1%}")
        
        # Middle nodes (blue)
        middle_list = list(middle_nodes.keys())
        for fp in middle_list:
            info = middle_nodes[fp]
            label = f"🔄 {info['nickname'] or fp[:8]}"
            all_labels.append(label)
            all_colors.append('#3498db')
            node_customdata.append(f"Middle: {fp}<br>IP: {info['ip']}<br>Country: {info['country']}")
        
        # Exit nodes (red)
        exit_list = list(exit_nodes.keys())
        for fp in exit_list:
            info = exit_nodes[fp]
            label = f"🚪 {info['nickname'] or fp[:8]}"
            all_labels.append(label)
            all_colors.append('#e74c3c')
            node_customdata.append(f"Exit: {fp}<br>IP: {info['ip']}<br>Country: {info['country']}")
        
        # Build links (flows between nodes)
        sources = []
        targets = []
        values = []
        link_colors = []
        link_labels = []
        
        for p in paths[:10]:
            nodes = p.get('path', [])
            conf = p.get('confidence', 0.5)
            if len(nodes) >= 3:
                g_fp = (nodes[0].get('fingerprint') or 'unknown')[:12]
                m_fp = (nodes[1].get('fingerprint') or 'unknown')[:12]
                e_fp = (nodes[2].get('fingerprint') or 'unknown')[:12]
                
                try:
                    g_idx = guard_list.index(g_fp)
                    m_idx = len(guard_list) + middle_list.index(m_fp)
                    e_idx = len(guard_list) + len(middle_list) + exit_list.index(e_fp)
                    
                    # Guard -> Middle link
                    sources.append(g_idx)
                    targets.append(m_idx)
                    values.append(max(1, int(conf * 10)))
                    link_colors.append(f'rgba(39, 174, 96, {0.3 + conf * 0.4})')
                    link_labels.append(f'Confidence: {conf:.1%}')
                    
                    # Middle -> Exit link
                    sources.append(m_idx)
                    targets.append(e_idx)
                    values.append(max(1, int(conf * 10)))
                    link_colors.append(f'rgba(52, 152, 219, {0.3 + conf * 0.4})')
                    link_labels.append(f'Confidence: {conf:.1%}')
                except ValueError:
                    continue
        
        if not sources:
            return None
        
        # Create Sankey diagram
        fig = go.Figure(data=[go.Sankey(
            node=dict(
                pad=20,
                thickness=25,
                line=dict(color='white', width=2),
                label=all_labels,
                color=all_colors,
                customdata=node_customdata,
                hovertemplate='%{customdata}<extra></extra>'
            ),
            link=dict(
                source=sources,
                target=targets,
                value=values,
                color=link_colors,
                label=link_labels,
                hovertemplate='%{label}<extra></extra>'
            )
        )])
        
        # Add column labels
        fig.add_annotation(x=0.0, y=1.1, text="<b>GUARD NODES</b>", showarrow=False,
                         font=dict(size=14, color='#27ae60'), xanchor='center')
        fig.add_annotation(x=0.5, y=1.1, text="<b>MIDDLE NODES</b>", showarrow=False,
                         font=dict(size=14, color='#3498db'), xanchor='center')
        fig.add_annotation(x=1.0, y=1.1, text="<b>EXIT NODES</b>", showarrow=False,
                         font=dict(size=14, color='#e74c3c'), xanchor='center')
        
        fig.update_layout(
            title={
                'text': "TOR Circuit Path Reconstruction",
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18, 'color': '#2c3e50', 'family': 'Arial, sans-serif'}
            },
            height=500,
            paper_bgcolor='#ffffff',
            plot_bgcolor='#ffffff',
            margin=dict(l=20, r=20, t=80, b=20),
            font=dict(size=11, family='Arial, sans-serif')
        )
        
        if output_path:
            fig.write_html(output_path)
        
        html_output = fig.to_html(include_plotlyjs=False, full_html=False, div_id='network_diagram')
        print(f"[NetworkDiagram] Generated Sankey HTML: {len(html_output)} bytes")
        return html_output
    except Exception as e:
        print(f"Error creating network diagram: {e}")
        import traceback
        traceback.print_exc()
        return None


def create_timeline_reconstruction(analysis_events, output_path=None):
    """Create timeline visualization of TOR traffic events."""
    if not PLOTLY_AVAILABLE or not analysis_events:
        return None
    
    try:
        events = sorted(analysis_events, key=lambda x: x.get('timestamp', 0))
        
        if not events:
            print("[Timeline] No events to display")
            return None
        
        # Process timestamps and create display labels
        timestamps = []
        display_times = []
        for i, e in enumerate(events):
            ts = e.get('timestamp', 0)
            if isinstance(ts, (int, float)):
                dt = datetime.fromtimestamp(ts)
                timestamps.append(i)  # Use index for x-axis positioning
                display_times.append(dt.strftime('%H:%M:%S'))
            elif isinstance(ts, str):
                timestamps.append(i)
                display_times.append(ts[:19] if len(ts) > 19 else ts)
            else:
                timestamps.append(i)
                display_times.append(str(ts))
        
        event_types = [e.get('event_type', 'unknown') for e in events]
        descriptions = [e.get('description', '') for e in events]
        
        color_map = {
            'analysis_started': '#3498db',
            'consensus_fetched': '#27ae60',
            'exit_detected': '#e74c3c',
            'guard_candidate': '#9b59b6',
            'correlation': '#f39c12',
            'circuit_established': '#1abc9c',
            'unknown': '#95a5a6'
        }
        colors = [color_map.get(et, '#95a5a6') for et in event_types]
        
        # Create labels for display
        labels = [et.replace('_', ' ').title() for et in event_types]
        
        fig = go.Figure()
        
        # Add connecting line
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=[1] * len(timestamps),
            mode='lines',
            line=dict(color='#bdc3c7', width=2, dash='dot'),
            showlegend=False,
            hoverinfo='skip'
        ))
        
        # Add event markers
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=[1] * len(timestamps),
            mode='markers',
            marker=dict(
                size=30,
                color=colors,
                line=dict(width=3, color='white'),
                symbol='circle'
            ),
            text=labels,
            customdata=list(zip(descriptions, display_times)),
            hovertemplate='<b>%{text}</b><br>%{customdata[0]}<br><i>%{customdata[1]}</i><extra></extra>',
            showlegend=False
        ))
        
        # Add text labels below markers
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=[0.7] * len(timestamps),
            mode='text',
            text=labels,
            textfont=dict(size=9, color='#2c3e50'),
            showlegend=False,
            hoverinfo='skip'
        ))
        
        # Add time labels above markers
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=[1.3] * len(timestamps),
            mode='text',
            text=display_times,
            textfont=dict(size=8, color='#7f8c8d'),
            showlegend=False,
            hoverinfo='skip'
        ))
        
        fig.update_layout(
            title={
                'text': "TOR Traffic Analysis Timeline",
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18, 'color': '#2c3e50', 'family': 'Arial, sans-serif'}
            },
            xaxis=dict(
                showticklabels=False,
                showgrid=False,
                zeroline=False,
                range=[-0.5, len(timestamps) - 0.5]
            ),
            yaxis=dict(
                showticklabels=False,
                showgrid=False,
                zeroline=False,
                range=[0.3, 1.6]
            ),
            hovermode='closest',
            height=250,
            plot_bgcolor='#ffffff',
            paper_bgcolor='#ffffff',
            margin=dict(l=20, r=20, t=60, b=20)
        )
        
        if output_path:
            fig.write_html(output_path)
        
        html_output = fig.to_html(include_plotlyjs=False, full_html=False, div_id='timeline')
        print(f"[Timeline] Generated HTML: {len(html_output)} bytes, {len(events)} events")
        return html_output
    except Exception as e:
        print(f"Error creating timeline: {e}")
        import traceback
        traceback.print_exc()
        return None


def create_confidence_heatmap(guard_scores, output_path=None):
    """Create heatmap showing confidence scores for guard candidates."""
    if not PLOTLY_AVAILABLE or not guard_scores:
        return None
    
    try:
        top_guards = guard_scores[:20]
        guards = []
        for g in top_guards:
            nickname = g.get('nickname', '')
            fingerprint = g.get('fingerprint', 'unknown')
            guards.append(nickname if nickname else fingerprint[:8])
        
        metrics = ['bandwidth', 'quality', 'proximity']
        matrix = []
        for metric in metrics:
            row = []
            for g in top_guards:
                scores = g.get('scores', {})
                # Try to get the metric value, fall back to confidence or 0
                val = scores.get(metric)
                if val is None:
                    val = g.get('confidence', 0.0) * (0.5 + 0.5 * (metrics.index(metric) / len(metrics)))
                row.append(float(val))
            matrix.append(row)
        
        # Create text annotations
        text_matrix = [[f'{val:.2f}' for val in row] for row in matrix]
        
        fig = go.Figure(data=go.Heatmap(
            z=matrix, x=guards, y=metrics, 
            colorscale=[
                [0, '#d73027'],
                [0.25, '#fc8d59'],
                [0.5, '#fee08b'],
                [0.75, '#d9ef8b'],
                [1, '#1a9850']
            ],
            text=text_matrix, 
            texttemplate='%{text}',
            textfont={"size": 11, "color": "#2c3e50", "family": "Arial, sans-serif"}, 
            hovertemplate='<b>Guard:</b> %{x}<br><b>Metric:</b> %{y}<br><b>Score:</b> %{z:.3f}<extra></extra>',
            colorbar=dict(
                title=dict(text="Score<br>Value", side="right", font=dict(size=12)),
                tickmode="linear",
                tick0=0,
                dtick=0.2,
                thickness=20,
                len=0.7
            ),
            zmid=0.5
        ))
        
        fig.update_layout(
            title={
                'text': "Guard Node Confidence Heatmap - Multi-Factor Scoring",
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18, 'color': '#2c3e50', 'family': 'Arial, sans-serif'}
            },
            xaxis_title="Guard Nodes (Top 20)",
            yaxis_title="Scoring Metrics",
            xaxis=dict(tickangle=-45, tickfont={'size': 9}, side='bottom'),
            yaxis=dict(tickfont={'size': 11, 'family': 'Arial, sans-serif'}, autorange='reversed'),
            height=350,
            plot_bgcolor='#ffffff',
            paper_bgcolor='#ffffff',
            margin=dict(l=100, r=60, t=70, b=120)
        )
        
        if output_path:
            fig.write_html(output_path)
        return fig.to_html(include_plotlyjs=False, full_html=False, div_id='heatmap')
    except Exception as e:
        print(f"Error creating heatmap: {e}")
        return None


def create_geographic_relay_map(relays):
    """Create geographic map of relay locations."""
    if not PLOTLY_AVAILABLE:
        return None

    # ISO-2 to ISO-3 country code mapping (partial, extend as needed)
    ISO2_TO_ISO3 = {
        'US': 'USA', 'GB': 'GBR', 'DE': 'DEU', 'FR': 'FRA', 'NL': 'NLD', 'CA': 'CAN', 'SE': 'SWE',
        'RU': 'RUS', 'RO': 'ROU', 'CH': 'CHE', 'FI': 'FIN', 'PL': 'POL', 'UA': 'UKR', 'IT': 'ITA',
        'ES': 'ESP', 'TR': 'TUR', 'AT': 'AUT', 'CZ': 'CZE', 'BG': 'BGR', 'NO': 'NOR', 'JP': 'JPN',
        'SG': 'SGP', 'AU': 'AUS', 'IE': 'IRL', 'DK': 'DNK', 'BE': 'BEL', 'KR': 'KOR', 'IN': 'IND',
        'BR': 'BRA', 'IL': 'ISR', 'LV': 'LVA', 'LT': 'LTU', 'EE': 'EST', 'IS': 'ISL', 'PT': 'PRT',
        'LU': 'LUX', 'SK': 'SVK', 'GR': 'GRC', 'HU': 'HUN', 'MX': 'MEX', 'ZA': 'ZAF', 'AR': 'ARG',
        'CL': 'CHL', 'NZ': 'NZL', 'TH': 'THA', 'ID': 'IDN', 'MY': 'MYS', 'PH': 'PHL', 'CN': 'CHN',
        'HK': 'HKG', 'TW': 'TWN', 'VN': 'VNM', 'IR': 'IRN', 'AE': 'ARE', 'SA': 'SAU', 'EG': 'EGY',
        'NG': 'NGA', 'PK': 'PAK', 'BD': 'BGD', 'CO': 'COL', 'PE': 'PER', 'VE': 'VEN', 'CU': 'CUB',
        'XX': 'Unknown', 'UN': 'Unknown', '': 'Unknown', None: 'Unknown'
    }

    try:
        country_counts = {}
        for r in relays:
            country = r.get('country', 'Unknown')
            # Convert ISO-2 to ISO-3 if needed
            if country and len(country) == 2 and country.upper() in ISO2_TO_ISO3:
                country = ISO2_TO_ISO3[country.upper()]
            if not country or country in ('Unknown', 'XX', 'UN', ''):
                continue
            country_counts[country] = country_counts.get(country, 0) + 1

        if not country_counts:
            print("[GeoMap] No valid country data for relays.")
            return None

        fig = go.Figure(data=go.Choropleth(
            locations=list(country_counts.keys()),
            z=list(country_counts.values()),
            locationmode='ISO-3',
            colorscale=[
                [0, '#f0f9ff'],
                [0.2, '#cfe2ff'],
                [0.4, '#9ec5fe'],
                [0.6, '#6ea8fe'],
                [0.8, '#3d8bfd'],
                [1, '#0d6efd']
            ],
            colorbar=dict(
                title=dict(text="Relay<br>Count", side="right", font=dict(size=13)),
                thickness=20,
                len=0.7,
                x=1.02
            ),
            hovertemplate='<b>Country:</b> %{location}<br><b>Relays:</b> %{z}<br><extra></extra>',
            marker_line_color='#7f8c8d',
            marker_line_width=0.5
        ))

        fig.update_layout(
            title={
                'text': "Geographic Distribution of TOR Relays",
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18, 'color': '#2c3e50', 'family': 'Arial, sans-serif'}
            },
            geo=dict(
                showframe=True,
                framecolor='#bdc3c7',
                showcoastlines=True,
                coastlinecolor='#95a5a6',
                projection_type='natural earth',
                bgcolor='#f5f5f5',
                landcolor='#ffffff',
                oceancolor='#e6f2ff',
                showcountries=True,
                countrycolor='#bdc3c7',
                countrywidth=0.5
            ),
            height=450,
            paper_bgcolor='#ffffff',
            margin=dict(l=10, r=10, t=60, b=10)
        )

        return fig.to_html(include_plotlyjs=False, full_html=False, div_id='geo_map')
    except Exception as e:
        print(f"Error creating geographic map: {e}")
        return None


def create_density_overlay_plotly(exit_density, guard_density):
    """Interactive Plotly version with enhanced bar chart visualization for better value display."""
    if not PLOTLY_AVAILABLE:
        return None
    
    try:
        exit_arr = np.array(exit_density, dtype=float)
        guard_arr = np.array(guard_density, dtype=float)
        
        if len(exit_arr) == 0 or len(guard_arr) == 0:
            print("[DensityPlot] Empty density arrays")
            return None
        
        n = max(len(exit_arr), len(guard_arr))
        
        if len(exit_arr) != n:
            exit_arr = np.interp(np.linspace(0, 1, n), np.linspace(0, 1, len(exit_arr)), exit_arr)
        if len(guard_arr) != n:
            guard_arr = np.interp(np.linspace(0, 1, n), np.linspace(0, 1, len(guard_arr)), guard_arr)
        
        # Sample data for better visibility (take every nth point to avoid overcrowding)
        sample_rate = max(1, n // 50)  # Show max 50 bars
        indices = list(range(0, n, sample_rate))
        
        x_labels = [f"{i/(n-1):.2f}" for i in indices]
        exit_sampled = [float(exit_arr[i]) for i in indices]
        guard_sampled = [float(guard_arr[i]) for i in indices]
        
        # Create grouped bar chart
        fig = go.Figure()
        
        # Exit Node bars
        fig.add_trace(go.Bar(
            x=x_labels,
            y=exit_sampled,
            name='Exit Node',
            marker=dict(
                color='#3498db',
                line=dict(color='#2980b9', width=1)
            ),
            text=[f'{v:.4f}' for v in exit_sampled],
            textposition='outside',
            textfont=dict(size=9, color='#2c3e50'),
            hovertemplate='<b>Exit Node</b><br>Time: %{x}<br>Density: %{y:.6f}<extra></extra>',
            width=0.4
        ))
        
        # Guard Node bars
        fig.add_trace(go.Bar(
            x=x_labels,
            y=guard_sampled,
            name='Guard Node',
            marker=dict(
                color='#e74c3c',
                line=dict(color='#c0392b', width=1)
            ),
            text=[f'{v:.4f}' for v in guard_sampled],
            textposition='outside',
            textfont=dict(size=9, color='#2c3e50'),
            hovertemplate='<b>Guard Node</b><br>Time: %{x}<br>Density: %{y:.6f}<extra></extra>',
            width=0.4
        ))
        
        fig.update_layout(
            title={
                'text': "Time-Density Correlation Analysis<br><sub>Traffic Pattern Comparison (Exit vs Guard Nodes)</sub>",
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18, 'color': '#2c3e50', 'family': 'Arial, sans-serif'}
            },
            xaxis=dict(
                title="Normalized Time",
                showgrid=True,
                gridcolor='#e0e0e0',
                tickangle=-45,
                tickfont=dict(size=10),
                showticklabels=True
            ),
            yaxis=dict(
                title="Traffic Density",
                showgrid=True,
                gridcolor='#e0e0e0',
                rangemode='tozero',
                tickformat='.4f'
            ),
            barmode='group',
            height=600,
            plot_bgcolor='#fafafa',
            paper_bgcolor='#ffffff',
            legend=dict(
                x=0.5,
                y=1.08,
                xanchor='center',
                orientation='h',
                bgcolor='rgba(255,255,255,0.95)',
                bordercolor='#bdc3c7',
                borderwidth=1,
                font={'size': 12, 'family': 'Arial, sans-serif'}
            ),
            margin=dict(l=70, r=30, t=120, b=100),
            hoverlabel=dict(
                bgcolor="white",
                font_size=12,
                font_family="Arial"
            )
        )
        
        # Add correlation coefficient annotation
        from scipy.stats import pearsonr
        try:
            corr, _ = pearsonr(exit_sampled, guard_sampled)
            fig.add_annotation(
                text=f"Correlation: {corr:.4f}",
                xref="paper", yref="paper",
                x=0.98, y=0.98,
                xanchor='right', yanchor='top',
                showarrow=False,
                bgcolor="rgba(255,255,255,0.9)",
                bordercolor="#3498db",
                borderwidth=2,
                borderpad=8,
                font=dict(size=14, color='#2c3e50', family='Arial, sans-serif')
            )
        except:
            pass
        
        html_output = fig.to_html(include_plotlyjs=False, full_html=False, div_id='density_overlay')
        print(f"[DensityPlot] Generated HTML: {len(html_output)} bytes")
        return html_output
    except Exception as e:
        print(f"Error creating density overlay: {e}")
        import traceback
        traceback.print_exc()
        return None


def create_geographic_map(relay_data, output_path=None, map_type='world'):
    """Create an interactive geographic map showing Tor relay distribution.
    
    Args:
        relay_data: List of relay dictionaries with 'country', 'latitude', 'longitude', 
                   'fingerprint', 'nickname', 'bandwidth', and optional 'confidence' fields
        output_path: Optional path to save HTML output
        map_type: 'world' for world map, 'scatter' for scatter geo, 'choropleth' for country counts
    
    Returns:
        str: HTML string of the map or None if error
    """
    if not PLOTLY_AVAILABLE or not relay_data:
        print("[GeoMap] Plotly not available or no data")
        return None
    
    try:
        # Prepare data
        countries = []
        latitudes = []
        longitudes = []
        labels = []
        sizes = []
        colors = []
        hover_texts = []
        
        for relay in relay_data:
            country = relay.get('country', 'Unknown')
            lat = relay.get('latitude')
            lon = relay.get('longitude')
            nickname = relay.get('nickname', 'Unknown')
            fingerprint = relay.get('fingerprint', '')[:12]
            bandwidth = relay.get('bandwidth', 0)
            confidence = relay.get('confidence', 0)
            relay_type = relay.get('type', 'Relay')
            
            # Skip if no coordinates
            if lat is None or lon is None:
                continue
            
            countries.append(country)
            latitudes.append(lat)
            longitudes.append(lon)
            labels.append(f"{nickname} ({country})")
            
            # Size based on bandwidth (normalized)
            size = max(5, min(30, (bandwidth / 1000000) * 5)) if bandwidth else 10
            sizes.append(size)
            
            # Color based on confidence or relay type
            if confidence > 0:
                # Use confidence for correlation results
                colors.append(confidence)
            else:
                # Default color scheme
                colors.append(0.5)
            
            # Hover text
            hover_text = (
                f"<b>{nickname}</b><br>"
                f"Fingerprint: {fingerprint}<br>"
                f"Country: {country}<br>"
                f"Type: {relay_type}<br>"
                f"Bandwidth: {bandwidth / 1000000:.2f} MB/s<br>"
            )
            if confidence > 0:
                hover_text += f"Confidence: {confidence:.1%}"
            hover_texts.append(hover_text)
        
        if not latitudes:
            print("[GeoMap] No valid geographic coordinates found")
            return None
        
        if map_type == 'scatter':
            # Scatter geo plot
            fig = go.Figure(data=go.Scattergeo(
                lon=longitudes,
                lat=latitudes,
                text=labels,
                mode='markers',
                marker=dict(
                    size=sizes,
                    color=colors,
                    colorscale='Viridis',
                    showscale=True,
                    colorbar=dict(title="Confidence"),
                    line=dict(width=0.5, color='white'),
                    sizemode='diameter'
                ),
                hovertext=hover_texts,
                hoverinfo='text'
            ))
            
            fig.update_layout(
                title={
                    'text': 'Tor Relay Geographic Distribution',
                    'x': 0.5,
                    'xanchor': 'center',
                    'font': {'size': 20, 'color': '#2c3e50'}
                },
                geo=dict(
                    projection_type='natural earth',
                    showland=True,
                    landcolor='rgb(243, 243, 243)',
                    coastlinecolor='rgb(204, 204, 204)',
                    showocean=True,
                    oceancolor='rgb(230, 245, 255)',
                    showcountries=True,
                    countrycolor='rgb(204, 204, 204)'
                ),
                height=600,
                margin=dict(l=0, r=0, t=80, b=0)
            )
        
        elif map_type == 'choropleth':
            # Country-based choropleth map
            from collections import Counter
            country_counts = Counter(countries)
            country_names = list(country_counts.keys())
            counts = list(country_counts.values())
            
            fig = go.Figure(data=go.Choropleth(
                locations=country_names,
                z=counts,
                locationmode='country names',
                colorscale='Blues',
                colorbar=dict(title="Relay Count"),
                hovertemplate='<b>%{location}</b><br>Relays: %{z}<extra></extra>'
            ))
            
            fig.update_layout(
                title={
                    'text': 'Tor Relay Concentration by Country',
                    'x': 0.5,
                    'xanchor': 'center',
                    'font': {'size': 20, 'color': '#2c3e50'}
                },
                geo=dict(
                    projection_type='natural earth',
                    showframe=False,
                    showcoastlines=True,
                    showcountries=True
                ),
                height=600,
                margin=dict(l=0, r=0, t=80, b=0)
            )
        
        else:  # world map with paths
            # Create paths between relays if we have correlation data
            fig = go.Figure()
            
            # Add relay markers
            fig.add_trace(go.Scattergeo(
                lon=longitudes,
                lat=latitudes,
                text=labels,
                mode='markers',
                marker=dict(
                    size=sizes,
                    color=colors,
                    colorscale='Viridis',
                    showscale=True,
                    colorbar=dict(title="Confidence"),
                    line=dict(width=0.5, color='white'),
                    sizemode='diameter'
                ),
                hovertext=hover_texts,
                hoverinfo='text',
                name='Relays'
            ))
            
            fig.update_layout(
                title={
                    'text': 'Tor Network Geographic Visualization',
                    'x': 0.5,
                    'xanchor': 'center',
                    'font': {'size': 20, 'color': '#2c3e50'}
                },
                geo=dict(
                    projection_type='orthographic',
                    showland=True,
                    landcolor='rgb(243, 243, 243)',
                    coastlinecolor='rgb(204, 204, 204)',
                    showocean=True,
                    oceancolor='rgb(230, 245, 255)',
                    showcountries=True,
                    countrycolor='rgb(204, 204, 204)'
                ),
                height=700,
                margin=dict(l=0, r=0, t=80, b=0)
            )
        
        # Save or return HTML
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            fig.write_html(output_path)
            print(f"[GeoMap] Saved to {output_path}")
            return output_path
        
        html_output = fig.to_html(include_plotlyjs=False, full_html=False, div_id='geographic_map')
        print(f"[GeoMap] Generated HTML: {len(html_output)} bytes")
        return html_output
        
    except Exception as e:
        print(f"Error creating geographic map: {e}")
        import traceback
        traceback.print_exc()
        return None


def create_circuit_path_map(path_data, output_path=None):
    """Create an interactive map showing circuit paths from Guard -> Middle -> Exit.
    
    Args:
        path_data: List of dictionaries with path information including:
                  - 'path': List of nodes with lat/lon/country/nickname
                  - 'confidence': Confidence score for the path
        output_path: Optional path to save HTML
    
    Returns:
        str: HTML string of the map
    """
    if not PLOTLY_AVAILABLE or not path_data:
        return None
    
    try:
        fig = go.Figure()
        
        # Process each path
        for idx, path_info in enumerate(path_data[:10]):  # Limit to top 10 paths
            path_nodes = path_info.get('path', [])
            confidence = path_info.get('confidence', 0.5)
            
            if len(path_nodes) < 2:
                continue
            
            # Extract coordinates
            lons = []
            lats = []
            labels = []
            
            for node in path_nodes:
                lat = node.get('latitude')
                lon = node.get('longitude')
                if lat is not None and lon is not None:
                    lats.append(lat)
                    lons.append(lon)
                    labels.append(f"{node.get('nickname', 'Unknown')} ({node.get('country', '??')})")
            
            if len(lons) < 2:
                continue
            
            # Draw path lines
            opacity = 0.3 + (confidence * 0.5)
            line_width = 1 + (confidence * 2)
            
            fig.add_trace(go.Scattergeo(
                lon=lons,
                lat=lats,
                mode='lines+markers',
                line=dict(width=line_width, color=f'rgba(231, 76, 60, {opacity})'),
                marker=dict(
                    size=[15, 10, 12],  # Guard larger, middle smaller, exit medium
                    color=['#27ae60', '#3498db', '#e74c3c'],  # Green, Blue, Red
                    line=dict(width=1, color='white')
                ),
                text=labels,
                hovertext=[f"<b>{l}</b><br>Confidence: {confidence:.1%}" for l in labels],
                hoverinfo='text',
                name=f"Path {idx + 1}",
                showlegend=False
            ))
        
        fig.update_layout(
            title={
                'text': 'Tor Circuit Paths: Guard → Middle → Exit',
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 20, 'color': '#2c3e50'}
            },
            geo=dict(
                projection_type='natural earth',
                showland=True,
                landcolor='rgb(243, 243, 243)',
                coastlinecolor='rgb(204, 204, 204)',
                showocean=True,
                oceancolor='rgb(230, 245, 255)',
                showcountries=True,
                countrycolor='rgb(204, 204, 204)'
            ),
            height=600,
            margin=dict(l=0, r=0, t=80, b=50)
        )
        
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            fig.write_html(output_path)
            return output_path
        
        html_output = fig.to_html(include_plotlyjs=False, full_html=False, div_id='circuit_path_map')
        return html_output
        
    except Exception as e:
        print(f"Error creating circuit path map: {e}")
        import traceback
        traceback.print_exc()
        return None


def create_country_analysis_chart(relay_data, output_path=None):
    """Create bar charts analyzing Tor relays by country with bandwidth metrics.
    
    Args:
        relay_data: List of relay dictionaries with country and bandwidth info
        output_path: Optional path to save HTML
    
    Returns:
        str: HTML string of the chart
    """
    if not PLOTLY_AVAILABLE or not relay_data:
        return None
    
    try:
        from collections import defaultdict
        
        # Aggregate by country
        country_stats = defaultdict(lambda: {'count': 0, 'bandwidth': 0, 'avg_confidence': []})
        
        for relay in relay_data:
            country = relay.get('country', 'Unknown')
            bandwidth = relay.get('bandwidth', 0)
            confidence = relay.get('confidence', 0)
            
            country_stats[country]['count'] += 1
            country_stats[country]['bandwidth'] += bandwidth
            if confidence > 0:
                country_stats[country]['avg_confidence'].append(confidence)
        
        # Prepare data for plotting
        countries = []
        counts = []
        bandwidths = []
        avg_confidences = []
        
        for country, stats in sorted(country_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:15]:
            countries.append(country)
            counts.append(stats['count'])
            bandwidths.append(stats['bandwidth'] / 1000000)  # Convert to MB/s
            avg_conf = np.mean(stats['avg_confidence']) if stats['avg_confidence'] else 0
            avg_confidences.append(avg_conf)
        
        # Create subplots
        from plotly.subplots import make_subplots
        
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=('Relay Count by Country', 'Total Bandwidth by Country'),
            vertical_spacing=0.15,
            specs=[[{"type": "bar"}], [{"type": "bar"}]]
        )
        
        # Relay count chart
        fig.add_trace(
            go.Bar(
                x=countries,
                y=counts,
                marker=dict(
                    color=counts,
                    colorscale='Blues',
                    showscale=False
                ),
                text=counts,
                textposition='outside',
                hovertemplate='<b>%{x}</b><br>Relays: %{y}<extra></extra>'
            ),
            row=1, col=1
        )
        
        # Bandwidth chart
        fig.add_trace(
            go.Bar(
                x=countries,
                y=bandwidths,
                marker=dict(
                    color=bandwidths,
                    colorscale='Greens',
                    showscale=False
                ),
                text=[f'{b:.1f}' for b in bandwidths],
                textposition='outside',
                hovertemplate='<b>%{x}</b><br>Bandwidth: %{y:.2f} MB/s<extra></extra>'
            ),
            row=2, col=1
        )
        
        fig.update_xaxes(title_text="Country", row=2, col=1)
        fig.update_yaxes(title_text="Number of Relays", row=1, col=1)
        fig.update_yaxes(title_text="Total Bandwidth (MB/s)", row=2, col=1)
        
        fig.update_layout(
            title={
                'text': 'Geographic Analysis: Top Countries by Relay Distribution',
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18, 'color': '#2c3e50'}
            },
            height=800,
            showlegend=False,
            margin=dict(l=60, r=30, t=100, b=60)
        )
        
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            fig.write_html(output_path)
            return output_path
        
        html_output = fig.to_html(include_plotlyjs=False, full_html=False, div_id='country_analysis')
        return html_output
        
    except Exception as e:
        print(f"Error creating country analysis: {e}")
        import traceback
        traceback.print_exc()
        return None
