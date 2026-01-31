"""
Theme and styling configuration for the TOR-UNVEIL dashboard.
"""

# Color palette
COLORS = {
    'dark': {
        'bg_primary': '#0d1117',
        'bg_secondary': '#161b22',
        'bg_card': '#21262d',
        'text': '#c9d1d9',
        'text_muted': '#8b949e',
        'border': '#30363d',
        'accent': '#58a6ff',
        'accent_secondary': '#8b5cf6',
        'success': '#3fb950',
        'warning': '#d29922',
        'danger': '#f85149',
    },
    'light': {
        'bg_primary': '#ffffff',
        'bg_secondary': '#f6f8fa',
        'bg_card': '#ffffff',
        'text': '#24292f',
        'text_muted': '#57606a',
        'border': '#d0d7de',
        'accent': '#0969da',
        'accent_secondary': '#8250df',
        'success': '#1a7f37',
        'warning': '#9a6700',
        'danger': '#cf222e',
    }
}

RISK_COLORS = {
    'HIGH': '#f85149',
    'MEDIUM': '#d29922', 
    'LOW': '#3fb950'
}


def get_css(theme: str = 'dark') -> str:
    """Generate CSS for the selected theme."""
    c = COLORS[theme]
    
    return f"""
    <style>
        /* ========== GLOBAL STYLES ========== */
        .stApp {{
            background-color: {c['bg_primary']} !important;
        }}
        
        /* Hide default Streamlit elements */
        #MainMenu, footer, header {{
            visibility: hidden !important;
        }}
        
        /* ========== SIDEBAR STYLES ========== */
        section[data-testid="stSidebar"] {{
            background-color: {c['bg_secondary']} !important;
            min-width: 320px !important;
            width: 320px !important;
        }}
        
        section[data-testid="stSidebar"] > div {{
            background-color: {c['bg_secondary']} !important;
        }}
        
        [data-testid="stSidebarContent"] {{
            background-color: {c['bg_secondary']} !important;
            padding: 1rem !important;
        }}
        
        [data-testid="stSidebarUserContent"] {{
            padding-top: 1rem !important;
        }}
        
        /* Sidebar text colors */
        section[data-testid="stSidebar"] p,
        section[data-testid="stSidebar"] label,
        section[data-testid="stSidebar"] span {{
            color: {c['text']} !important;
        }}
        
        section[data-testid="stSidebar"] h2 {{
            color: {c['accent']} !important;
        }}
        
        /* ========== MAIN HEADER ========== */
        .main-header {{
            background: linear-gradient(135deg, {c['bg_secondary']} 0%, {c['bg_card']} 100%) !important;
            border: 1px solid {c['border']} !important;
            border-radius: 12px !important;
            padding: 24px 32px !important;
            margin-bottom: 24px !important;
        }}
        
        .main-title {{
            font-size: 2.2rem !important;
            font-weight: 700 !important;
            color: {c['accent']} !important;
            margin: 0 !important;
            letter-spacing: -0.5px !important;
        }}
        
        .main-subtitle {{
            color: {c['text_muted']} !important;
            font-size: 0.95rem !important;
            margin-top: 8px !important;
        }}
        
        .status-badge {{
            display: inline-flex !important;
            align-items: center !important;
            gap: 8px !important;
            background: {c['bg_card']} !important;
            border: 1px solid {c['border']} !important;
            border-radius: 20px !important;
            padding: 6px 14px !important;
            font-size: 0.8rem !important;
            color: {c['text']} !important;
        }}
        
        .status-dot {{
            width: 8px !important;
            height: 8px !important;
            border-radius: 50% !important;
            background: {c['success']} !important;
            animation: pulse 2s infinite !important;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}
        
        /* ========== METRIC CARDS ========== */
        .metric-card {{
            background: {c['bg_card']} !important;
            border: 1px solid {c['border']} !important;
            border-radius: 10px !important;
            padding: 20px !important;
            text-align: center !important;
            transition: border-color 0.2s ease !important;
        }}
        
        .metric-card:hover {{
            border-color: {c['accent']} !important;
        }}
        
        .metric-value {{
            font-size: 2.4rem !important;
            font-weight: 700 !important;
            color: {c['text']} !important;
            line-height: 1 !important;
        }}
        
        .metric-label {{
            font-size: 0.85rem !important;
            color: {c['text_muted']} !important;
            margin-top: 8px !important;
            text-transform: uppercase !important;
            letter-spacing: 0.5px !important;
        }}
        
        /* ========== ALERT BANNER ========== */
        .alert-banner {{
            background: linear-gradient(90deg, rgba(248, 81, 73, 0.15) 0%, rgba(210, 153, 34, 0.15) 100%) !important;
            border: 1px solid {c['danger']} !important;
            border-left: 4px solid {c['danger']} !important;
            border-radius: 8px !important;
            padding: 16px 20px !important;
            margin-bottom: 20px !important;
            display: flex !important;
            align-items: center !important;
            gap: 12px !important;
        }}
        
        .alert-icon {{
            font-size: 1.4rem !important;
        }}
        
        .alert-content {{
            flex: 1 !important;
        }}
        
        .alert-title {{
            font-weight: 600 !important;
            color: {c['danger']} !important;
            font-size: 0.95rem !important;
        }}
        
        .alert-desc {{
            color: {c['text_muted']} !important;
            font-size: 0.85rem !important;
            margin-top: 4px !important;
        }}
        
        .alert-count {{
            background: {c['danger']} !important;
            color: white !important;
            font-weight: 700 !important;
            padding: 8px 16px !important;
            border-radius: 6px !important;
            font-size: 1.1rem !important;
        }}
        
        /* ========== RISK BADGES ========== */
        .risk-badge {{
            display: inline-block !important;
            padding: 4px 12px !important;
            border-radius: 20px !important;
            font-weight: 600 !important;
            font-size: 0.75rem !important;
            text-transform: uppercase !important;
            letter-spacing: 0.5px !important;
        }}
        
        .risk-high {{
            background: rgba(248, 81, 73, 0.2) !important;
            color: {c['danger']} !important;
            border: 1px solid {c['danger']} !important;
        }}
        
        .risk-medium {{
            background: rgba(210, 153, 34, 0.2) !important;
            color: {c['warning']} !important;
            border: 1px solid {c['warning']} !important;
        }}
        
        .risk-low {{
            background: rgba(63, 185, 80, 0.2) !important;
            color: {c['success']} !important;
            border: 1px solid {c['success']} !important;
        }}
        
        /* ========== INVESTIGATION PANEL ========== */
        .investigation-panel {{
            background: {c['bg_card']} !important;
            border: 1px solid {c['border']} !important;
            border-radius: 12px !important;
            padding: 24px !important;
            margin-top: 20px !important;
        }}
        
        .panel-header {{
            display: flex !important;
            justify-content: space-between !important;
            align-items: center !important;
            margin-bottom: 20px !important;
        }}
        
        .panel-title {{
            font-size: 1.2rem !important;
            font-weight: 600 !important;
            color: {c['text']} !important;
        }}
        
        /* ========== FOOTER ========== */
        .footer {{
            margin-top: 60px !important;
            padding: 40px 0 !important;
            border-top: 1px solid {c['border']} !important;
            text-align: center !important;
        }}
        
        .footer-text {{
            color: {c['text_muted']} !important;
            font-size: 0.85rem !important;
            line-height: 1.6 !important;
        }}
        
        .footer-legal {{
            font-weight: 600 !important;
            color: {c['text']} !important;
        }}
        
        /* ========== STREAMLIT OVERRIDES ========== */
        .stMarkdown, .stMarkdown p {{
            color: {c['text']} !important;
        }}
        
        .stSelectbox label, .stSlider label, .stCheckbox label {{
            color: {c['text']} !important;
        }}
        
        /* Data table styling */
        .stDataFrame {{
            border: 1px solid {c['border']} !important;
            border-radius: 8px !important;
        }}
        
        /* Tab styling */
        .stTabs [data-baseweb="tab-list"] {{
            gap: 8px !important;
            background-color: {c['bg_secondary']} !important;
            border-radius: 8px !important;
            padding: 4px !important;
        }}
        
        .stTabs [data-baseweb="tab"] {{
            background-color: transparent !important;
            border-radius: 6px !important;
            color: {c['text_muted']} !important;
            padding: 8px 16px !important;
        }}
        
        .stTabs [aria-selected="true"] {{
            background-color: {c['bg_card']} !important;
            color: {c['accent']} !important;
        }}
        
        /* Button styling */
        .stButton > button {{
            background-color: {c['accent']} !important;
            color: white !important;
            border: none !important;
            border-radius: 6px !important;
            padding: 8px 16px !important;
            font-weight: 500 !important;
        }}
        
        .stButton > button:hover {{
            background-color: {c['accent_secondary']} !important;
        }}
        
        /* Plotly chart backgrounds */
        .js-plotly-plot .plotly {{
            background-color: transparent !important;
        }}
    </style>
    """
