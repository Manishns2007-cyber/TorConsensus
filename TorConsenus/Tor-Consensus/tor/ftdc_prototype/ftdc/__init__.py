"""FTDC (Flow Time-Density Correlation) TOR Analysis System.

A comprehensive forensic analysis system for TOR network traffic investigation.
Implements sophisticated algorithms for timing analysis, circuit reconstruction,
and iterative learning to identify probable origin IPs behind TOR-based traffic.
"""

__version__ = "2.0.0"
__author__ = "TN Police Cybercrime Division"
__license__ = "Proprietary"

# Core modules
from .consensus import TorConsensusCollector
from .extractor import FTDCExtractor
from .correlation import combined_score, cosine_similarity, area_difference
from .path import infer_paths
from .visualization import plot_density_overlay, generate_html_report

# Import advanced modules
try:
    from .node_correlation import NodeCorrelationEngine
    from .database import FTDCDatabase
    from .report_generator import ForensicReportGenerator
    from .orchestrator import TorAnalysisOrchestrator
    from .comprehensive_analysis import ComprehensiveTorAnalysis
    ADVANCED_AVAILABLE = True
except ImportError:
    ADVANCED_AVAILABLE = False

# Import real-time capture (optional)
try:
    from .realtime_capture import RealTimeTorCapture, LiveCorrelationEngine
    REALTIME_AVAILABLE = True
except ImportError:
    REALTIME_AVAILABLE = False

__all__ = [
    "TorConsensusCollector",
    "FTDCExtractor",
    "combined_score",
    "cosine_similarity",
    "area_difference",
    "infer_paths",
    "plot_density_overlay",
    "generate_html_report",
]

# Add advanced modules if available
if ADVANCED_AVAILABLE:
    __all__.extend([
        "NodeCorrelationEngine",
        "FTDCDatabase",
        "ForensicReportGenerator",
        "TorAnalysisOrchestrator",
        "ComprehensiveTorAnalysis",
    ])

if REALTIME_AVAILABLE:
    __all__.extend([
        "RealTimeTorCapture",
        "LiveCorrelationEngine"
    ])


def get_version():
    """Return the current version of FTDC."""
    return __version__


def check_dependencies():
    """Check availability of optional dependencies."""
    deps = {
        'core': True,
        'advanced': ADVANCED_AVAILABLE,
        'realtime': REALTIME_AVAILABLE
    }
    
    try:
        import plotly
        deps['plotly'] = True
    except ImportError:
        deps['plotly'] = False
    
    try:
        import reportlab
        deps['reportlab'] = True
    except ImportError:
        deps['reportlab'] = False
    
    try:
        from scapy.all import sniff
        deps['scapy'] = True
    except ImportError:
        deps['scapy'] = False
    
    return deps


def print_system_info():
    """Print system information and capability summary."""
    print("=" * 70)
    print("TOR-Unveil FTDC Analysis System")
    print(f"Version: {__version__}")
    print("=" * 70)
    print()
    
    deps = check_dependencies()
    
    print("System Capabilities:")
    print(f"  ✓ Core Analysis: {'Available' if deps['core'] else 'Not Available'}")
    print(f"  {'✓' if deps.get('advanced') else '✗'} Advanced Features: {'Available' if deps.get('advanced') else 'Not Available'}")
    print(f"  {'✓' if deps.get('realtime') else '✗'} Real-time Capture: {'Available' if deps.get('realtime') else 'Not Available'}")
    print()
    
    print("Dependencies:")
    print(f"  {'✓' if deps.get('plotly') else '✗'} Plotly (interactive visualizations)")
    print(f"  {'✓' if deps.get('reportlab') else '✗'} ReportLab (PDF reports)")
    print(f"  {'✓' if deps.get('scapy') else '✗'} Scapy (packet capture and analysis)")
    print()
    
    if not all([deps.get('plotly'), deps.get('reportlab'), deps.get('scapy')]):
        print("To install missing dependencies:")
        if not deps.get('plotly'):
            print("  pip install plotly")
        if not deps.get('reportlab'):
            print("  pip install reportlab")
        if not deps.get('scapy'):
            print("  pip install scapy")
        print()
    
    print("Quick Start:")
    print("  Dashboard:      streamlit run streamlit_dashboard/app.py")
    print("  CLI Analysis:   python -m ftdc.orchestrator <pcap_file>")
    print("=" * 70)
