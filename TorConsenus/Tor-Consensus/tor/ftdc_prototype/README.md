# TOR-UNVEIL - Forensic TOR Traffic Analysis System

A comprehensive forensic tool for passive TOR traffic analysis using **Flow Time-Density Correlation (FTDC)** methodology. Built for law enforcement and cybersecurity professionals.

---

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
  - [Web Dashboard](#1-web-dashboard-recommended)
  - [Command Line Interface](#2-command-line-interface)
  - [Docker Deployment](#3-docker-deployment)
- [Project Structure](#-project-structure)
- [How It Works](#-how-it-works)
- [Configuration](#-configuration)
- [Troubleshooting](#-troubleshooting)

---

## ✨ Features

- **PCAP Analysis** - Upload and analyze TOR network captures
- **FTDC Correlation** - Time-density pattern matching to identify traffic flows
- **AI Risk Engine** - Machine learning-based threat scoring
- **Origin IP Approximation** - Probabilistic source identification
- **Geographic Visualization** - Interactive maps showing relay locations and circuit paths
- **Forensic Reports** - Generate HTML reports with evidence documentation
- **Real-time Capture** - Live TOR traffic monitoring (requires root privileges)

---

## 🚀 Quick Start

### Option 1: Run with Script (Easiest)

```bash
cd tor/ftdc_prototype
./start.sh development
```

Access the dashboard at: **http://localhost:5007**

### Option 2: Run Directly

```bash
cd tor/ftdc_prototype
pip install -r requirements.txt
streamlit run dashboard/main.py --server.port 5007
```

---

## 📦 Installation

### Prerequisites

- **Python 3.9+**
- **pip** (Python package manager)
- **libpcap** (for PCAP processing)

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd TorConsensus/tor/ftdc_prototype
```

### Step 2: Create Virtual Environment (Recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Install Package (Optional)

```bash
pip install -e .
```

This enables the `tor-unveil` CLI command globally.

### Verify Installation

```bash
python -c "import streamlit; import scapy; import pandas; print('All dependencies OK!')"
```

---

## 💻 Usage

### 1. Web Dashboard (Recommended)

The Streamlit dashboard provides a user-friendly interface for all analysis tasks.

**Start the Dashboard:**

```bash
# Using start script
./start.sh development

# OR directly with streamlit
streamlit run dashboard/main.py --server.port 5007

# OR using the installed package
tor-unveil dashboard
```

**Dashboard Features:**

| Tab | Description |
|-----|-------------|
| **Demo Data** | Test with synthetic data |
| **Upload CSV** | Analyze pre-processed flow data |
| **Upload PCAP** | Full PCAP analysis pipeline |

**Steps to Analyze a PCAP:**

1. Open browser to `http://localhost:5007`
2. In sidebar, select **"Upload PCAP"** as data source
3. Click **Browse files** and select your `.pcap` file
4. Wait for analysis to complete
5. View results in the tabs:
   - **Risk Analysis** - Threat scores and alerts
   - **Network Graph** - Visual flow connections
   - **Origin IP** - Probable source identification
   - **Geographic Map** - Relay locations

---

### 2. Command Line Interface

For automation and batch processing, use the CLI tool.

**Analyze a PCAP File:**

```bash
tor-unveil analyze /path/to/capture.pcap
```

**With Options:**

```bash
tor-unveil analyze capture.pcap \
    --output-dir ./results \
    --window 50 \
    --case-id "CASE-2025-001" \
    --investigator "John Doe" \
    --agency "Cybercrime Unit" \
    --export html
```

**Capture Live Traffic:**

```bash
# Requires root/sudo privileges
sudo tor-unveil capture -i eth0 -d 60 -o tor_traffic.pcap --analyze
```

**List Previous Analyses:**

```bash
tor-unveil list -n 20
```

**Show System Info:**

```bash
tor-unveil info
```

---

### 3. Docker Deployment

For production deployment with isolation.

**Build and Run:**

```bash
docker-compose up -d
```

**Access:**
- Dashboard: `http://localhost:5007`

**Stop:**

```bash
docker-compose down
```

**View Logs:**

```bash
docker-compose logs -f tor-unveil
```

---

## 📁 Project Structure

```
ftdc_prototype/
├── start.sh              # Startup script
├── requirements.txt      # Python dependencies
├── docker-compose.yml    # Docker configuration
├── Dockerfile            # Container build instructions
│
├── bin/
│   └── tor-unveil        # CLI entry point
│
├── dashboard/            # Streamlit web interface
│   ├── main.py           # Dashboard entry point
│   ├── styles.py         # UI styling
│   ├── data_loader.py    # Data processing
│   ├── visualizations.py # Charts and graphs
│   └── components/       # UI components
│       ├── ui.py
│       ├── sidebar.py
│       ├── pcap_ui.py
│       ├── origin_tab.py
│       └── investigation.py
│
├── ftdc/                 # Core analysis engine
│   ├── consensus.py      # TOR relay data collector
│   ├── extractor.py      # FTDC feature extraction
│   ├── correlation.py    # Traffic correlation engine
│   ├── node_correlation.py  # Node matching
│   ├── path.py           # Circuit path reconstruction
│   ├── orchestrator.py   # Analysis coordinator
│   ├── ai_risk_engine.py # ML risk scoring
│   ├── origin_ip_approximator.py  # Source IP inference
│   ├── visualization.py  # Map and chart generation
│   ├── report_generator.py  # Forensic reports
│   ├── database.py       # SQLite storage
│   ├── realtime_capture.py  # Live capture
│   └── config.py         # Configuration
│
├── uploads/              # Uploaded PCAP files
├── results/              # Generated reports
├── models/               # Trained ML models
└── logs/                 # Application logs
```

---

## 🔬 How It Works

### Analysis Pipeline

```
PCAP File → Feature Extraction → Correlation → Risk Scoring → Report
    │              │                  │              │
    ▼              ▼                  ▼              ▼
  Parse      Sliding window     Cosine + Area    AI Engine
  Packets    20-50ms density    similarity       ML Model
```

### 1. Feature Extraction (FTDC)

Transforms raw packets into analyzable vectors:
- Temporal windows: 20-50ms sliding intervals
- Metrics: packet counts, byte totals, direction changes, burst intensity

### 2. Correlation Engine

Dual-metric matching:
- **Cosine Similarity**: Pattern shape matching
- **Area Difference**: Volume comparison
- **Combined Score**: 0-100% confidence

### 3. Path Reconstruction

Infers circuit path: **Guard → Middle → Exit** relays using:
- Correlation scores
- Relay metadata from TOR consensus
- Geographic and bandwidth analysis

### 4. Risk Assessment

Machine learning model evaluates:
- Traffic anomalies
- Known malicious patterns
- Behavioral indicators

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Server settings
PORT=5007
HOST=0.0.0.0

# Analysis settings
CONSENSUS_CACHE_TTL=3600
MAX_CONCURRENT_ANALYSES=5
LOG_LEVEL=INFO

# Database
DATABASE_PATH=ftdc/ftdc_analysis.db
```

### Dashboard Settings

Modify in `ftdc/config.py`:

```python
FTDC_WINDOW_MS = 50          # Correlation window size
MIN_CORRELATION_SCORE = 0.6  # Minimum score threshold
BATCH_SIZE = 1000            # Packets per batch
```

---

## 🔧 Troubleshooting

### Common Issues

**1. "ModuleNotFoundError: No module named 'streamlit'"**

```bash
pip install -r requirements.txt
```

**2. "Permission denied" when capturing**

```bash
sudo tor-unveil capture -i eth0  # Need root for live capture
```

**3. Dashboard won't start**

```bash
# Check if port is in use
lsof -i :5007

# Kill existing process
kill -9 <PID>

# Try different port
streamlit run dashboard/main.py --server.port 5008
```

**4. PCAP parsing fails**

- Ensure file is valid PCAP format (not PCAPNG)
- Check file permissions
- Verify libpcap is installed:
  ```bash
  # Ubuntu/Debian
  sudo apt install libpcap-dev
  
  # macOS
  brew install libpcap
  ```

**5. Memory errors with large PCAPs**

- Split large files: `editcap -c 100000 large.pcap split.pcap`
- Increase system memory or use streaming mode

---

## 📊 Output Examples

### Risk Analysis View

| Flow ID | Source | Destination | Risk Score | Status |
|---------|--------|-------------|------------|--------|
| FL-001 | 10.0.0.5 | Guard Node | 85% | ⚠️ High |
| FL-002 | 10.0.0.5 | Exit Node | 45% | ✓ Medium |

### Generated Reports

Reports are saved to `ftdc/results/`:
- `<uuid>_report.html` - Full forensic report
- Includes: timeline, node correlations, geographic maps, evidence summary

---

## 📜 Ethical Notice

This tool is designed for **authorized forensic investigations only**.

- ✅ Passive analysis only - no injection or modification
- ✅ Metadata analysis - never decrypts payload content
- ✅ Results are **probabilistic** - not definitive proof
- ✅ Always include confidence levels in reports

---

## 📞 Support

For issues or questions:
1. Check the [Troubleshooting](#-troubleshooting) section
2. Review logs in `logs/` directory
3. Open an issue in the repository

---

## 📄 License

This project is for authorized forensic use by law enforcement agencies.

---

**Built for Tamil Nadu Police Cybercrime Division** 🛡️
