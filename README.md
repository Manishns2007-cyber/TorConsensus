# TorConsensus

## Overview
TorConsensus is a forensic research tool implementing Flow Time-Density Correlation (FTDC) methodology for passive Tor traffic analysis. The system analyzes network packet captures to identify potential correlations between traffic flows using temporal and statistical patterns, without decrypting or injecting any data.

## Approach

### 1. **Data Collection & Preprocessing**
The system begins with two parallel data streams:

- **Network Capture**: PCAP files containing Tor circuit traffic are ingested and parsed to extract packet-level metadata (timestamps, sizes, directions)
- **Consensus Data**: Live Tor network consensus is fetched from Onionoo APIs, providing relay metadata including fingerprints, IP addresses, bandwidth, flags, and geographic locations

### 2. **Feature Engineering (FTDC Method)**
The FTDC extractor transforms raw packet streams into analyzable features:

- **Temporal Windows**: Traffic is divided into sliding windows of 20-50ms intervals
- **Density Metrics**: For each window, we calculate:
  - Packet counts (upstream/downstream)
  - Byte totals and variance
  - Direction changes (flow reversals)
  - Burst intensity (concentration of packets in short periods)
- **Feature Vectors**: Each flow is represented as a time-series vector capturing its traffic density signature

### 3. **Correlation Analysis**
The correlation engine employs a dual-metric approach:

- **Cosine Similarity**: Measures the directional similarity between two traffic density vectors, identifying patterns with similar shapes
- **Normalized Area Difference**: Quantifies the absolute magnitude differences between flows, detecting volume mismatches
- **Composite Scoring**: Combines both metrics with weights to produce probabilistic confidence scores (0-100%)

### 4. **Path Reconstruction**
Using correlation scores and network topology:

- **Guard Node Identification**: High-confidence correlations at the entry point identify likely guard relays
- **Circuit Path Inference**: Traces the probable path through Guard → Middle → Exit relays
- **Ranking System**: Candidate nodes are ranked by correlation confidence, bandwidth capacity, and temporal alignment

### 5. **Node Correlation & Enrichment**
Relay metadata is enriched with:

- Geographic mapping (country, AS number)
- Bandwidth and flags (Guard, Exit, Fast, Stable)
- Historical patterns and relationship mapping
- Cross-circuit correlation to identify relay reuse patterns

### 6. **Visualization & Reporting**
Results are presented through:

- **Density Overlays**: Time-aligned plots showing traffic patterns between entry/exit flows
- **Interactive Dashboards**: Web-based interface for PCAP upload and real-time analysis
- **Geographic Maps**: 
  - World scatter maps showing relay distribution with confidence-based coloring
  - Choropleth maps displaying relay concentration by country
  - Interactive circuit path maps tracing Guard → Middle → Exit routes across geographic regions
  - Country-based analysis charts with bandwidth and relay statistics
- **Forensic HTML Reports**: Comprehensive reports with embedded visualizations, correlation matrices, and confidence metrics
- **Ethical Disclaimers**: All outputs include prominent notices about probabilistic nature and limitations

### 7. **Quality Assurance**
The system implements multiple safeguards:

- **Noise Sensitivity**: Correlation scores account for network jitter and timing variations
- **False Positive Mitigation**: Multi-metric validation reduces spurious correlations
- **Confidence Intervals**: All results include uncertainty quantification
- **Reproducible Testing**: Automated test suite validates core components

## Key Design Principles

- **Passive Analysis**: No active probing, injection, or watermarking of Tor circuits
- **Metadata Only**: Analysis is based purely on packet timing and sizes, never payload content
- **Probabilistic Output**: All results are presented as confidence-ranked possibilities, not certainties
- **Ethical Framework**: Built-in disclaimers and accuracy limitations in all interfaces
- **Modularity**: Independent components (consensus, extraction, correlation, visualization) for flexible deployment
- **Geographic Context**: Visual representation of relay locations and circuit paths across countries for enhanced forensic analysis

## Geographic Visualization Features

The system includes comprehensive geographic analysis and visualization capabilities:

### Interactive Maps
- **Scatter Geo Maps**: Display individual relay positions on world map with:
  - Size indicators based on bandwidth capacity
  - Color coding by confidence scores
  - Hover tooltips with relay details (nickname, country, bandwidth, flags)
  - Multiple projection types (natural earth, orthographic)

- **Choropleth Maps**: Show relay concentration by country:
  - Color intensity indicates number of relays per country
  - Quick identification of high-density regions
  - Interactive country-level statistics

- **Circuit Path Maps**: Visualize complete Guard → Middle → Exit paths:
  - Animated path lines connecting circuit nodes
  - Color-coded nodes (Green=Guard, Blue=Middle, Red=Exit)
  - Line opacity and width scaled by confidence scores
  - Geographic routing visualization

### Country Analysis
- **Distribution Charts**: Bar charts showing:
  - Top countries by relay count
  - Total bandwidth by country
  - Average confidence scores by region
- **Statistical Breakdown**: Detailed metrics per country including relay types and flags

### Usage
Run the geographic visualization demo:
```bash
cd scripts
python demo_geographic_visualization.py
```

This generates interactive HTML maps that can be opened in any browser, showing:
- Global relay distribution
- Circuit path visualization
- Country-level statistics
- Correlation confidence mapping

## Technical Workflow

```
PCAP Upload → Feature Extraction → Consensus Fetch
                    ↓                      ↓
              [Time Windows]        [Relay Metadata]
                    ↓                      ↓
              Density Vectors → Correlation Engine
                                          ↓
                                  [Scoring Matrix]
                                          ↓
                           Path Reconstruction → Report Generation
                                          ↓
                                  [HTML/Dashboard Output]
```

## Limitations & Considerations

- **Timing Noise**: Network latency variations can reduce correlation accuracy
- **Guard Discovery**: Requires sufficient traffic volume for reliable pattern detection
- **Circuit Multiplexing**: Multiple circuits on same connection may confuse correlations
- **Research Tool**: Designed for forensic research and education, not operational deployment
- **Legal/Ethical**: Must be used in compliance with applicable laws and ethical guidelines
