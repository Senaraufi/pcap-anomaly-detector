# PCAP Anomaly Detector

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Issues](https://img.shields.io/badge/issues-0-green.svg)
![Stars](https://img.shields.io/badge/stars-0-grey.svg)
![Last Commit](https://img.shields.io/badge/last%20commit-today-grey.svg)

A Python-based network traffic analyzer that parses PCAP files and detects suspicious domains and unusual traffic spikes.

## Quick Start

### Professional Interactive Tool (Recommended)

```bash
# Launch the professional security tool interface
./interactive-tool.sh

# Features:
# - Interactive menu system
# - Professional security tool appearance
# - File selection interface
# - Progress indicators
# - System status monitoring
```

### Quick Start Script

```bash
# Use the start script - handles everything automatically!
./start.sh test                    # Run with test file
./start.sh advanced traffic.pcap    # Advanced analysis
./start.sh help                     # See all options
```

### Manual Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Basic analysis
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap'])"

# Advanced analysis with all detection features
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--advanced'])"

# Save results
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--output', 'results.txt'])"
```

## Features

- **PCAP Parsing**: Extract network traffic data using Scapy
- **Suspicious Domain Detection**: Pattern matching, DGA detection, entropy analysis
- **Traffic Spike Detection**: Volume spikes, IP activity, port usage anomalies
- **Advanced Detection**: Data exfiltration, malware indicators, network anomalies
- **CLI Interface**: Colored output with tables and risk assessment
- **Export Results**: Save detailed findings to text files

## Detection Capabilities

### Basic Analysis
- Suspicious domains (malware TLDs, DGA, high entropy)
- Traffic spikes (volume, IP activity, port usage)

### Advanced Analysis (`--advanced`)
- **Data Exfiltration**: Large outbound transfers, high-frequency connections
- **Malware Indicators**: Beaconing patterns, suspicious domains
- **Network Anomalies**: Rare protocols, port scans, IP anomalies

## Installation

```bash
# Clone and setup
git clone <repository-url>
cd pcap-anomaly-detector
pip install -r requirements.txt

# Optional: Install in development mode
pip install -e .
```

## Usage Examples

### Professional Interactive Tool

```bash
# Launch the professional interface
./interactive-tool.sh

# Interactive menu options:
# 1) Quick Analysis           - Fast scan with basic detection
# 2) Advanced Analysis        - Comprehensive security scan
# 3) Domain Analysis          - Focus on suspicious domains
# 4) Traffic Analysis         - Analyze traffic patterns
# 5) Malware Detection        - Scan for malware indicators
# 6) Exfiltration Check        - Detect data theft attempts
# 7) Network Anomalies        - Find unusual network activity
# 8) File Information          - Show PCAP file details
# 9) Test with Sample         - Run analysis on test data
# 10) System Status            - Check tool configuration
# 0) Exit                     - Terminate session
```

### Using Start Script

```bash
# Quick test
./start.sh test

# Basic commands
./start.sh info traffic.pcap                    # File info
./start.sh analyze traffic.pcap                # Full analysis
./start.sh advanced traffic.pcap --verbose     # Advanced analysis + verbose

# Targeted analysis
./start.sh domains traffic.pcap                # Domains only
./start.sh traffic traffic.pcap                # Traffic only
./start.sh exfil traffic.pcap                  # Exfiltration only
./start.sh malware traffic.pcap                # Malware only
./start.sh anomalies traffic.pcap              # Anomalies only

# Save results
./start.sh advanced traffic.pcap --output report.txt

# Setup only
./start.sh setup                               # Setup environment
```

### Manual Commands

```bash
# Basic commands
python -c "from pcap_analyzer.cli import cli; cli(['info', 'traffic.pcap'])"                    # File info
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap'])"              # Full analysis
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--verbose'])" # Verbose mode

# Targeted analysis
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--domains-only'])"    # Domains only
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--traffic-only'])"    # Traffic only
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--exfil-only'])"      # Exfiltration only
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--malware-only'])"    # Malware only
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--anomaly-only'])"    # Anomalies only

# Output options
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--output', 'results.txt'])" # Save results
```

## Python API

```python
from pcap_analyzer import PcapAnomalyDetector

# Initialize and analyze
detector = PcapAnomalyDetector(verbose=True)
results = detector.analyze_file('traffic.pcap')

# Get summary
print(detector.get_summary(results))
```

## Documentation

See [DOCUMENTATION.md](DOCUMENTATION.md) for detailed usage, configuration, and examples.

## Requirements

- Python 3.7+
- scapy >= 2.5.0
- click >= 8.1.0
- colorama >= 0.4.6
- tabulate >= 0.9.0

## License

MIT License - see LICENSE file for details.

