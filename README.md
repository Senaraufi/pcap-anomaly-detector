# PCAP Anomaly Detector

A Python-based network traffic analyzer that parses PCAP files and detects suspicious domains and unusual traffic spikes.

## Quick Start

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

