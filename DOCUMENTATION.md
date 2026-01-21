# PCAP Anomaly Detector Documentation

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Command Line Interface](#command-line-interface)
4. [Detection Methods](#detection-methods)
5. [Python API](#python-api)
6. [Configuration](#configuration)
7. [Examples](#examples)
8. [Troubleshooting](#troubleshooting)

## Overview

The PCAP Anomaly Detector is a comprehensive network traffic analysis tool that identifies suspicious activities in PCAP files. It uses multiple detection techniques to identify potential security threats including malicious domains, data exfiltration, malware communication, and network anomalies.

### Key Components

- **Parser**: Extracts network traffic data from PCAP files using Scapy
- **Detectors**: Multiple specialized detectors for different threat types
- **CLI Interface**: User-friendly command-line interface with colored output
- **Export System**: Save detailed results for further analysis

## Installation

### System Requirements

- Python 3.7 or higher
- 2GB RAM minimum (for large PCAP files)
- 100MB disk space

### Installation Steps

```bash
# 1. Clone the repository
git clone <repository-url>
cd pcap-anomaly-detector

# 2. Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python -c "from pcap_analyzer.cli import cli; cli(['--help'])"
```

### Development Installation

```bash
# Install in development mode
pip install -e .

# Run tests (if available)
python -m pytest tests/
```

## Command Line Interface

### Basic Commands

#### File Information
```bash
python -c "from pcap_analyzer.cli import cli; cli(['info', 'traffic.pcap'])"
```
Displays basic statistics about the PCAP file including packet count, protocols, and IP addresses.

#### Full Analysis
```bash
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap'])"
```
Runs complete analysis with all basic detection features.

#### Advanced Analysis
```bash
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--advanced'])"
```
Enables all detection features including exfiltration, malware, and anomaly detection.

### Command Options

| Option | Description |
|--------|-------------|
| `--verbose, -v` | Enable verbose logging with debug information |
| `--output, -o` | Save results to specified file |
| `--domains-only` | Only analyze suspicious domains |
| `--traffic-only` | Only analyze traffic spikes |
| `--advanced` | Enable all advanced detection features |
| `--exfil-only` | Only analyze data exfiltration patterns |
| `--malware-only` | Only analyze malware indicators |
| `--anomaly-only` | Only analyze network anomalies |

### Usage Examples

#### Basic Analysis with Output
```bash
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--output', 'results.txt'])"
```

#### Verbose Analysis
```bash
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--verbose'])"
```

#### Targeted Analysis
```bash
# Only check for data exfiltration
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--exfil-only'])"

# Only check for malware indicators
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--malware-only'])"

# Only check for network anomalies
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--anomaly-only'])"
```

## Detection Methods

### Suspicious Domain Detection

#### Techniques Used

1. **Pattern Matching**
   - Suspicious TLDs: `.tk`, `.ml`, `.ga`, `.cf`, `.bit`
   - Tor domains: `.onion`
   - Direct IP addresses in domain names
   - IP-like patterns (e.g., `192-168-1-1.com`)

2. **DGA (Domain Generation Algorithm) Detection**
   - Long random-looking domains
   - Hex-based domain patterns
   - Mixed alphanumeric patterns

3. **Entropy Analysis**
   - High entropy domains (> 4.0 bits)
   - Random character distribution

4. **Keyword Matching**
   - Suspicious keywords: `malware`, `virus`, `botnet`, `c2`, `phishing`, etc.

5. **Structural Analysis**
   - Unusually long domains (> 50 characters)
   - Excessive subdomains (> 4 levels)

#### Risk Scoring

- **Score 1-2**: Low risk (single indicator)
- **Score 3**: Medium risk (multiple indicators)
- **Score 4+**: High risk (strong indicators)

### Traffic Spike Detection

#### Statistical Analysis

Uses standard deviation-based thresholding to identify outliers:

- **Threshold**: 2.5 standard deviations above mean
- **Minimum Sample Size**: 10 data points required

#### Spike Types

1. **Volume Spikes**
   - Unusual increases in bytes per second
   - Potential data exfiltration or DDoS

2. **IP Activity Spikes**
   - Abnormal traffic from specific IPs
   - Potential scanning or attacks

3. **Port Usage Spikes**
   - Unusual activity on specific ports
   - Potential services exploitation

### Advanced Detection Features

#### Data Exfiltration Detection

1. **Large Outbound Transfers**
   - Threshold: 1MB+ to external IPs
   - Severity: High (>5MB), Medium (1-5MB)

2. **High-Frequency Connections**
   - Threshold: 100+ connections per minute
   - Potential C2 communication

3. **Unusual Port Usage**
   - Monitors ports: 443, 8443, 9999, 8080, 9000-9002
   - Potential covert channels

4. **DNS Tunneling** (Planned)
   - Large DNS queries
   - Encoded data in DNS

#### Malware Detection

1. **Malware-Related Domains**
   - Known malware infrastructure
   - Paste sites, URL shorteners
   - Raw GitHub content links

2. **Beaconing Detection**
   - Regular DNS query intervals
   - Low variance in timing
   - Minimum 5 queries required

3. **User Agent Analysis** (Planned)
   - Suspicious user agent strings
   - Automated tool signatures

#### Network Anomaly Detection

1. **Protocol Anomalies**
   - Rare protocols: GRE, ESP, AH, OSPF
   - Potential covert channels

2. **Port Scan Detection**
   - Many unique destination ports
   - Potential network reconnaissance

3. **IP Address Anomalies**
   - Many source IPs (potential DDoS)
   - Many destination IPs (potential scanning)

## Python API

### Basic Usage

```python
from pcap_analyzer import PcapAnomalyDetector

# Initialize detector
detector = PcapAnomalyDetector(verbose=True)

# Analyze PCAP file
results = detector.analyze_file('traffic.pcap')

# Get summary
print(detector.get_summary(results))

# Access specific results
domains = results['suspicious_domains']
spikes = results['traffic_spikes']
print(f"Found {len(domains)} suspicious domains")
print(f"Found {len(spikes)} traffic spikes")
```

### Advanced Usage

```python
from pcap_analyzer.parser import PcapParser
from pcap_analyzer.detectors import SuspiciousDomainDetector, TrafficSpikeDetector
from pcap_analyzer.advanced_detectors import ExfilDetector, MalwareDetector, AnomalyDetector

# Parse PCAP
parser = PcapParser()
parser.parse_file('traffic.pcap')

# Get data
dns_queries = parser.get_dns_queries()
traffic_stats = parser.get_traffic_stats()

# Run specific detectors
domain_detector = SuspiciousDomainDetector()
suspicious_domains = domain_detector.detect_suspicious_domains(dns_queries)

exfil_detector = ExfilDetector()
exfil_findings = exfil_detector.detect_exfiltration(traffic_stats)

# Process results
for domain in suspicious_domains:
    print(f"Suspicious domain: {domain['domain']} (risk: {domain['risk_score']})")
```

### Result Structure

```python
results = {
    'file': 'traffic.pcap',
    'packet_count': 15420,
    'dns_query_count': 89,
    'suspicious_domains': [...],
    'traffic_spikes': [...],
    'total_anomalies': 5,
    'traffic_stats': {...}
}
```

#### Domain Finding Structure

```python
{
    'domain': 'malware-site.tk',
    'timestamp': 1642775535.123,
    'datetime': datetime(2022, 1, 21, 14, 32, 15),
    'src_ip': '192.168.1.100',
    'reasons': ['Matches pattern: .*\.tk$', 'Contains keyword: malware'],
    'risk_score': 2
}
```

#### Traffic Spike Structure

```python
{
    'type': 'volume_spike',
    'timestamp': 1642775712,
    'datetime': datetime(2022, 1, 21, 14, 35, 12),
    'bytes': 5242880,
    'mean': 1048576,
    'std_dev': 1677721,
    'severity': 3.2,
    'description': 'Traffic spike: 5242880 bytes (mean: 1048576, +3.2σ)'
}
```

## Configuration

### Environment Variables

```bash
# Set log level
export PCAP_LOG_LEVEL=DEBUG

# Set default output directory
export PCAP_OUTPUT_DIR=/path/to/output

# Enable/disable features
export PCAP_ENABLE_ADVANCED=true
export PCAP_ENABLE_MALWARE=true
```

### Configuration File (Planned)

```yaml
# pcap_config.yaml
detection:
  domains:
    enable_entropy: true
    entropy_threshold: 4.0
    suspicious_tlds: [".tk", ".ml", ".ga", ".cf"]
  
  traffic:
    spike_threshold: 2.5
    min_sample_size: 10
  
  exfiltration:
    large_transfer_threshold: 1000000  # 1MB
    high_frequency_threshold: 100
    
output:
    format: "table"
    colors: true
    max_results: 10
```

## Examples

### Example 1: Basic Malware Analysis

```bash
# Analyze a suspected malware PCAP
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'malware_traffic.pcap', '--advanced', '--verbose'])"

# Output shows:
# - Suspicious domains with C2 infrastructure
# - Beaconing patterns
# - Data exfiltration attempts
```

### Example 2: Data Breach Investigation

```bash
# Focus on exfiltration detection
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'breach_evidence.pcap', '--exfil-only', '--output', 'exfil_report.txt'])"

# Output shows:
# - Large outbound transfers
# - Unusual destination IPs
# - High-frequency connections
```

### Example 3: Network Anomaly Investigation

```bash
# Check for network anomalies
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'anomaly_traffic.pcap', '--anomaly-only'])"

# Output shows:
# - Port scanning activity
# - Protocol anomalies
# - IP address anomalies
```

### Example 4: Automated Analysis

```python
# Python script for batch processing
import os
from pcap_analyzer import PcapAnomalyDetector

def analyze_directory(directory):
    detector = PcapAnomalyDetector()
    
    for filename in os.listdir(directory):
        if filename.endswith('.pcap'):
            filepath = os.path.join(directory, filename)
            try:
                results = detector.analyze_file(filepath)
                if results['total_anomalies'] > 0:
                    print(f"ALERT: {filename} - {results['total_anomalies']} anomalies")
                    # Save detailed report
                    with open(f"{filename}_report.txt", 'w') as f:
                        f.write(detector.get_summary(results))
            except Exception as e:
                print(f"Error processing {filename}: {e}")

# Usage
analyze_directory('/path/to/pcaps')
```

## Troubleshooting

### Common Issues

#### 1. "No module named 'scapy'"
```bash
# Solution: Install dependencies
pip install -r requirements.txt

# Or install scapy directly
pip install scapy
```

#### 2. "Failed to parse PCAP file"
```bash
# Check file permissions
ls -la traffic.pcap

# Verify file format
file traffic.pcap

# Try with verbose mode
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--verbose'])"
```

#### 3. "Memory Error with Large Files"
```python
# Process in chunks (future feature)
from pcap_analyzer.parser import PcapParser

parser = PcapParser()
parser.parse_file_chunked('large_traffic.pcap', chunk_size=10000)
```

#### 4. "No DNS queries found"
- Verify the PCAP contains DNS traffic
- Check if traffic is encrypted (DNS over HTTPS)
- Use `--traffic-only` flag to focus on traffic analysis

#### 5. "False Positives"
```python
# Adjust thresholds (future feature)
from pcap_analyzer.detectors import SuspiciousDomainDetector

detector = SuspiciousDomainDetector()
detector.entropy_threshold = 4.5  # Increase threshold
```

### Performance Tips

1. **Large PCAP Files**
   - Use virtual environment with sufficient memory
   - Consider splitting large files into smaller chunks
   - Use targeted analysis flags to reduce processing

2. **Batch Processing**
   - Process files in parallel using multiprocessing
   - Use SSD storage for faster I/O
   - Monitor memory usage during processing

3. **Optimization**
   - Disable verbose mode for production use
   - Use specific analysis flags when possible
   - Cache results for repeated analysis

### Getting Help

1. **Verbose Mode**: Use `--verbose` flag for detailed logging
2. **File Info**: Use `info` command to verify PCAP contents
3. **Targeted Analysis**: Use specific flags to isolate issues
4. **Community**: Report issues on GitHub repository

### Debug Mode

```bash
# Enable debug logging
export PCAP_LOG_LEVEL=DEBUG
python -c "from pcap_analyzer.cli import cli; cli(['analyze', 'traffic.pcap', '--verbose'])"
```

This will show:
- Packet parsing details
- Detection algorithm steps
- Internal processing information
- Error stack traces
