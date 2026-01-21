"""
Command Line Interface for PCAP Anomaly Detector

Provides a CLI interface for analyzing PCAP files and detecting anomalies.
"""

import click
import logging
from typing import Optional
from tabulate import tabulate
from colorama import init, Fore, Style
from datetime import datetime

from .parser import PcapParser
from .detectors import SuspiciousDomainDetector, TrafficSpikeDetector
from .advanced_detectors import ExfilDetector, MalwareDetector, AnomalyDetector

# Initialize colorama for cross-platform colored output
init()


class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to log messages."""
    
    COLORS = {
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'DEBUG': Fore.BLUE,
        'INFO': Fore.GREEN
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    
    # Apply colored formatter if not in verbose mode
    if not verbose:
        for handler in logging.root.handlers:
            handler.setFormatter(ColoredFormatter())


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """PCAP Anomaly Detector - Analyze network traffic for suspicious activity."""
    pass


@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--domains-only', is_flag=True, help='Only analyze suspicious domains')
@click.option('--traffic-only', is_flag=True, help='Only analyze traffic spikes')
@click.option('--advanced', is_flag=True, help='Enable advanced detection features')
@click.option('--exfil-only', is_flag=True, help='Only analyze data exfiltration')
@click.option('--malware-only', is_flag=True, help='Only analyze malware indicators')
@click.option('--anomaly-only', is_flag=True, help='Only analyze general anomalies')
def analyze(pcap_file: str, output: Optional[str], verbose: bool, domains_only: bool, traffic_only: bool, advanced: bool, exfil_only: bool, malware_only: bool, anomaly_only: bool):
    """Analyze a PCAP file for anomalies."""
    
    setup_logging(verbose)
    
    click.echo(f"{Fore.CYAN}PCAP Anomaly Detector{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    
    # Parse PCAP file
    parser = PcapParser()
    if not parser.parse_file(pcap_file):
        click.echo(f"{Fore.RED}Error: Failed to parse PCAP file{Style.RESET_ALL}")
        return
    
    click.echo(f"{Fore.GREEN}✓ Successfully parsed {parser.get_packet_count()} packets{Style.RESET_ALL}")
    
    results = []
    
    # Analyze suspicious domains
    if not traffic_only and not exfil_only and not malware_only and not anomaly_only:
        click.echo(f"\n{Fore.YELLOW}Analyzing suspicious domains...{Style.RESET_ALL}")
        domain_detector = SuspiciousDomainDetector()
        dns_queries = parser.get_dns_queries()
        
        if dns_queries:
            suspicious_domains = domain_detector.detect_suspicious_domains(dns_queries)
            results.extend(suspicious_domains)
            
            if suspicious_domains:
                click.echo(f"{Fore.RED}Found {len(suspicious_domains)} suspicious domains{Style.RESET_ALL}")
                _display_suspicious_domains(suspicious_domains[:10])  # Show top 10
            else:
                click.echo(f"{Fore.GREEN}No suspicious domains detected{Style.RESET_ALL}")
        else:
            click.echo(f"{Fore.YELLOW}No DNS queries found in PCAP{Style.RESET_ALL}")
    
    # Analyze traffic spikes
    if not domains_only and not exfil_only and not malware_only and not anomaly_only:
        click.echo(f"\n{Fore.YELLOW}Analyzing traffic spikes...{Style.RESET_ALL}")
        spike_detector = TrafficSpikeDetector()
        traffic_stats = parser.get_traffic_stats()
        
        traffic_spikes = spike_detector.detect_traffic_spikes(traffic_stats)
        results.extend(traffic_spikes)
        
        if traffic_spikes:
            click.echo(f"{Fore.RED}Found {len(traffic_spikes)} traffic spikes{Style.RESET_ALL}")
            _display_traffic_spikes(traffic_spikes[:10])  # Show top 10
        else:
            click.echo(f"{Fore.GREEN}No traffic spikes detected{Style.RESET_ALL}")
    
    # Advanced detection features
    if advanced or exfil_only or malware_only or anomaly_only:
        click.echo(f"\n{Fore.YELLOW}Running advanced detection...{Style.RESET_ALL}")
        traffic_stats = parser.get_traffic_stats()
        dns_queries = parser.get_dns_queries()
        
        # Data exfiltration detection
        if advanced or exfil_only:
            click.echo(f"{Fore.YELLOW}Checking for data exfiltration...{Style.RESET_ALL}")
            exfil_detector = ExfilDetector()
            exfil_findings = exfil_detector.detect_exfiltration(traffic_stats)
            results.extend(exfil_findings)
            
            if exfil_findings:
                click.echo(f"{Fore.RED}Found {len(exfil_findings)} exfiltration indicators{Style.RESET_ALL}")
                _display_advanced_findings(exfil_findings[:5], "Exfiltration")
            else:
                click.echo(f"{Fore.GREEN}No exfiltration detected{Style.RESET_ALL}")
        
        # Malware detection
        if advanced or malware_only:
            click.echo(f"{Fore.YELLOW}Checking for malware indicators...{Style.RESET_ALL}")
            malware_detector = MalwareDetector()
            malware_findings = malware_detector.detect_malware_indicators(dns_queries)
            results.extend(malware_findings)
            
            if malware_findings:
                click.echo(f"{Fore.RED}Found {len(malware_findings)} malware indicators{Style.RESET_ALL}")
                _display_advanced_findings(malware_findings[:5], "Malware")
            else:
                click.echo(f"{Fore.GREEN}No malware indicators detected{Style.RESET_ALL}")
        
        # General anomaly detection
        if advanced or anomaly_only:
            click.echo(f"{Fore.YELLOW}Checking for network anomalies...{Style.RESET_ALL}")
            anomaly_detector = AnomalyDetector()
            anomaly_findings = anomaly_detector.detect_anomalies(traffic_stats)
            results.extend(anomaly_findings)
            
            if anomaly_findings:
                click.echo(f"{Fore.RED}Found {len(anomaly_findings)} network anomalies{Style.RESET_ALL}")
                _display_advanced_findings(anomaly_findings[:5], "Anomalies")
            else:
                click.echo(f"{Fore.GREEN}No network anomalies detected{Style.RESET_ALL}")
    
    # Display summary
    _display_summary(parser, results)
    
    # Save results to file if requested
    if output:
        _save_results(results, output)
        click.echo(f"\n{Fore.GREEN}Results saved to {output}{Style.RESET_ALL}")


def _display_suspicious_domains(domains):
    """Display suspicious domains in a formatted table."""
    if not domains:
        return
    
    headers = ['Domain', 'Risk Score', 'Timestamp', 'Reasons']
    rows = []
    
    for domain in domains:
        reasons_str = '; '.join(domain['reasons'][:2])  # Show first 2 reasons
        if len(domain['reasons']) > 2:
            reasons_str += '...'
        
        rows.append([
            domain['domain'][:30],  # Truncate long domains
            domain['risk_score'],
            domain['datetime'].strftime('%H:%M:%S'),
            reasons_str
        ])
    
    click.echo(f"\n{Fore.CYAN}Top Suspicious Domains:{Style.RESET_ALL}")
    click.echo(tabulate(rows, headers=headers, tablefmt='grid'))


def _display_advanced_findings(findings, category):
    """Display advanced detection findings in a formatted table."""
    if not findings:
        return
    
    headers = ['Type', 'Target', 'Severity', 'Description']
    rows = []
    
    for finding in findings:
        target = finding.get('ip', finding.get('port', finding.get('domain', 'N/A')))
        severity = finding.get('severity', 'unknown').title()
        description = finding.get('description', 'No description')
        
        # Truncate long descriptions
        if len(description) > 60:
            description = description[:57] + '...'
        
        rows.append([
            finding.get('type', 'unknown').replace('_', ' ').title(),
            str(target)[:30],
            severity,
            description
        ])
    
    click.echo(f"\n{Fore.CYAN}Top {category} Findings:{Style.RESET_ALL}")
    click.echo(tabulate(rows, headers=headers, tablefmt='grid'))


def _display_traffic_spikes(spikes):
    """Display traffic spikes in a formatted table."""
    if not spikes:
        return
    
    headers = ['Type', 'Target', 'Severity', 'Timestamp', 'Description']
    rows = []
    
    for spike in spikes:
        target = spike.get('ip', spike.get('port', 'N/A'))
        severity = f"{spike['severity']:.1f}σ"
        
        rows.append([
            spike['type'].replace('_', ' ').title(),
            target,
            severity,
            spike['datetime'].strftime('%H:%M:%S'),
            spike['description'][:50] + '...' if len(spike['description']) > 50 else spike['description']
        ])
    
    click.echo(f"\n{Fore.CYAN}Top Traffic Spikes:{Style.RESET_ALL}")
    click.echo(tabulate(rows, headers=headers, tablefmt='grid'))


def _display_summary(parser, results):
    """Display analysis summary."""
    click.echo(f"\n{Fore.CYAN}Analysis Summary:{Style.RESET_ALL}")
    click.echo(f"{'='*50}")
    
    # Basic stats
    click.echo(f"Total packets analyzed: {Fore.GREEN}{parser.get_packet_count()}{Style.RESET_ALL}")
    click.echo(f"DNS queries found: {Fore.GREEN}{len(parser.get_dns_queries())}{Style.RESET_ALL}")
    
    # Anomaly counts
    domain_count = len([r for r in results if 'domain' in r])
    spike_count = len([r for r in results if 'type' in r])
    
    click.echo(f"Suspicious domains: {Fore.RED}{domain_count}{Style.RESET_ALL}")
    click.echo(f"Traffic spikes: {Fore.RED}{spike_count}{Style.RESET_ALL}")
    click.echo(f"Total anomalies: {Fore.RED}{len(results)}{Style.RESET_ALL}")
    
    # Risk assessment
    if len(results) == 0:
        click.echo(f"\n{Fore.GREEN}✓ No anomalies detected - traffic appears normal{Style.RESET_ALL}")
    elif len(results) <= 5:
        click.echo(f"\n{Fore.YELLOW}⚠ Low risk - few anomalies detected{Style.RESET_ALL}")
    elif len(results) <= 15:
        click.echo(f"\n{Fore.RED}⚠ Medium risk - multiple anomalies detected{Style.RESET_ALL}")
    else:
        click.echo(f"\n{Fore.RED}🚨 High risk - many anomalies detected{Style.RESET_ALL}")


def _save_results(results, output_file):
    """Save analysis results to a file."""
    with open(output_file, 'w') as f:
        f.write("PCAP Anomaly Detector Results\n")
        f.write("=" * 50 + "\n")
        f.write(f"Analysis completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total anomalies found: {len(results)}\n\n")
        
        # Group results by type
        domains = [r for r in results if 'domain' in r]
        spikes = [r for r in results if 'type' in r and 'spike' in r['type']]
        exfil = [r for r in results if 'type' in r and 'exfil' in r['type']]
        malware = [r for r in results if 'type' in r and 'malware' in r['type']]
        anomalies = [r for r in results if 'type' in r and ('protocol' in r['type'] or 'scan' in r['type'] or 'ip' in r['type'])]
        
        if domains:
            f.write("SUSPICIOUS DOMAINS\n")
            f.write("-" * 20 + "\n")
            for domain in domains:
                f.write(f"Domain: {domain['domain']}\n")
                f.write(f"Risk Score: {domain.get('risk_score', 'N/A')}\n")
                f.write(f"Timestamp: {domain.get('datetime', 'N/A')}\n")
                f.write(f"Reasons: {'; '.join(domain.get('reasons', []))}\n")
                f.write(f"Source IP: {domain.get('src_ip', 'N/A')}\n\n")
        
        if spikes:
            f.write("TRAFFIC SPIKES\n")
            f.write("-" * 20 + "\n")
            for spike in spikes:
                f.write(f"Type: {spike['type']}\n")
                f.write(f"Description: {spike['description']}\n")
                f.write(f"Timestamp: {spike.get('datetime', 'N/A')}\n")
                f.write(f"Severity: {spike.get('severity', 'N/A')}\n\n")
        
        if exfil:
            f.write("DATA EXFILTRATION\n")
            f.write("-" * 20 + "\n")
            for finding in exfil:
                f.write(f"Type: {finding['type']}\n")
                f.write(f"Description: {finding['description']}\n")
                f.write(f"Severity: {finding['severity']}\n\n")
        
        if malware:
            f.write("MALWARE INDICATORS\n")
            f.write("-" * 20 + "\n")
            for finding in malware:
                f.write(f"Type: {finding['type']}\n")
                f.write(f"Description: {finding['description']}\n")
                f.write(f"Severity: {finding['severity']}\n\n")
        
        if anomalies:
            f.write("NETWORK ANOMALIES\n")
            f.write("-" * 20 + "\n")
            for finding in anomalies:
                f.write(f"Type: {finding['type']}\n")
                f.write(f"Description: {finding['description']}\n")
                f.write(f"Severity: {finding['severity']}\n\n")


@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
def info(pcap_file: str):
    """Display basic information about a PCAP file."""
    
    setup_logging()
    
    parser = PcapParser()
    if not parser.parse_file(pcap_file):
        click.echo(f"{Fore.RED}Error: Failed to parse PCAP file{Style.RESET_ALL}")
        return
    
    click.echo(f"{Fore.CYAN}PCAP File Information{Style.RESET_ALL}")
    click.echo(f"{'='*50}")
    click.echo(f"File: {pcap_file}")
    click.echo(f"Total packets: {parser.get_packet_count()}")
    click.echo(f"DNS queries: {len(parser.get_dns_queries())}")
    
    # Display traffic stats summary
    stats = parser.get_traffic_stats()
    click.echo(f"\n{Fore.YELLOW}Traffic Statistics:{Style.RESET_ALL}")
    click.echo(f"Unique source IPs: {len(stats.get('src_ips', {}))}")
    click.echo(f"Unique destination IPs: {len(stats.get('dst_ips', {}))}")
    click.echo(f"Unique ports: {len(stats.get('ports', {}))}")
    
    if stats.get('protocols'):
        click.echo(f"\nProtocols:")
        for protocol, count in stats['protocols'].items():
            click.echo(f"  {protocol}: {count} packets")


if __name__ == '__main__':
    cli()
