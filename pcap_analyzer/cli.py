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
def analyze(pcap_file: str, output: Optional[str], verbose: bool, domains_only: bool, traffic_only: bool):
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
    if not traffic_only:
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
    if not domains_only:
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
        spikes = [r for r in results if 'type' in r]
        
        if domains:
            f.write("SUSPICIOUS DOMAINS\n")
            f.write("-" * 20 + "\n")
            for domain in domains:
                f.write(f"Domain: {domain['domain']}\n")
                f.write(f"Risk Score: {domain['risk_score']}\n")
                f.write(f"Timestamp: {domain['datetime']}\n")
                f.write(f"Reasons: {'; '.join(domain['reasons'])}\n")
                f.write(f"Source IP: {domain['src_ip']}\n\n")
        
        if spikes:
            f.write("TRAFFIC SPIKES\n")
            f.write("-" * 20 + "\n")
            for spike in spikes:
                f.write(f"Type: {spike['type']}\n")
                f.write(f"Description: {spike['description']}\n")
                f.write(f"Timestamp: {spike['datetime']}\n")
                f.write(f"Severity: {spike['severity']:.2f}σ\n\n")


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
