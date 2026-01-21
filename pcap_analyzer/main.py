"""
Main entry point for the PCAP Anomaly Detector

This module provides the main interface for the PCAP anomaly detection system.
"""

from .parser import PcapParser
from .detectors import SuspiciousDomainDetector, TrafficSpikeDetector
from .cli import cli
import logging


class PcapAnomalyDetector:
    """Main class for PCAP anomaly detection."""
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the anomaly detector.
        
        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        self.parser = PcapParser()
        self.domain_detector = SuspiciousDomainDetector()
        self.traffic_detector = TrafficSpikeDetector()
        
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
    
    def analyze_file(self, pcap_file: str) -> dict:
        """
        Analyze a PCAP file for anomalies.
        
        Args:
            pcap_file: Path to the PCAP file
            
        Returns:
            Dictionary containing analysis results
        """
        logging.info(f"Starting analysis of {pcap_file}")
        
        # Parse the PCAP file
        if not self.parser.parse_file(pcap_file):
            raise ValueError(f"Failed to parse PCAP file: {pcap_file}")
        
        # Detect suspicious domains
        dns_queries = self.parser.get_dns_queries()
        suspicious_domains = self.domain_detector.detect_suspicious_domains(dns_queries)
        
        # Detect traffic spikes
        traffic_stats = self.parser.get_traffic_stats()
        traffic_spikes = self.traffic_detector.detect_traffic_spikes(traffic_stats)
        
        # Compile results
        results = {
            'file': pcap_file,
            'packet_count': self.parser.get_packet_count(),
            'dns_query_count': len(dns_queries),
            'suspicious_domains': suspicious_domains,
            'traffic_spikes': traffic_spikes,
            'total_anomalies': len(suspicious_domains) + len(traffic_spikes),
            'traffic_stats': traffic_stats
        }
        
        logging.info(f"Analysis complete. Found {results['total_anomalies']} anomalies")
        
        return results
    
    def get_summary(self, results: dict) -> str:
        """
        Generate a summary of analysis results.
        
        Args:
            results: Analysis results dictionary
            
        Returns:
            Formatted summary string
        """
        summary = []
        summary.append(f"PCAP Analysis Summary for: {results['file']}")
        summary.append("=" * 50)
        summary.append(f"Total packets analyzed: {results['packet_count']}")
        summary.append(f"DNS queries found: {results['dns_query_count']}")
        summary.append(f"Suspicious domains: {len(results['suspicious_domains'])}")
        summary.append(f"Traffic spikes: {len(results['traffic_spikes'])}")
        summary.append(f"Total anomalies: {results['total_anomalies']}")
        
        if results['total_anomalies'] == 0:
            summary.append("\n✓ No anomalies detected - traffic appears normal")
        elif results['total_anomalies'] <= 5:
            summary.append("\n⚠ Low risk - few anomalies detected")
        elif results['total_anomalies'] <= 15:
            summary.append("\n⚠ Medium risk - multiple anomalies detected")
        else:
            summary.append("\n🚨 High risk - many anomalies detected")
        
        return "\n".join(summary)


# CLI entry point
def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()
