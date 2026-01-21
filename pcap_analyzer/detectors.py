"""
Anomaly Detection Module

Contains detectors for suspicious domains and traffic spikes.
"""

import re
from typing import List, Dict, Any, Tuple
import logging
from datetime import datetime, timedelta
import statistics


class SuspiciousDomainDetector:
    """Detect suspicious domains from DNS queries."""
    
    def __init__(self):
        # Common suspicious patterns
        self.suspicious_patterns = [
            r'.*\.tk$',      # Free TLD often used maliciously
            r'.*\.ml$',      # Free TLD often used maliciously
            r'.*\.ga$',      # Free TLD often used maliciously
            r'.*\.cf$',      # Free TLD often used maliciously
            r'.*\.bit$',     # Alternative TLD
            r'[a-f0-9]{32,}',# Long hex strings (potential malware domains)
            r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}',  # IP-like domains
            r'.*\.onion$',   # Tor hidden services
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # Direct IP domains
        ]
        
        # Suspicious keywords
        self.suspicious_keywords = [
            'malware', 'virus', 'trojan', 'botnet', 'c2', 'command',
            'control', 'phishing', 'spam', 'exploit', 'payload',
            'backdoor', 'rootkit', 'keylog', 'rat', 'ddos'
        ]
        
        # DGA (Domain Generation Algorithm) patterns
        self.dga_patterns = [
            r'^[a-z]{16,}\.[a-z]{2,3}$',  # Long random-looking domains
            r'^[a-f0-9]{8,}\.[a-z]{2,3}$',  # Hex-based domains
            r'^[a-z]{1,2}\d{6,}\.[a-z]{2,3}$',  # Mixed alphanumeric
        ]
    
    def detect_suspicious_domains(self, dns_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect suspicious domains from DNS queries.
        
        Args:
            dns_queries: List of DNS query dictionaries
            
        Returns:
            List of suspicious domain findings
        """
        suspicious_domains = []
        
        for query in dns_queries:
            domain = query['domain'].lower()
            reasons = []
            
            # Check against suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.match(pattern, domain, re.IGNORECASE):
                    reasons.append(f"Matches pattern: {pattern}")
            
            # Check for suspicious keywords
            for keyword in self.suspicious_keywords:
                if keyword in domain:
                    reasons.append(f"Contains keyword: {keyword}")
            
            # Check DGA patterns
            for pattern in self.dga_patterns:
                if re.match(pattern, domain, re.IGNORECASE):
                    reasons.append(f"DGA pattern: {pattern}")
            
            # Check for high entropy (random-looking domains)
            if self._calculate_entropy(domain) > 4.0:
                reasons.append("High entropy (random-looking)")
            
            # Check for unusually long domains
            if len(domain) > 50:
                reasons.append("Unusually long domain")
            
            # Check for many subdomains
            if domain.count('.') > 4:
                reasons.append("Many subdomains")
            
            if reasons:
                finding = {
                    'domain': domain,
                    'timestamp': query['timestamp'],
                    'datetime': query['datetime'],
                    'src_ip': query['src_ip'],
                    'reasons': reasons,
                    'risk_score': len(reasons)
                }
                suspicious_domains.append(finding)
        
        # Sort by risk score (highest first)
        suspicious_domains.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return suspicious_domains
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy using log2
        import math
        entropy = 0
        string_len = len(string)
        
        for count in char_counts.values():
            probability = count / string_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy


class TrafficSpikeDetector:
    """Detect unusual traffic spikes in network data."""
    
    def __init__(self):
        self.spike_threshold_multiplier = 2.5  # Standard deviations above mean
        self.min_sample_size = 10  # Minimum data points for analysis
    
    def detect_traffic_spikes(self, traffic_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect traffic spikes from network statistics.
        
        Args:
            traffic_stats: Dictionary containing traffic statistics
            
        Returns:
            List of traffic spike findings
        """
        spikes = []
        
        # Detect spikes in bytes per second
        bytes_spikes = self._detect_volume_spikes(traffic_stats.get('bytes_per_second', {}))
        spikes.extend(bytes_spikes)
        
        # Detect spikes in source IP activity
        ip_spikes = self._detect_ip_spikes(traffic_stats.get('src_ips', {}), 'source')
        spikes.extend(ip_spikes)
        
        # Detect spikes in destination IP activity
        dst_ip_spikes = self._detect_ip_spikes(traffic_stats.get('dst_ips', {}), 'destination')
        spikes.extend(dst_ip_spikes)
        
        # Detect spikes in port usage
        port_spikes = self._detect_port_spikes(traffic_stats.get('ports', {}))
        spikes.extend(port_spikes)
        
        # Sort by severity (highest first)
        spikes.sort(key=lambda x: x.get('severity', 0), reverse=True)
        
        return spikes
    
    def _detect_volume_spikes(self, bytes_per_second: Dict[int, int]) -> List[Dict[str, Any]]:
        """Detect spikes in traffic volume over time."""
        if len(bytes_per_second) < self.min_sample_size:
            return []
        
        values = list(bytes_per_second.values())
        timestamps = list(bytes_per_second.keys())
        
        mean = statistics.mean(values)
        stdev = statistics.stdev(values) if len(values) > 1 else 0
        
        spikes = []
        
        for timestamp, bytes_count in bytes_per_second.items():
            if stdev > 0 and (bytes_count - mean) > (self.spike_threshold_multiplier * stdev):
                severity = (bytes_count - mean) / stdev if stdev > 0 else 0
                
                spike = {
                    'type': 'volume_spike',
                    'timestamp': timestamp,
                    'datetime': datetime.fromtimestamp(timestamp),
                    'bytes': bytes_count,
                    'mean': mean,
                    'std_dev': stdev,
                    'severity': severity,
                    'description': f"Traffic spike: {bytes_count} bytes (mean: {mean:.0f}, +{severity:.1f}σ)"
                }
                spikes.append(spike)
        
        return spikes
    
    def _detect_ip_spikes(self, ip_stats: Dict[str, int], ip_type: str) -> List[Dict[str, Any]]:
        """Detect spikes in IP address activity."""
        if len(ip_stats) < self.min_sample_size:
            return []
        
        values = list(ip_stats.values())
        mean = statistics.mean(values)
        stdev = statistics.stdev(values) if len(values) > 1 else 0
        
        spikes = []
        
        for ip, byte_count in ip_stats.items():
            if stdev > 0 and (byte_count - mean) > (self.spike_threshold_multiplier * stdev):
                severity = (byte_count - mean) / stdev if stdev > 0 else 0
                
                spike = {
                    'type': f'{ip_type}_ip_spike',
                    'ip': ip,
                    'bytes': byte_count,
                    'mean': mean,
                    'std_dev': stdev,
                    'severity': severity,
                    'description': f"{ip_type.title()} IP spike: {ip} ({byte_count} bytes, mean: {mean:.0f}, +{severity:.1f}σ)"
                }
                spikes.append(spike)
        
        return spikes
    
    def _detect_port_spikes(self, port_stats: Dict[int, int]) -> List[Dict[str, Any]]:
        """Detect spikes in port usage."""
        if len(port_stats) < self.min_sample_size:
            return []
        
        values = list(port_stats.values())
        mean = statistics.mean(values)
        stdev = statistics.stdev(values) if len(values) > 1 else 0
        
        spikes = []
        
        for port, packet_count in port_stats.items():
            if stdev > 0 and (packet_count - mean) > (self.spike_threshold_multiplier * stdev):
                severity = (packet_count - mean) / stdev if stdev > 0 else 0
                
                spike = {
                    'type': 'port_spike',
                    'port': port,
                    'packets': packet_count,
                    'mean': mean,
                    'std_dev': stdev,
                    'severity': severity,
                    'description': f"Port spike: {port} ({packet_count} packets, mean: {mean:.0f}, +{severity:.1f}σ)"
                }
                spikes.append(spike)
        
        return spikes
