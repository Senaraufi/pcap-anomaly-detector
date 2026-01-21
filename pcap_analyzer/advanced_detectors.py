"""
Advanced Detection Module

Additional detection capabilities for the PCAP analyzer.
"""

import re
import base64
import hashlib
from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict, Counter
import logging
from datetime import datetime, timedelta


class ExfilDetector:
    """Detect potential data exfiltration patterns."""
    
    def __init__(self):
        self.large_data_threshold = 1000000  # 1MB
        self.high_frequency_threshold = 100  # connections per minute
        self.uncommon_ports = [443, 8443, 9999, 8080, 9000, 9001, 9002]
        
    def detect_exfiltration(self, traffic_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect potential data exfiltration patterns."""
        findings = []
        
        # Large outbound transfers
        large_transfers = self._detect_large_transfers(traffic_stats)
        findings.extend(large_transfers)
        
        # High-frequency connections
        high_freq = self._detect_high_frequency_connections(traffic_stats)
        findings.extend(high_freq)
        
        # Unusual port usage
        unusual_ports = self._detect_unusual_ports(traffic_stats)
        findings.extend(unusual_ports)
        
        # DNS tunneling detection
        dns_tunneling = self._detect_dns_tunneling(traffic_stats)
        findings.extend(dns_tunneling)
        
        return findings
    
    def _detect_large_transfers(self, traffic_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect large outbound data transfers."""
        findings = []
        
        for dst_ip, byte_count in traffic_stats.get('dst_ips', {}).items():
            if byte_count > self.large_data_threshold:
                # Check if it's an external IP (not private)
                if not self._is_private_ip(dst_ip):
                    finding = {
                        'type': 'large_exfil',
                        'ip': dst_ip,
                        'bytes': byte_count,
                        'severity': 'high' if byte_count > 5000000 else 'medium',
                        'description': f"Large outbound transfer to {dst_ip}: {byte_count:,} bytes"
                    }
                    findings.append(finding)
        
        return findings
    
    def _detect_high_frequency_connections(self, traffic_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect high-frequency connections to external hosts."""
        findings = []
        
        # Group connections by destination and time (simplified)
        dst_counts = Counter()
        for dst_ip in traffic_stats.get('dst_ips', {}):
            dst_counts[dst_ip] += 1
        
        for dst_ip, count in dst_counts.items():
            if count > self.high_frequency_threshold and not self._is_private_ip(dst_ip):
                finding = {
                    'type': 'high_frequency',
                    'ip': dst_ip,
                    'connections': count,
                    'severity': 'medium',
                    'description': f"High-frequency connections to {dst_ip}: {count} connections"
                }
                findings.append(finding)
        
        return findings
    
    def _detect_unusual_ports(self, traffic_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect connections to unusual ports."""
        findings = []
        
        for port, packet_count in traffic_stats.get('ports', {}).items():
            if port in self.uncommon_ports and packet_count > 10:
                finding = {
                    'type': 'unusual_port',
                    'port': port,
                    'packets': packet_count,
                    'severity': 'medium',
                    'description': f"Unusual port activity on port {port}: {packet_count} packets"
                }
                findings.append(finding)
        
        return findings
    
    def _detect_dns_tunneling(self, traffic_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect potential DNS tunneling."""
        findings = []
        
        # This would require more detailed DNS analysis
        # For now, placeholder for future enhancement
        return findings
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range."""
        try:
            parts = list(map(int, ip.split('.')))
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
            return False
        except:
            return True


class MalwareDetector:
    """Detect potential malware communication patterns."""
    
    def __init__(self):
        self.malware_signatures = {
            'user_agents': [
                r'.*bot.*',
                r'.*crawler.*',
                r'.*scanner.*',
                r'.*wget.*',
                r'.*curl.*'
            ],
            'payloads': [
                b'eval(',
                b'system(',
                b'shell_exec(',
                b'passthru(',
                b'base64_decode('
            ],
            'domains': [
                r'.*\.onion$',
                r'.*pastebin\.com',
                r'.*githubusercontent\.com.*raw',
                r'.*bit\.ly',
                r'.*tinyurl\.com'
            ]
        }
    
    def detect_malware_indicators(self, dns_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect potential malware indicators."""
        findings = []
        
        # Suspicious domains
        suspicious_domains = self._check_suspicious_domains(dns_queries)
        findings.extend(suspicious_domains)
        
        # Beaconing patterns
        beaconing = self._detect_beaconing(dns_queries)
        findings.extend(beaconing)
        
        return findings
    
    def _check_suspicious_domains(self, dns_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for malware-related domains."""
        findings = []
        
        for query in dns_queries:
            domain = query['domain'].lower()
            
            for pattern in self.malware_signatures['domains']:
                if re.match(pattern, domain, re.IGNORECASE):
                    finding = {
                        'type': 'malware_domain',
                        'domain': domain,
                        'pattern': pattern,
                        'timestamp': query['timestamp'],
                        'severity': 'high',
                        'description': f"Malware-related domain detected: {domain}"
                    }
                    findings.append(finding)
                    break
        
        return findings
    
    def _detect_beaconing(self, dns_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect beaconing patterns (regular DNS queries)."""
        findings = []
        
        # Group queries by domain
        domain_queries = defaultdict(list)
        for query in dns_queries:
            domain_queries[query['domain']].append(query['timestamp'])
        
        # Check for regular intervals
        for domain, timestamps in domain_queries.items():
            if len(timestamps) >= 5:  # Need at least 5 queries
                timestamps.sort()
                intervals = []
                
                for i in range(1, len(timestamps)):
                    interval = timestamps[i] - timestamps[i-1]
                    intervals.append(interval)
                
                # Check if intervals are consistent (beaconing)
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                    
                    # Low variance indicates regular beaconing
                    if variance < (avg_interval * 0.1):  # Less than 10% variance
                        finding = {
                            'type': 'beaconing',
                            'domain': domain,
                            'interval': avg_interval,
                            'queries': len(timestamps),
                            'severity': 'high',
                            'description': f"Potential beaconing detected for {domain}: {len(timestamps)} queries at {avg_interval:.1f}s intervals"
                        }
                        findings.append(finding)
        
        return findings


class AnomalyDetector:
    """General anomaly detection for network traffic."""
    
    def __init__(self):
        self.protocol_anomalies = {
            'expected_protocols': {'TCP', 'UDP', 'ICMP'},
            'rare_protocols': {'GRE', 'ESP', 'AH', 'OSPF'}
        }
    
    def detect_anomalies(self, traffic_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect general network anomalies."""
        findings = []
        
        # Protocol anomalies
        protocol_anomalies = self._detect_protocol_anomalies(traffic_stats)
        findings.extend(protocol_anomalies)
        
        # Port scan detection
        port_scans = self._detect_port_scans(traffic_stats)
        findings.extend(port_scans)
        
        # IP address anomalies
        ip_anomalies = self._detect_ip_anomalies(traffic_stats)
        findings.extend(ip_anomalies)
        
        return findings
    
    def _detect_protocol_anomalies(self, traffic_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect unusual protocol usage."""
        findings = []
        
        protocols = traffic_stats.get('protocols', {})
        
        for protocol, count in protocols.items():
            if protocol in self.protocol_anomalies['rare_protocols']:
                finding = {
                    'type': 'rare_protocol',
                    'protocol': protocol,
                    'packets': count,
                    'severity': 'medium',
                    'description': f"Rare protocol detected: {protocol} ({count} packets)"
                }
                findings.append(finding)
        
        return findings
    
    def _detect_port_scans(self, traffic_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect potential port scanning activity."""
        findings = []
        
        ports = traffic_stats.get('ports', {})
        
        # Look for many different destination ports from single source
        # This is simplified - would need more detailed analysis
        if len(ports) > 50:
            finding = {
                'type': 'port_scan',
                'unique_ports': len(ports),
                'total_packets': sum(ports.values()),
                'severity': 'high' if len(ports) > 100 else 'medium',
                'description': f"Potential port scan detected: {len(ports)} unique ports"
            }
            findings.append(finding)
        
        return findings
    
    def _detect_ip_anomalies(self, traffic_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect IP address anomalies."""
        findings = []
        
        src_ips = traffic_stats.get('src_ips', {})
        dst_ips = traffic_stats.get('dst_ips', {})
        
        # Check for many unique source IPs (potential DDoS)
        if len(src_ips) > 100:
            finding = {
                'type': 'many_src_ips',
                'unique_ips': len(src_ips),
                'severity': 'high',
                'description': f"Unusual number of source IPs: {len(src_ips)} (potential DDoS)"
            }
            findings.append(finding)
        
        # Check for single IP with many destinations (potential scanning)
        if len(dst_ips) > 50:
            finding = {
                'type': 'many_dst_ips',
                'unique_ips': len(dst_ips),
                'severity': 'medium',
                'description': f"Many destination IPs contacted: {len(dst_ips)} (potential scanning)"
            }
            findings.append(finding)
        
        return findings
