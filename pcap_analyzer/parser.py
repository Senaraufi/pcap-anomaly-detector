"""
PCAP Parser Module

Handles parsing of PCAP files using scapy and extracting network traffic data.
"""

from scapy.all import rdpcap, IP, TCP, UDP, DNS, IPv6
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging


class PcapParser:
    """Parse PCAP files and extract network traffic information."""
    
    def __init__(self):
        self.packets = []
        self.dns_queries = []
        self.traffic_stats = {}
        
    def parse_file(self, pcap_file: str) -> bool:
        """
        Parse a PCAP file and extract relevant information.
        
        Args:
            pcap_file: Path to the PCAP file
            
        Returns:
            True if parsing was successful, False otherwise
        """
        try:
            logging.info(f"Parsing PCAP file: {pcap_file}")
            self.packets = rdpcap(pcap_file)
            logging.info(f"Loaded {len(self.packets)} packets")
            
            self._extract_dns_queries()
            self._calculate_traffic_stats()
            
            return True
            
        except Exception as e:
            logging.error(f"Error parsing PCAP file: {e}")
            return False
    
    def _extract_dns_queries(self):
        """Extract DNS queries from packets."""
        self.dns_queries = []
        
        for packet in self.packets:
            if DNS in packet:
                dns_layer = packet[DNS]
                if dns_layer.qr == 0:  # DNS query
                    if dns_layer.qd:
                        query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                        timestamp = float(packet.time)
                        
                        query_info = {
                            'domain': query_name,
                            'timestamp': timestamp,
                            'datetime': datetime.fromtimestamp(timestamp),
                            'src_ip': self._get_src_ip(packet),
                            'dst_ip': self._get_dst_ip(packet)
                        }
                        self.dns_queries.append(query_info)
    
    def _calculate_traffic_stats(self):
        """Calculate traffic statistics for spike detection."""
        self.traffic_stats = {
            'timestamps': [],
            'src_ips': {},
            'dst_ips': {},
            'protocols': {},
            'ports': {},
            'bytes_per_second': {}
        }
        
        # Group packets by second
        time_buckets = {}
        
        for packet in self.packets:
            if IP in packet or IPv6 in packet:
                timestamp = int(packet.time)
                packet_size = len(packet)
                
                # Track bytes per second
                if timestamp not in time_buckets:
                    time_buckets[timestamp] = 0
                time_buckets[timestamp] += packet_size
                
                # Track source IPs
                src_ip = self._get_src_ip(packet)
                if src_ip:
                    if src_ip not in self.traffic_stats['src_ips']:
                        self.traffic_stats['src_ips'][src_ip] = 0
                    self.traffic_stats['src_ips'][src_ip] += packet_size
                
                # Track destination IPs
                dst_ip = self._get_dst_ip(packet)
                if dst_ip:
                    if dst_ip not in self.traffic_stats['dst_ips']:
                        self.traffic_stats['dst_ips'][dst_ip] = 0
                    self.traffic_stats['dst_ips'][dst_ip] += packet_size
                
                # Track protocols
                protocol = self._get_protocol(packet)
                if protocol:
                    if protocol not in self.traffic_stats['protocols']:
                        self.traffic_stats['protocols'][protocol] = 0
                    self.traffic_stats['protocols'][protocol] += 1
                
                # Track ports
                src_port, dst_port = self._get_ports(packet)
                if src_port:
                    if src_port not in self.traffic_stats['ports']:
                        self.traffic_stats['ports'][src_port] = 0
                    self.traffic_stats['ports'][src_port] += 1
                if dst_port:
                    if dst_port not in self.traffic_stats['ports']:
                        self.traffic_stats['ports'][dst_port] = 0
                    self.traffic_stats['ports'][dst_port] += 1
        
        self.traffic_stats['bytes_per_second'] = time_buckets
        self.traffic_stats['timestamps'] = sorted(time_buckets.keys())
    
    def _get_src_ip(self, packet) -> Optional[str]:
        """Extract source IP from packet."""
        if IP in packet:
            return packet[IP].src
        elif IPv6 in packet:
            return packet[IPv6].src
        return None
    
    def _get_dst_ip(self, packet) -> Optional[str]:
        """Extract destination IP from packet."""
        if IP in packet:
            return packet[IP].dst
        elif IPv6 in packet:
            return packet[IPv6].dst
        return None
    
    def _get_protocol(self, packet) -> Optional[str]:
        """Extract protocol from packet."""
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif ICMP in packet:
            return "ICMP"
        return None
    
    def _get_ports(self, packet) -> tuple:
        """Extract source and destination ports from packet."""
        src_port = None
        dst_port = None
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        return src_port, dst_port
    
    def get_packet_count(self) -> int:
        """Get total number of packets."""
        return len(self.packets)
    
    def get_dns_queries(self) -> List[Dict[str, Any]]:
        """Get all DNS queries found in the PCAP."""
        return self.dns_queries
    
    def get_traffic_stats(self) -> Dict[str, Any]:
        """Get traffic statistics."""
        return self.traffic_stats
