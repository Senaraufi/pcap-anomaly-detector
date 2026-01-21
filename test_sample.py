#!/usr/bin/env python3
"""
Test script to create a sample PCAP file for testing the analyzer.
"""

from scapy.all import *
import time
from datetime import datetime

def create_test_pcap():
    """Create a test PCAP file with various traffic patterns."""
    
    packets = []
    
    # Create some normal HTTP traffic
    for i in range(10):
        packet = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
        packets.append(packet)
    
    # Create some suspicious DNS queries
    suspicious_domains = [
        "malware-site.tk",
        "random-abc123.ml", 
        "phishing-bad.ga",
        "botnet-c2.cf",
        "suspicious-domain.bit"
    ]
    
    for domain in suspicious_domains:
        packet = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        packets.append(packet)
    
    # Create some traffic spikes (large packets)
    base_time = time.time()
    for i in range(50):
        # Normal traffic
        packet = Ether()/IP(src="192.168.1.100", dst="10.0.0.1")/TCP(sport=12345, dport=80)/Raw(load="Normal traffic data")
        packet.time = base_time + i
        packets.append(packet)
    
    # Create a traffic spike
    for i in range(20):
        # Large packets to simulate spike
        large_data = "X" * 10000  # 10KB payload
        packet = Ether()/IP(src="192.168.1.200", dst="10.0.0.1")/TCP(sport=54321, dport=80)/Raw(load=large_data)
        packet.time = base_time + 60 + i  # Spike at 60 seconds
        packets.append(packet)
    
    # Add some port-based anomalies
    for i in range(30):
        packet = Ether()/IP(src="192.168.1.150", dst="10.0.0.1")/TCP(sport=33333, dport=4444)/Raw(load="Suspicious port traffic")
        packet.time = base_time + 120 + i
        packets.append(packet)
    
    # Sort packets by time
    packets.sort(key=lambda x: x.time)
    
    # Write to PCAP file
    wrpcap("test_traffic.pcap", packets)
    print(f"Created test PCAP file with {len(packets)} packets")
    
    return "test_traffic.pcap"

if __name__ == "__main__":
    create_test_pcap()
