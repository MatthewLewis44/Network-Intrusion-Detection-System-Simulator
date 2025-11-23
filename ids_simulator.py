"""
Network Packet Simulator for IDS Training
==========================================
This script simulates 100 network packets with realistic patterns:
- 80% normal traffic (HTTP, TCP, DNS)
- 20% malicious patterns (SYN floods, invalid ports, large payloads)

Each packet is logged to 'network_logs.csv' with comprehensive fields.
"""

import csv
import random
from datetime import datetime, timedelta

# Configuration
TOTAL_PACKETS = 100
NORMAL_TRAFFIC_RATIO = 0.80  # 80% normal traffic
MALICIOUS_TRAFFIC_RATIO = 0.20  # 20% malicious traffic

# Protocol definitions
NORMAL_PROTOCOLS = ['TCP', 'UDP', 'ICMP']
NORMAL_PORTS = [80, 443, 22, 21, 53, 123, 8080, 443, 3306, 5432]
MALICIOUS_PROTOCOLS = ['TCP', 'UDP']  # Used for malicious packets
MALICIOUS_PORTS = [1, 2, 3, 4, 5, 666, 1234, 5555, 9999, 65535]

# Output file
OUTPUT_FILE = 'network_logs.csv'


def generate_random_ip():
    """
    Generate a random private IP address in the 192.168.x.x range.
    Returns: str - IP address in format 'xxx.xxx.xxx.xxx'
    """
    return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"


def generate_timestamp(base_time, index):
    """
    Generate a sequential timestamp starting from base time.
    Returns: str - ISO format timestamp
    """
    timestamp = base_time + timedelta(seconds=index)
    return timestamp.isoformat()


def generate_normal_packet(timestamp, packet_id):
    """
    Generate a normal network packet (benign traffic).
    
    Normal traffic characteristics:
    - Standard protocols (TCP, UDP, ICMP)
    - Well-known ports (HTTP, HTTPS, SSH, DNS, etc.)
    - Reasonable payload sizes (64-1024 bytes)
    - No suspicious patterns
    
    Args:
        timestamp (str): Packet timestamp
        packet_id (int): Unique packet identifier
    
    Returns:
        dict - Packet data with standard fields
    """
    protocols = ['TCP', 'UDP', 'ICMP']
    selected_protocol = random.choice(protocols)
    
    # Choose ports based on protocol
    if selected_protocol == 'TCP':
        port = random.choice([80, 443, 22, 3306, 5432, 8080])
    elif selected_protocol == 'UDP':
        port = random.choice([53, 123, 5353, 67, 68])
    else:  # ICMP
        port = 0  # ICMP doesn't use ports
    
    payload_size = random.randint(64, 1024)
    
    return {
        'timestamp': timestamp,
        'src_ip': generate_random_ip(),
        'dst_ip': generate_random_ip(),
        'protocol': selected_protocol,
        'port': port,
        'payload_size': payload_size,
        'is_malicious': False
    }


def generate_malicious_packet(timestamp, packet_id):
    """
    Generate a malicious network packet (anomalous/attack traffic).
    
    Malicious patterns simulated:
    1. SYN Flood: TCP packets to multiple ports in rapid succession
    2. Port Scanning: UDP/TCP to unusual/reserved ports (1-1024, high range)
    3. Large Payload: Oversized payloads (>10KB) suggesting DoS/data exfiltration
    4. Invalid Port: Packets to restricted/uncommon ports (666, 65535, etc.)
    5. Protocol Anomaly: Unusual protocol combinations
    
    Args:
        timestamp (str): Packet timestamp
        packet_id (int): Unique packet identifier
    
    Returns:
        dict - Packet data marked as malicious
    """
    malicious_types = [
        'syn_flood',
        'port_scan',
        'large_payload',
        'invalid_port',
        'protocol_anomaly'
    ]
    
    attack_type = random.choice(malicious_types)
    
    if attack_type == 'syn_flood':
        # SYN flood: rapid TCP connections to various ports
        protocol = 'TCP'
        port = random.randint(1000, 65535)
        payload_size = random.randint(40, 200)
    
    elif attack_type == 'port_scan':
        # Port scanning: probing unusual ports
        protocol = random.choice(['TCP', 'UDP'])
        port = random.choice(MALICIOUS_PORTS)
        payload_size = random.randint(20, 100)
    
    elif attack_type == 'large_payload':
        # Large payload: potential data exfiltration or DoS
        protocol = random.choice(['TCP', 'UDP'])
        port = random.choice([80, 443, 22, 3306])  # Using legitimate ports
        payload_size = random.randint(10000, 50000)  # Unusually large
    
    elif attack_type == 'invalid_port':
        # Invalid/restricted port: attempts to reach reserved ports
        protocol = random.choice(['TCP', 'UDP'])
        port = random.choice([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        payload_size = random.randint(64, 512)
    
    else:  # protocol_anomaly
        # Unusual protocol usage
        protocol = random.choice(['TCP', 'UDP'])
        port = random.randint(1, 100)  # Low port numbers unusual for source
        payload_size = random.randint(200, 1500)
    
    return {
        'timestamp': timestamp,
        'src_ip': generate_random_ip(),
        'dst_ip': generate_random_ip(),
        'protocol': protocol,
        'port': port,
        'payload_size': payload_size,
        'is_malicious': True
    }


def generate_packets(total_count, normal_ratio):
    """
    Generate a list of packets with specified normal/malicious split.
    
    Args:
        total_count (int): Total number of packets to generate
        normal_ratio (float): Ratio of normal packets (0.0-1.0)
    
    Returns:
        list - List of packet dictionaries
    """
    packets = []
    
    # Calculate packet counts
    normal_count = int(total_count * normal_ratio)
    malicious_count = total_count - normal_count
    
    # Generate base timestamp
    base_time = datetime.now() - timedelta(hours=1)
    
    print(f"Generating {total_count} network packets...")
    print(f"  - Normal traffic: {normal_count} packets ({normal_ratio*100:.0f}%)")
    print(f"  - Malicious traffic: {malicious_count} packets ({(1-normal_ratio)*100:.0f}%)")
    
    # Generate normal packets
    for i in range(normal_count):
        timestamp = generate_timestamp(base_time, i)
        packet = generate_normal_packet(timestamp, i)
        packets.append(packet)
    
    # Generate malicious packets
    for i in range(malicious_count):
        timestamp = generate_timestamp(base_time, normal_count + i)
        packet = generate_malicious_packet(timestamp, normal_count + i)
        packets.append(packet)
    
    # Shuffle packets to mix normal and malicious traffic
    random.shuffle(packets)
    
    return packets


def save_packets_to_csv(packets, filename):
    """
    Save generated packets to a CSV file.
    
    CSV columns:
    - timestamp: ISO format datetime
    - src_ip: Source IP address
    - dst_ip: Destination IP address
    - protocol: Network protocol (TCP, UDP, ICMP)
    - port: Destination port number
    - payload_size: Packet payload size in bytes
    - is_malicious: Boolean flag (True=malicious, False=normal)
    
    Args:
        packets (list): List of packet dictionaries
        filename (str): Output CSV filename
    
    Returns:
        None
    """
    fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'port', 'payload_size', 'is_malicious']
    
    try:
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            # Write header
            writer.writeheader()
            
            # Write packet data
            writer.writerows(packets)
        
        print(f"\n✓ Successfully saved {len(packets)} packets to '{filename}'")
        
        # Print summary statistics
        normal_count = sum(1 for p in packets if not p['is_malicious'])
        malicious_count = len(packets) - normal_count
        
        print(f"\nPacket Summary:")
        print(f"  - Total packets: {len(packets)}")
        print(f"  - Normal packets: {normal_count}")
        print(f"  - Malicious packets: {malicious_count}")
        print(f"  - Avg payload size: {sum(p['payload_size'] for p in packets) / len(packets):.2f} bytes")
        
    except IOError as e:
        print(f"✗ Error writing to file '{filename}': {e}")
        raise


def main():
    """
    Main execution function.
    Orchestrates packet generation and CSV export.
    """
    print("=" * 60)
    print("Network Packet Simulator for IDS Training")
    print("=" * 60)
    
    # Generate packets
    packets = generate_packets(TOTAL_PACKETS, NORMAL_TRAFFIC_RATIO)
    
    # Save to CSV
    save_packets_to_csv(packets, OUTPUT_FILE)
    
    print("\n" + "=" * 60)
    print("Simulation complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
