"""
Dataset converter for network traffic datasets.
Converts various dataset formats (UNSW-NB15, CICIDS2017, NSL-KDD) to our JSON format.
"""

import csv
import json
import random
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any


def convert_cicids2017(csv_path: str, output_path: str, max_rows: int = 500) -> List[Dict[str, Any]]:
    """
    Convert CICIDS2017 dataset to our network log JSON format.
    
    Handles both full datasets (with Source IP/Destination IP columns) and 
    flow-based datasets (without IP columns) by generating realistic IPs
    based on attack types.
    
    Args:
        csv_path: Path to CICIDS2017 CSV file
        output_path: Path to output JSON file
        max_rows: Maximum rows to convert
    
    Returns:
        List of converted log entries
    """
    logs = []
    base_time = datetime.now()
    
    # Attack type to source IP pattern mapping for flow-based datasets
    attack_source_ips = {
        'DDoS': lambda: f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'DoS': lambda: f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'PortScan': lambda: f"45.33.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'Bot': lambda: f"185.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'Brute Force': lambda: f"185.220.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'Web Attack': lambda: f"104.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'Infiltration': lambda: f"192.168.1.{random.randint(100, 254)}",
        'Heartbleed': lambda: f"45.33.32.{random.randint(1, 254)}",
        'FTP-Patator': lambda: f"185.220.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'SSH-Patator': lambda: f"185.220.{random.randint(1, 254)}.{random.randint(1, 254)}",
    }
    
    # Common internal servers that would be targets
    internal_servers = [
        "192.168.1.10", "192.168.1.20", "192.168.1.100",
        "10.0.0.5", "10.0.0.10", "10.0.0.50",
    ]
    
    with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            
            try:
                # Check if this is a full dataset (has IP columns) or flow-based (no IPs)
                source_ip = row.get(' Source IP', row.get('Source IP', '')).strip() if row.get(' Source IP') or row.get('Source IP') else ''
                dest_ip = row.get(' Destination IP', row.get('Destination IP', '')).strip() if row.get(' Destination IP') or row.get('Destination IP') else ''
                
                # Get the label (attack type)
                label = row.get(' Label', row.get('Label', 'BENIGN')).strip()
                
                # If no IPs found, generate realistic ones based on attack type
                if not source_ip or not dest_ip:
                    if label == 'BENIGN':
                        source_ip = f"192.168.1.{random.randint(10, 99)}"
                        dest_ip = random.choice(internal_servers) if random.random() < 0.5 else f"8.8.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    else:
                        # Find matching attack pattern
                        source_gen = None
                        for attack_key, gen_func in attack_source_ips.items():
                            if attack_key.lower() in label.lower():
                                source_gen = gen_func
                                break
                        
                        if source_gen:
                            source_ip = source_gen()
                        else:
                            source_ip = f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                        
                        dest_ip = random.choice(internal_servers)
                
                # Get destination port
                dest_port_raw = row.get(' Destination Port', row.get('Destination Port', 0))
                dest_port = int(float(dest_port_raw)) if dest_port_raw else 80
                
                log_entry = {
                    "timestamp": (base_time + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "protocol": "TCP",
                    "bytes_sent": int(float(row.get('Total Length of Fwd Packets', row.get(' Total Fwd Packets', row.get('Total Fwd Packets', 0))))) if row.get('Total Length of Fwd Packets') or row.get(' Total Fwd Packets') or row.get('Total Fwd Packets') else random.randint(100, 5000),
                    "bytes_received": int(float(row.get('Total Length of Bwd Packets', row.get(' Total Backward Packets', row.get('Total Backward Packets', 0))))) if row.get('Total Length of Bwd Packets') or row.get(' Total Backward Packets') or row.get('Total Backward Packets') else random.randint(100, 5000),
                    "duration": float(row.get(' Flow Duration', row.get('Flow Duration', 0))) / 1000000 if row.get(' Flow Duration') or row.get('Flow Duration') else random.uniform(0.1, 10),
                    "action": "allow" if label == 'BENIGN' else "deny",
                }
                
                if label != 'BENIGN':
                    log_entry["attack_type"] = label
                
                logs.append(log_entry)
                    
            except (ValueError, KeyError) as e:
                continue  # Skip malformed rows
    
    # Save to JSON
    with open(output_path, 'w') as f:
        json.dump(logs, f, indent=2)
    
    print(f"Converted {len(logs)} entries to {output_path}")
    return logs


def convert_nsl_kdd(txt_path: str, output_path: str, max_rows: int = 500) -> List[Dict[str, Any]]:
    """
    Convert NSL-KDD dataset to our format.
    
    NSL-KDD columns (41 features + label + difficulty):
    0: duration, 1: protocol_type, 2: service, 3: flag, 4: src_bytes, 5: dst_bytes...
    
    Note: NSL-KDD doesn't have actual IP addresses, so we generate fake ones.
    """
    logs = []
    base_time = datetime.now()
    
    # Service to port mapping
    service_ports = {
        'http': 80, 'https': 443, 'ftp': 21, 'ssh': 22, 'telnet': 23,
        'smtp': 25, 'dns': 53, 'pop3': 110, 'imap': 143, 'mysql': 3306,
        'rdp': 3389, 'vnc': 5900, 'other': 8080, 'private': 1024
    }
    
    with open(txt_path, 'r') as f:
        for i, line in enumerate(f):
            if i >= max_rows:
                break
            
            try:
                parts = line.strip().split(',')
                if len(parts) < 42:
                    continue
                
                duration = float(parts[0])
                protocol = parts[1]
                service = parts[2]
                src_bytes = int(parts[4])
                dst_bytes = int(parts[5])
                label = parts[41]  # Attack type
                
                # Generate fake IPs based on attack type
                if label == 'normal':
                    source_ip = f"192.168.1.{random.randint(1, 254)}"
                    dest_ip = f"10.0.0.{random.randint(1, 254)}"
                else:
                    source_ip = f"45.33.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    dest_ip = f"192.168.1.{random.randint(1, 254)}"
                
                log_entry = {
                    "timestamp": (base_time + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "dest_port": service_ports.get(service, 8080),
                    "protocol": protocol.upper(),
                    "bytes_sent": src_bytes,
                    "bytes_received": dst_bytes,
                    "duration": duration,
                    "action": "allow" if label == 'normal' else "deny",
                }
                
                if label != 'normal':
                    log_entry["attack_type"] = label
                
                logs.append(log_entry)
                
            except (ValueError, IndexError) as e:
                continue
    
    with open(output_path, 'w') as f:
        json.dump(logs, f, indent=2)
    
    print(f"Converted {len(logs)} entries to {output_path}")
    return logs


def convert_unsw_nb15(csv_path: str, output_path: str, max_rows: int = 1000) -> List[Dict[str, Any]]:
    """
    Convert UNSW-NB15 dataset to our network log JSON format.
    
    UNSW-NB15 has REAL IP addresses and ports:
    - srcip: Source IP address
    - sport: Source port  
    - dstip: Destination IP address
    - dsport: Destination port
    - proto: Protocol
    - attack_cat: Attack category
    
    Note: The CSV files don't have headers, so we define them manually.
    
    Args:
        csv_path: Path to UNSW-NB15 CSV file
        output_path: Path to output JSON file
        max_rows: Maximum rows to convert
    
    Returns:
        List of converted log entries
    """
    logs = []
    base_time = datetime.now()
    
    # UNSW-NB15 column names (from NUSW-NB15_features.csv)
    columns = [
        'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur',
        'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service',
        'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
        'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit',
        'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat',
        'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login',
        'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
        'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
        'attack_cat', 'Label'
    ]
    
    with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            
            try:
                if len(row) < 45:
                    continue
                
                # Map row values to column names
                data = dict(zip(columns, row))
                
                # Extract values
                source_ip = data.get('srcip', '').strip()
                dest_ip = data.get('dstip', '').strip()
                source_port = data.get('sport', '0')
                dest_port = data.get('dsport', '0')
                protocol = data.get('proto', 'tcp').upper()
                attack_cat = data.get('attack_cat', '').strip()
                label = data.get('Label', '0')
                
                # Skip if no valid IPs
                if not source_ip or not dest_ip:
                    continue
                
                # Convert ports
                try:
                    source_port = int(float(source_port))
                    dest_port = int(float(dest_port))
                except:
                    source_port = 0
                    dest_port = 80
                
                # Get bytes
                try:
                    bytes_sent = int(float(data.get('sbytes', 0)))
                    bytes_received = int(float(data.get('dbytes', 0)))
                except:
                    bytes_sent = 0
                    bytes_received = 0
                
                # Get duration
                try:
                    duration = float(data.get('dur', 0))
                except:
                    duration = 0
                
                # Determine if attack
                is_attack = label == '1' or (attack_cat and attack_cat not in ['', 'Normal', '-'])
                
                log_entry = {
                    "timestamp": (base_time + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "source_port": source_port,
                    "dest_port": dest_port,
                    "protocol": protocol if protocol else "TCP",
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_received,
                    "duration": duration,
                    "action": "deny" if is_attack else "allow",
                }
                
                if is_attack and attack_cat and attack_cat not in ['', '-']:
                    log_entry["attack_type"] = attack_cat
                
                logs.append(log_entry)
                    
            except (ValueError, KeyError, IndexError) as e:
                continue  # Skip malformed rows
    
    # Save to JSON
    with open(output_path, 'w') as f:
        json.dump(logs, f, indent=2)
    
    print(f"Converted {len(logs)} entries to {output_path}")
    return logs


def generate_realistic_traffic(output_path: str, num_entries: int = 200) -> List[Dict[str, Any]]:
    """
    Generate realistic network traffic data for demo purposes.
    Mix of normal traffic and attack patterns.
    """
    logs = []
    base_time = datetime.now() - timedelta(hours=12)
    
    # Common destinations
    normal_destinations = [
        ("8.8.8.8", 53, "DNS"),
        ("1.1.1.1", 53, "DNS"),
        ("142.250.190.78", 443, "HTTPS"),  # Google
        ("157.240.1.35", 443, "HTTPS"),     # Facebook
        ("52.94.236.248", 443, "HTTPS"),    # AWS
        ("20.190.128.1", 443, "HTTPS"),     # Microsoft
    ]
    
    internal_servers = [
        ("192.168.1.10", 80, "Web Server"),
        ("192.168.1.20", 22, "SSH Server"),
        ("192.168.1.30", 3306, "MySQL"),
        ("192.168.1.40", 445, "File Server"),
        ("10.0.0.5", 8080, "App Server"),
    ]
    
    # Attack patterns
    attack_patterns = [
        {
            "name": "Port Scan",
            "source_base": "45.33.32.",
            "targets": [(f"192.168.1.{i}", p, "scan") for i in range(1, 50) for p in [22, 80, 443, 3389, 445]],
            "bytes_range": (60, 200),
        },
        {
            "name": "Brute Force SSH",
            "source_base": "185.220.101.",
            "targets": [("192.168.1.20", 22, "ssh")] * 50,
            "bytes_range": (100, 500),
        },
        {
            "name": "Data Exfiltration",
            "source_base": "192.168.1.",
            "targets": [("45.33.32.156", 443, "exfil")],
            "bytes_range": (50000, 500000),
        },
        {
            "name": "DDoS",
            "source_base": None,  # Multiple random sources
            "targets": [("192.168.1.10", 80, "http")],
            "bytes_range": (1000, 5000),
        },
    ]
    
    # Generate normal traffic (70%)
    normal_count = int(num_entries * 0.7)
    for i in range(normal_count):
        source_ip = f"192.168.1.{random.randint(100, 200)}"
        
        if random.random() < 0.6:
            # External traffic
            dest_ip, port, service = random.choice(normal_destinations)
        else:
            # Internal traffic
            dest_ip, port, service = random.choice(internal_servers)
        
        logs.append({
            "timestamp": (base_time + timedelta(seconds=i*10)).strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "source_port": random.randint(49152, 65535),
            "dest_port": port,
            "protocol": "TCP" if port != 53 else "UDP",
            "bytes_sent": random.randint(100, 5000),
            "bytes_received": random.randint(100, 10000),
            "duration": round(random.uniform(0.01, 5.0), 3),
            "action": "allow",
        })
    
    # Generate attack traffic (30%)
    attack_count = num_entries - normal_count
    for i in range(attack_count):
        pattern = random.choice(attack_patterns)
        
        if pattern["source_base"]:
            source_ip = pattern["source_base"] + str(random.randint(1, 254))
        else:
            source_ip = f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        dest_ip, port, _ = random.choice(pattern["targets"])
        
        logs.append({
            "timestamp": (base_time + timedelta(seconds=normal_count*10 + i*5)).strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "source_port": random.randint(49152, 65535),
            "dest_port": port,
            "protocol": "TCP",
            "bytes_sent": random.randint(*pattern["bytes_range"]),
            "bytes_received": random.randint(50, 500),
            "duration": round(random.uniform(0.001, 1.0), 3),
            "action": "deny",
            "attack_type": pattern["name"],
        })
    
    # Shuffle to mix normal and attack traffic
    random.shuffle(logs)
    
    # Save to JSON
    with open(output_path, 'w') as f:
        json.dump(logs, f, indent=2)
    
    print(f"Generated {len(logs)} entries to {output_path}")
    return logs


if __name__ == "__main__":
    import sys
    
    # Get the directory where this script is located for proper path resolution
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python dataset_converter.py generate [output.json] [count]")
        print("  python dataset_converter.py cicids input.csv output.json [max_rows]")
        print("  python dataset_converter.py nsl input.txt output.json [max_rows]")
        print("  python dataset_converter.py unsw input.csv output.json [max_rows]")
        print("")
        print("Examples:")
        print("  python dataset_converter.py generate                    # Creates realistic_traffic.json in sample_data/")
        print("  python dataset_converter.py generate custom.json 500   # Creates custom.json with 500 entries")
        print("  python dataset_converter.py cicids cicids2017_cleaned.csv converted.json 1000")
        print("  python dataset_converter.py unsw UNSW-NB15_1.csv unsw_converted.json 2000")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "generate":
        # Default output is in the same directory as this script
        default_output = os.path.join(SCRIPT_DIR, "realistic_traffic.json")
        output = sys.argv[2] if len(sys.argv) > 2 else default_output
        # If output is a relative path without directory, put it in script dir
        if not os.path.isabs(output) and os.path.dirname(output) == '':
            output = os.path.join(SCRIPT_DIR, output)
        count = int(sys.argv[3]) if len(sys.argv) > 3 else 200
        generate_realistic_traffic(output, count)
        
    elif command == "cicids":
        if len(sys.argv) < 4:
            print("Usage: python dataset_converter.py cicids input.csv output.json [max_rows]")
            sys.exit(1)
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        # Resolve relative paths to script directory
        if not os.path.isabs(input_path) and os.path.dirname(input_path) == '':
            input_path = os.path.join(SCRIPT_DIR, input_path)
        if not os.path.isabs(output_path) and os.path.dirname(output_path) == '':
            output_path = os.path.join(SCRIPT_DIR, output_path)
        max_rows = int(sys.argv[4]) if len(sys.argv) > 4 else 500
        convert_cicids2017(input_path, output_path, max_rows)
        
    elif command == "nsl":
        if len(sys.argv) < 4:
            print("Usage: python dataset_converter.py nsl input.txt output.json [max_rows]")
            sys.exit(1)
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        # Resolve relative paths to script directory
        if not os.path.isabs(input_path) and os.path.dirname(input_path) == '':
            input_path = os.path.join(SCRIPT_DIR, input_path)
        if not os.path.isabs(output_path) and os.path.dirname(output_path) == '':
            output_path = os.path.join(SCRIPT_DIR, output_path)
        max_rows = int(sys.argv[4]) if len(sys.argv) > 4 else 500
        convert_nsl_kdd(input_path, output_path, max_rows)
    
    elif command == "unsw":
        if len(sys.argv) < 4:
            print("Usage: python dataset_converter.py unsw input.csv output.json [max_rows]")
            print("Example: python dataset_converter.py unsw UNSW-NB15_1.csv unsw_converted.json 2000")
            sys.exit(1)
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        # Resolve relative paths to script directory
        if not os.path.isabs(input_path) and os.path.dirname(input_path) == '':
            input_path = os.path.join(SCRIPT_DIR, input_path)
        if not os.path.isabs(output_path) and os.path.dirname(output_path) == '':
            output_path = os.path.join(SCRIPT_DIR, output_path)
        max_rows = int(sys.argv[4]) if len(sys.argv) > 4 else 1000
        convert_unsw_nb15(input_path, output_path, max_rows)
    
    else:
        print(f"Unknown command: {command}")
        print("Available commands: generate, cicids, nsl, unsw")
