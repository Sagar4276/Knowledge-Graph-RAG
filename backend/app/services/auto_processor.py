"""
Auto-processor service for automatic CSV detection, conversion, and ingestion.
Handles multiple dataset formats and provides a unified pipeline.
"""

import csv
import json
import logging
import os
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import uuid

from app.services.network_parser import NetworkLogParser
from app.services.anomaly_detector import analyze_network_traffic
from app.services.neo4j_service import Neo4jService
from app.config import settings

logger = logging.getLogger(__name__)


class DatasetFormat:
    """Enum-like class for supported dataset formats."""
    UNSW_NB15 = "unsw_nb15"
    UNSW_NB15_PREPROCESSED = "unsw_nb15_preprocessed"  # Training/testing sets without IPs
    CICIDS2017 = "cicids2017"
    CUSTOM_JSON = "custom_json"
    UNKNOWN = "unknown"


# Column mappings for different dataset formats
UNSW_NB15_COLUMNS = [
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


def detect_dataset_format(csv_path: str) -> Tuple[str, List[str]]:
    """
    Auto-detect the format of a CSV file.
    
    Returns:
        Tuple of (format_name, column_headers)
    """
    try:
        # Read with utf-8-sig to handle BOM
        with open(csv_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            # Read first few lines
            first_line = f.readline().strip()
            second_line = f.readline().strip()
            
            # Check if first line looks like headers
            first_values = first_line.split(',')
            second_values = second_line.split(',')
            
            # Clean up any remaining BOM or whitespace
            if first_values:
                first_values[0] = first_values[0].strip().lstrip('\ufeff')
            
            # UNSW-NB15: No headers, first value is an IP, ~49 columns
            if len(first_values) >= 45 and _looks_like_ip(first_values[0]):
                logger.info(f"Detected UNSW-NB15 format (no headers, ~49 columns)")
                return DatasetFormat.UNSW_NB15, UNSW_NB15_COLUMNS
            
            # CICIDS2017: Has headers with specific column names
            lower_headers = [h.lower().strip() for h in first_values]
            if 'destination port' in lower_headers or ' destination port' in lower_headers:
                if 'source ip' in lower_headers or ' source ip' in lower_headers:
                    logger.info(f"Detected CICIDS2017 format with IPs")
                    return DatasetFormat.CICIDS2017, first_values
                else:
                    logger.info(f"Detected CICIDS2017 flow format (no IPs)")
                    return DatasetFormat.CICIDS2017, first_values
            
            # Check for srcip column (UNSW-NB15 with headers)
            if 'srcip' in lower_headers:
                logger.info(f"Detected UNSW-NB15 format with headers")
                return DatasetFormat.UNSW_NB15, first_values
            
            # Check for preprocessed UNSW-NB15 (has id, attack_cat, label but NO srcip)
            if 'attack_cat' in lower_headers and 'label' in lower_headers and 'id' in lower_headers:
                logger.info(f"Detected UNSW-NB15 preprocessed format (no IPs, will generate synthetic)")
                return DatasetFormat.UNSW_NB15_PREPROCESSED, first_values
            
            # Check if second row looks like UNSW-NB15 data
            if len(second_values) >= 45 and _looks_like_ip(second_values[0]):
                logger.info(f"Detected UNSW-NB15 format (with header row)")
                return DatasetFormat.UNSW_NB15, UNSW_NB15_COLUMNS
            
            logger.warning(f"Unknown dataset format, will attempt generic parsing")
            return DatasetFormat.UNKNOWN, first_values
            
    except Exception as e:
        logger.error(f"Error detecting dataset format: {e}")
        return DatasetFormat.UNKNOWN, []


def _looks_like_ip(value: str) -> bool:
    """Check if a value looks like an IP address."""
    # Strip BOM and whitespace
    value = value.strip().lstrip('\ufeff')
    parts = value.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def convert_csv_to_logs(csv_path: str, max_rows: int = 5000) -> List[Dict[str, Any]]:
    """
    Auto-detect CSV format and convert to our log format.
    
    Args:
        csv_path: Path to CSV file
        max_rows: Maximum rows to process
        
    Returns:
        List of log entries in our standard format
    """
    format_type, columns = detect_dataset_format(csv_path)
    
    if format_type == DatasetFormat.UNSW_NB15:
        return _convert_unsw_nb15(csv_path, columns, max_rows)
    elif format_type == DatasetFormat.UNSW_NB15_PREPROCESSED:
        return _convert_unsw_nb15_preprocessed(csv_path, columns, max_rows)
    elif format_type == DatasetFormat.CICIDS2017:
        return _convert_cicids(csv_path, columns, max_rows)
    else:
        return _convert_generic(csv_path, max_rows)


def _convert_unsw_nb15(csv_path: str, columns: List[str], max_rows: int) -> List[Dict[str, Any]]:
    """Convert UNSW-NB15 format CSV (with or without headers)."""
    logs = []
    base_time = datetime.now()
    
    # Check if file has headers by looking at first row
    has_headers = False
    with open(csv_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
        first_line = f.readline().strip()
        first_values = first_line.split(',')
        if first_values:
            first_values[0] = first_values[0].strip().lstrip('\ufeff')
        # If first value is not an IP, assume headers exist
        if not _looks_like_ip(first_values[0]):
            has_headers = True
            logger.info(f"UNSW-NB15 file has headers. First 5 columns: {first_values[:5]}")
    
    with open(csv_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
        if has_headers:
            # Use DictReader when file has headers
            reader = csv.DictReader(f)
            
            # Log the actual fieldnames for debugging
            logger.info(f"CSV fieldnames: {reader.fieldnames[:10] if reader.fieldnames else 'None'}")
            
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break
                
                try:
                    # Normalize column names - lowercase and strip whitespace
                    normalized_row = {k.lower().strip(): v for k, v in row.items()}
                    
                    source_ip = normalized_row.get('srcip', '').strip()
                    dest_ip = normalized_row.get('dstip', '').strip()
                    
                    # Debug first few rows
                    if i < 3:
                        logger.debug(f"Row {i}: srcip={source_ip}, dstip={dest_ip}")
                    
                    if not source_ip or not dest_ip:
                        if i < 3:
                            logger.warning(f"Row {i} missing IP: srcip='{source_ip}', dstip='{dest_ip}'")
                        continue
                    
                    if not _looks_like_ip(source_ip):
                        if i < 3:
                            logger.warning(f"Row {i} srcip doesn't look like IP: '{source_ip}'")
                        continue
                    
                    try:
                        sport_val = normalized_row.get('sport', '0') or '0'
                        dsport_val = normalized_row.get('dsport', '0') or '0'
                        source_port = int(float(sport_val))
                        dest_port = int(float(dsport_val))
                    except:
                        source_port = 0
                        dest_port = 80
                    
                    try:
                        sbytes_val = normalized_row.get('sbytes', '0') or '0'
                        dbytes_val = normalized_row.get('dbytes', '0') or '0'
                        dur_val = normalized_row.get('dur', '0') or '0'
                        bytes_sent = int(float(sbytes_val))
                        bytes_received = int(float(dbytes_val))
                        duration = float(dur_val)
                    except:
                        bytes_sent = 0
                        bytes_received = 0
                        duration = 0
                    
                    attack_cat = normalized_row.get('attack_cat', '').strip()
                    label = normalized_row.get('label', '0')
                    is_attack = str(label) == '1' or (attack_cat and attack_cat not in ['', 'Normal', '-', ' '])
                    
                    log_entry = {
                        "timestamp": (base_time + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
                        "source_ip": source_ip,
                        "dest_ip": dest_ip,
                        "source_port": source_port,
                        "dest_port": dest_port,
                        "protocol": normalized_row.get('proto', 'TCP').upper(),
                        "bytes_sent": bytes_sent,
                        "bytes_received": bytes_received,
                        "duration": duration,
                        "action": "deny" if is_attack else "allow",
                    }
                    
                    if is_attack and attack_cat and attack_cat not in ['', '-', ' ']:
                        log_entry["attack_type"] = attack_cat
                    
                    logs.append(log_entry)
                    
                except Exception as e:
                    if i < 3:
                        logger.error(f"Error parsing row {i}: {e}")
                    continue
        else:
            # No headers - use original column mapping approach
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break
                
                try:
                    if len(row) < 45:
                        continue
                    
                    data = dict(zip(columns, row))
                    
                    source_ip = data.get('srcip', '').strip()
                    dest_ip = data.get('dstip', '').strip()
                    
                    if not source_ip or not dest_ip or not _looks_like_ip(source_ip):
                        continue
                    
                    try:
                        source_port = int(float(data.get('sport', 0)))
                        dest_port = int(float(data.get('dsport', 0)))
                    except:
                        source_port = 0
                        dest_port = 80
                    
                    try:
                        bytes_sent = int(float(data.get('sbytes', 0)))
                        bytes_received = int(float(data.get('dbytes', 0)))
                        duration = float(data.get('dur', 0))
                    except:
                        bytes_sent = 0
                        bytes_received = 0
                        duration = 0
                    
                    attack_cat = data.get('attack_cat', '').strip()
                    label = data.get('Label', '0')
                    is_attack = label == '1' or (attack_cat and attack_cat not in ['', 'Normal', '-'])
                    
                    log_entry = {
                        "timestamp": (base_time + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
                        "source_ip": source_ip,
                        "dest_ip": dest_ip,
                        "source_port": source_port,
                        "dest_port": dest_port,
                        "protocol": data.get('proto', 'TCP').upper(),
                        "bytes_sent": bytes_sent,
                        "bytes_received": bytes_received,
                        "duration": duration,
                        "action": "deny" if is_attack else "allow",
                    }
                    
                    if is_attack and attack_cat and attack_cat not in ['', '-']:
                        log_entry["attack_type"] = attack_cat
                    
                    logs.append(log_entry)
                    
                except Exception as e:
                    continue
    
    logger.info(f"Converted {len(logs)} entries from UNSW-NB15 format")
    return logs


def _convert_unsw_nb15_preprocessed(csv_path: str, columns: List[str], max_rows: int) -> List[Dict[str, Any]]:
    """
    Convert preprocessed UNSW-NB15 format CSV (training/testing sets without IP addresses).
    Generates synthetic IPs from the row ID to enable network graph building.
    """
    logs = []
    base_time = datetime.now()
    
    # Generate deterministic IPs from ID - creates realistic network topology
    def id_to_ip(row_id: int, is_source: bool = True) -> str:
        """Generate a deterministic IP from row ID."""
        if is_source:
            # Internal sources: 192.168.x.x or 10.x.x.x
            subnet = (row_id % 2)
            if subnet == 0:
                return f"192.168.{(row_id // 256) % 256}.{row_id % 256}"
            else:
                return f"10.{(row_id // 65536) % 256}.{(row_id // 256) % 256}.{row_id % 256}"
        else:
            # Destinations: could be internal or external based on pattern
            if row_id % 5 == 0:  # 20% external
                return f"{59 + (row_id % 100)}.{(row_id // 256) % 256}.{row_id % 256}.{(row_id * 7) % 256}"
            else:  # 80% internal
                return f"192.168.{(row_id // 100) % 256}.{(row_id * 3) % 256}"
    
    with open(csv_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
        reader = csv.DictReader(f)
        
        logger.info(f"Processing preprocessed UNSW-NB15 file with columns: {reader.fieldnames[:10] if reader.fieldnames else 'None'}")
        
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            
            try:
                # Normalize column names
                normalized_row = {k.lower().strip(): v for k, v in row.items()}
                
                # Get row ID for synthetic IP generation
                try:
                    row_id = int(normalized_row.get('id', i))
                except:
                    row_id = i
                
                # Generate synthetic IPs from row ID
                source_ip = id_to_ip(row_id, is_source=True)
                dest_ip = id_to_ip(row_id, is_source=False)
                
                # Parse other fields
                try:
                    duration = float(normalized_row.get('dur', 0) or 0)
                except:
                    duration = 0
                
                try:
                    bytes_sent = int(float(normalized_row.get('sbytes', 0) or 0))
                    bytes_received = int(float(normalized_row.get('dbytes', 0) or 0))
                except:
                    bytes_sent = 0
                    bytes_received = 0
                
                protocol = normalized_row.get('proto', 'tcp').upper()
                
                # Get attack information
                attack_cat = normalized_row.get('attack_cat', '').strip()
                label = normalized_row.get('label', '0')
                is_attack = str(label) == '1' or (attack_cat and attack_cat not in ['', 'Normal', '-', ' '])
                
                # Generate synthetic port from service if available
                service = normalized_row.get('service', '-')
                service_ports = {
                    'http': 80, 'https': 443, 'ftp': 21, 'ssh': 22, 'dns': 53,
                    'smtp': 25, 'pop3': 110, 'imap': 143, 'snmp': 161, 'dhcp': 67
                }
                dest_port = service_ports.get(service.lower(), 80 + (row_id % 1000))
                
                log_entry = {
                    "timestamp": (base_time + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "source_port": 1024 + (row_id % 60000),
                    "dest_port": dest_port,
                    "protocol": protocol,
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_received,
                    "duration": duration,
                    "action": "deny" if is_attack else "allow",
                }
                
                if is_attack and attack_cat and attack_cat not in ['', '-', ' ', 'Normal']:
                    log_entry["attack_type"] = attack_cat
                
                logs.append(log_entry)
                
                if i < 3:
                    logger.debug(f"Row {i}: Generated {source_ip} -> {dest_ip}, attack={attack_cat}, label={label}")
                
            except Exception as e:
                if i < 3:
                    logger.error(f"Error parsing preprocessed row {i}: {e}")
                continue
    
    logger.info(f"Converted {len(logs)} entries from preprocessed UNSW-NB15 format")
    return logs


def _convert_cicids(csv_path: str, columns: List[str], max_rows: int) -> List[Dict[str, Any]]:
    """Convert CICIDS2017 format CSV."""
    logs = []
    base_time = datetime.now()
    
    # Attack type to source IP pattern mapping
    attack_source_ips = {
        'DDoS': lambda: f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'DoS': lambda: f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'PortScan': lambda: f"45.33.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'Bot': lambda: f"185.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        'Brute Force': lambda: f"185.220.{random.randint(1, 254)}.{random.randint(1, 254)}",
    }
    
    internal_servers = ["192.168.1.10", "192.168.1.20", "192.168.1.100", "10.0.0.5", "10.0.0.10"]
    
    with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            
            try:
                # Try to get IP addresses
                source_ip = row.get(' Source IP', row.get('Source IP', '')).strip() if row.get(' Source IP') or row.get('Source IP') else ''
                dest_ip = row.get(' Destination IP', row.get('Destination IP', '')).strip() if row.get(' Destination IP') or row.get('Destination IP') else ''
                
                label = row.get(' Label', row.get('Label', 'BENIGN')).strip()
                
                # Generate IPs if not present
                if not source_ip or not dest_ip:
                    if label == 'BENIGN':
                        source_ip = f"192.168.1.{random.randint(10, 99)}"
                        dest_ip = random.choice(internal_servers)
                    else:
                        source_gen = None
                        for attack_key, gen_func in attack_source_ips.items():
                            if attack_key.lower() in label.lower():
                                source_gen = gen_func
                                break
                        source_ip = source_gen() if source_gen else f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                        dest_ip = random.choice(internal_servers)
                
                dest_port_raw = row.get(' Destination Port', row.get('Destination Port', 0))
                dest_port = int(float(dest_port_raw)) if dest_port_raw else 80
                
                log_entry = {
                    "timestamp": (base_time + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "protocol": "TCP",
                    "bytes_sent": random.randint(100, 5000),
                    "bytes_received": random.randint(100, 5000),
                    "duration": random.uniform(0.1, 10),
                    "action": "allow" if label == 'BENIGN' else "deny",
                }
                
                if label != 'BENIGN':
                    log_entry["attack_type"] = label
                
                logs.append(log_entry)
                
            except Exception as e:
                continue
    
    logger.info(f"Converted {len(logs)} entries from CICIDS format")
    return logs


def _convert_generic(csv_path: str, max_rows: int) -> List[Dict[str, Any]]:
    """Try generic conversion for unknown formats."""
    logs = []
    base_time = datetime.now()
    
    with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            
            try:
                # Try common column name variations
                source_ip = (row.get('source_ip') or row.get('src_ip') or 
                           row.get('srcip') or row.get('src') or '').strip()
                dest_ip = (row.get('dest_ip') or row.get('dst_ip') or 
                         row.get('dstip') or row.get('dst') or '').strip()
                dest_port = int(row.get('dest_port') or row.get('dst_port') or 
                               row.get('dsport') or row.get('dport') or 80)
                
                if not source_ip or not dest_ip:
                    continue
                
                logs.append({
                    "timestamp": (base_time + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "protocol": row.get('protocol', row.get('proto', 'TCP')).upper(),
                    "bytes_sent": int(row.get('bytes_sent', row.get('sbytes', 0))),
                    "bytes_received": int(row.get('bytes_received', row.get('dbytes', 0))),
                    "action": "allow",
                })
                
            except Exception as e:
                continue
    
    logger.info(f"Converted {len(logs)} entries from generic format")
    return logs


class AutoProcessor:
    """
    Automated pipeline for CSV processing, ingestion, and analysis.
    """
    
    def __init__(self, neo4j_service: Neo4jService):
        self.neo4j_service = neo4j_service
        self.parser = NetworkLogParser()
    
    def process_csv(self, csv_path: str, max_rows: int = 5000) -> Dict[str, Any]:
        """
        Full automated pipeline: detect format → convert → ingest → analyze → store.
        
        Args:
            csv_path: Path to CSV file
            max_rows: Maximum rows to process
            
        Returns:
            Complete processing result with graph_id and analysis
        """
        import time
        start_time = time.time()
        
        logger.info(f"Starting auto-processing of {csv_path}")
        
        # Step 1: Detect format first
        format_type, columns = detect_dataset_format(csv_path)
        
        # Map format type to display name
        format_display = {
            DatasetFormat.UNSW_NB15: "UNSW-NB15",
            DatasetFormat.UNSW_NB15_PREPROCESSED: "UNSW-NB15 (Preprocessed)",
            DatasetFormat.CICIDS2017: "CICIDS2017",
            DatasetFormat.CUSTOM_JSON: "Custom JSON",
            DatasetFormat.UNKNOWN: "Unknown"
        }.get(format_type, "Unknown")
        
        # Step 2: Convert CSV to logs
        logs = convert_csv_to_logs(csv_path, max_rows)
        
        if not logs:
            raise ValueError(f"No valid log entries could be extracted from {csv_path}")
        
        # Step 3: Process and analyze
        result = self.process_logs(logs)
        
        # Add format detection and timing info
        processing_time = time.time() - start_time
        result["format_detected"] = format_display
        result["processing_time"] = round(processing_time, 2)
        result["rows_processed"] = len(logs)
        result["message"] = "CSV processed successfully"
        
        # Add stats object in expected format
        result["stats"] = {
            "total_nodes": result["processing_summary"]["nodes_created"],
            "total_edges": result["processing_summary"]["edges_created"],
            "total_ips": result["processing_summary"]["unique_ips"],
            "total_ports": result["processing_summary"]["unique_ports"],
            "total_connections": result["processing_summary"]["valid_connections"],
            "anomaly_count": result["security_analysis"]["anomalies_detected"]
        }
        
        return result
    
    def process_logs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process log entries through the full pipeline.
        
        Args:
            logs: List of log entry dictionaries
            
        Returns:
            Complete processing result
        """
        # Parse logs
        connections = self.parser.parse_logs(logs)
        
        if not connections:
            raise ValueError("No valid connections found in logs")
        
        # Analyze for anomalies (ML-based)
        analysis = analyze_network_traffic(connections)
        analyzed_connections = analysis["connections"]
        summary = analysis["summary"]
        
        # Convert to graph format with enhanced data
        graph_data = self._connections_to_enhanced_graph(analyzed_connections, logs)
        
        # Store in Neo4j using MERGE for unified graph
        graph_id = self.neo4j_service.store_graph_merge(graph_data, graph_id="network_security")
        
        # Run all detections
        from app.services.network_parser import detect_port_scan, detect_data_exfiltration
        port_scans = detect_port_scan(connections, threshold=5)
        exfil_events = detect_data_exfiltration(connections, byte_threshold=10_000_000)
        
        # Collect attack types
        attack_types = set()
        for log in logs:
            if 'attack_type' in log and log['attack_type']:
                attack_types.add(log['attack_type'])
        
        # Get unique counts
        unique_ips = len(set(c["source_ip"] for c in connections) | 
                        set(c["dest_ip"] for c in connections))
        unique_ports = len(set(c["dest_port"] for c in connections))
        
        result = {
            "graph_id": graph_id,
            "status": "success",
            "processing_summary": {
                "total_logs": len(logs),
                "valid_connections": len(connections),
                "unique_ips": unique_ips,
                "unique_ports": unique_ports,
                "nodes_created": len(graph_data["nodes"]),
                "edges_created": len(graph_data["edges"]),
            },
            "security_analysis": {
                "anomalies_detected": summary["anomalies_detected"],
                "anomaly_percentage": summary["anomaly_percentage"],
                "port_scans_detected": len(port_scans),
                "exfiltration_events": len(exfil_events),
                "attack_types": list(attack_types),
            },
            "top_threats": {
                "scanners": [s["scanner_ip"] for s in port_scans[:5]],
                "anomalous_ips": [ip["ip"] for ip in summary.get("top_suspicious_ips", [])[:5]],
            }
        }
        
        logger.info(f"Auto-processing complete. Graph ID: {graph_id}")
        return result
    
    def _connections_to_enhanced_graph(self, connections: List[Dict], logs: List[Dict]) -> Dict[str, Any]:
        """
        Convert connections to graph with enhanced attack information.
        """
        nodes = []
        edges = []
        seen_ips = set()
        seen_ports = set()
        seen_attacks = set()
        
        # Build attack type lookup from original logs
        ip_attacks = {}
        for log in logs:
            if 'attack_type' in log and log['attack_type']:
                src = log.get('source_ip')
                if src:
                    if src not in ip_attacks:
                        ip_attacks[src] = set()
                    ip_attacks[src].add(log['attack_type'])
        
        # Build IP -> anomaly data mapping
        ip_anomaly_data = {}
        for conn in connections:
            src = conn.get("source_ip")
            if src:
                if src not in ip_anomaly_data:
                    ip_anomaly_data[src] = {
                        "is_anomaly": False,
                        "anomaly_score": 0.0,
                        "anomaly_types": [],
                        "connection_count": 0
                    }
                ip_anomaly_data[src]["connection_count"] += 1
                if conn.get("is_anomaly", False):
                    ip_anomaly_data[src]["is_anomaly"] = True
                    ip_anomaly_data[src]["anomaly_score"] = max(
                        ip_anomaly_data[src]["anomaly_score"],
                        conn.get("anomaly_score", 0)
                    )
                    for atype in conn.get("anomaly_types", []):
                        if atype not in ip_anomaly_data[src]["anomaly_types"]:
                            ip_anomaly_data[src]["anomaly_types"].append(atype)
        
        # Create IP nodes with attack info AND anomaly data
        for conn in connections:
            for ip_field in ["source_ip", "dest_ip"]:
                ip = conn[ip_field]
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    from app.services.network_parser import is_internal_ip
                    is_internal = is_internal_ip(ip)
                    
                    ip_attack_types = list(ip_attacks.get(ip, []))
                    is_attacker = len(ip_attack_types) > 0
                    
                    # Get anomaly data for this IP
                    anomaly_info = ip_anomaly_data.get(ip, {
                        "is_anomaly": False,
                        "anomaly_score": 0.0,
                        "anomaly_types": [],
                        "connection_count": 0
                    })
                    
                    nodes.append({
                        "data": {
                            "id": f"ip_{ip.replace('.', '_')}",
                            "label": ip,
                            "type": "InternalIP" if is_internal else "ExternalIP",
                            "properties": {
                                "is_internal": is_internal,
                                "is_attacker": is_attacker,
                                "is_anomaly": anomaly_info["is_anomaly"],
                                "anomaly_score": anomaly_info["anomaly_score"],
                                "anomaly_types": anomaly_info["anomaly_types"],
                                "attack_types": ip_attack_types,
                                "connection_count": anomaly_info["connection_count"],
                            }
                        }
                    })
            
            # Create port nodes
            port = conn["dest_port"]
            port_key = f"port_{port}"
            if port_key not in seen_ports:
                seen_ports.add(port_key)
                from app.services.network_parser import get_service_name, is_suspicious_port
                nodes.append({
                    "data": {
                        "id": port_key,
                        "label": f"{get_service_name(port)} ({port})",
                        "type": "Port",
                        "properties": {
                            "port_number": port,
                            "service": get_service_name(port),
                            "is_suspicious": is_suspicious_port(port)
                        }
                    }
                })
        
        # Create Attack Type nodes
        all_attacks = set()
        for attacks in ip_attacks.values():
            all_attacks.update(attacks)
        
        for attack in all_attacks:
            attack_id = f"attack_{attack.replace(' ', '_').lower()}"
            if attack_id not in seen_attacks:
                seen_attacks.add(attack_id)
                nodes.append({
                    "data": {
                        "id": attack_id,
                        "label": attack,
                        "type": "AttackType",
                        "properties": {
                            "name": attack,
                            "is_threat": True
                        }
                    }
                })
        
        # Create edges
        for conn in connections:
            source_id = f"ip_{conn['source_ip'].replace('.', '_')}"
            dest_id = f"ip_{conn['dest_ip'].replace('.', '_')}"
            port_id = f"port_{conn['dest_port']}"
            
            # Connection edge
            edges.append({
                "data": {
                    "id": f"conn_{conn['id'][:8]}",
                    "source": source_id,
                    "target": dest_id,
                    "label": "CONNECTED_TO",
                    "properties": {
                        "protocol": conn["protocol"],
                        "port": conn["dest_port"],
                        "bytes": conn.get("bytes_sent", 0) + conn.get("bytes_received", 0),
                        "is_anomaly": conn.get("is_anomaly", False),
                    }
                }
            })
            
            # Port usage edge
            edges.append({
                "data": {
                    "id": f"uses_{conn['id'][:8]}",
                    "source": dest_id,
                    "target": port_id,
                    "label": "USES_PORT",
                }
            })
        
        # Attack edges - link IPs to their attack types
        edge_count = 0
        for ip, attacks in ip_attacks.items():
            source_id = f"ip_{ip.replace('.', '_')}"
            for attack in attacks:
                attack_id = f"attack_{attack.replace(' ', '_').lower()}"
                edges.append({
                    "data": {
                        "id": f"attack_edge_{edge_count}",
                        "source": source_id,
                        "target": attack_id,
                        "label": "INVOLVED_IN",
                    }
                })
                edge_count += 1
        
        return {"nodes": nodes, "edges": edges}


def scan_and_process_csv_files(sample_data_dir: str, neo4j_service: Neo4jService) -> List[Dict]:
    """
    Scan directory for unprocessed CSV files and process them.
    
    Args:
        sample_data_dir: Directory to scan
        neo4j_service: Neo4j service instance
        
    Returns:
        List of processing results
    """
    results = []
    processor = AutoProcessor(neo4j_service)
    
    # Track which files we've processed
    processed_marker = os.path.join(sample_data_dir, ".processed_files")
    processed_files = set()
    
    if os.path.exists(processed_marker):
        with open(processed_marker, 'r') as f:
            processed_files = set(f.read().strip().split('\n'))
    
    # Find CSV files
    csv_files = []
    for f in os.listdir(sample_data_dir):
        if f.endswith('.csv') and not f.startswith('.'):
            csv_files.append(f)
    
    new_files = [f for f in csv_files if f not in processed_files]
    
    if new_files:
        logger.info(f"Found {len(new_files)} new CSV files to process")
        
        for csv_file in new_files:
            try:
                csv_path = os.path.join(sample_data_dir, csv_file)
                logger.info(f"Auto-processing: {csv_file}")
                
                result = processor.process_csv(csv_path, max_rows=2000)
                result["filename"] = csv_file
                results.append(result)
                
                # Mark as processed
                processed_files.add(csv_file)
                
            except Exception as e:
                logger.error(f"Error processing {csv_file}: {e}")
                results.append({
                    "filename": csv_file,
                    "status": "error",
                    "error": str(e)
                })
        
        # Update processed marker
        with open(processed_marker, 'w') as f:
            f.write('\n'.join(processed_files))
    else:
        logger.info("No new CSV files to process")
    
    return results
