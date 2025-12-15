"""
Network log parser and processor for the Network Security Graph RAG system.
Handles parsing of network logs and conversion to graph format.
"""

import logging
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
import ipaddress
import re

logger = logging.getLogger(__name__)

# Common internal IP ranges
INTERNAL_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Well-known ports and their services
WELL_KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Suspicious ports that might indicate malicious activity
SUSPICIOUS_PORTS = [4444, 5555, 6666, 7777, 31337, 12345, 54321, 1234]


def is_internal_ip(ip: str) -> bool:
    """Check if an IP address is internal/private."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in network for network in INTERNAL_IP_RANGES)
    except ValueError:
        return False


def get_service_name(port: int) -> str:
    """Get the service name for a port number."""
    return WELL_KNOWN_PORTS.get(port, f"Port-{port}")


def is_suspicious_port(port: int) -> bool:
    """Check if a port is known to be suspicious."""
    return port in SUSPICIOUS_PORTS or (port > 49152 and port not in [49152, 49153])


class NetworkLogParser:
    """Parser for network logs in various formats."""
    
    def __init__(self):
        self.connections = []
        self.ip_stats = {}
        self.port_stats = {}
    
    def parse_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse a list of network log entries into structured connections.
        
        Args:
            logs: List of log entry dictionaries
            
        Returns:
            List of parsed connection dictionaries
        """
        connections = []
        
        for log in logs:
            try:
                connection = self._parse_single_log(log)
                if connection:
                    connections.append(connection)
                    self._update_stats(connection)
            except Exception as e:
                logger.warning(f"Failed to parse log entry: {e}")
                continue
        
        logger.info(f"Parsed {len(connections)} connections from {len(logs)} log entries")
        return connections
    
    def _parse_single_log(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single log entry."""
        source_ip = log.get("source_ip")
        dest_ip = log.get("dest_ip")
        dest_port = log.get("dest_port")
        
        if not all([source_ip, dest_ip, dest_port]):
            return None
        
        return {
            "id": str(uuid.uuid4()),
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "source_port": log.get("source_port"),
            "dest_port": int(dest_port),
            "protocol": log.get("protocol", "TCP").upper(),
            "timestamp": log.get("timestamp"),
            "bytes_sent": log.get("bytes_sent", 0) or 0,
            "bytes_received": log.get("bytes_received", 0) or 0,
            "duration": log.get("duration", 0) or 0,
            "action": log.get("action", "allow"),
            "user": log.get("user"),
            "source_is_internal": is_internal_ip(source_ip),
            "dest_is_internal": is_internal_ip(dest_ip),
            "service": get_service_name(int(dest_port)),
            "is_suspicious_port": is_suspicious_port(int(dest_port)),
        }
    
    def _update_stats(self, connection: Dict[str, Any]):
        """Update IP and port statistics."""
        source_ip = connection["source_ip"]
        dest_ip = connection["dest_ip"]
        dest_port = connection["dest_port"]
        
        # Update source IP stats
        if source_ip not in self.ip_stats:
            self.ip_stats[source_ip] = {
                "outgoing": 0, "incoming": 0, "unique_dest_ips": set(),
                "unique_dest_ports": set(), "bytes_sent": 0
            }
        self.ip_stats[source_ip]["outgoing"] += 1
        self.ip_stats[source_ip]["unique_dest_ips"].add(dest_ip)
        self.ip_stats[source_ip]["unique_dest_ports"].add(dest_port)
        self.ip_stats[source_ip]["bytes_sent"] += connection.get("bytes_sent", 0)
        
        # Update dest IP stats
        if dest_ip not in self.ip_stats:
            self.ip_stats[dest_ip] = {
                "outgoing": 0, "incoming": 0, "unique_dest_ips": set(),
                "unique_dest_ports": set(), "bytes_sent": 0
            }
        self.ip_stats[dest_ip]["incoming"] += 1
        
        # Update port stats
        if dest_port not in self.port_stats:
            self.port_stats[dest_port] = {"count": 0, "unique_sources": set()}
        self.port_stats[dest_port]["count"] += 1
        self.port_stats[dest_port]["unique_sources"].add(source_ip)
    
    def get_ip_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for each IP address."""
        stats = {}
        for ip, data in self.ip_stats.items():
            stats[ip] = {
                "outgoing_connections": data["outgoing"],
                "incoming_connections": data["incoming"],
                "unique_destinations": len(data["unique_dest_ips"]),
                "unique_ports_accessed": len(data["unique_dest_ports"]),
                "total_bytes_sent": data["bytes_sent"],
                "is_internal": is_internal_ip(ip),
            }
        return stats
    
    def connections_to_graph(self, connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Convert parsed connections into a knowledge graph format.
        
        Args:
            connections: List of parsed connection dictionaries
            
        Returns:
            Graph dictionary with nodes and edges
        """
        nodes = []
        edges = []
        seen_ips = set()
        seen_ports = set()
        
        # Create IP nodes
        for conn in connections:
            for ip_field in ["source_ip", "dest_ip"]:
                ip = conn[ip_field]
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    is_internal = is_internal_ip(ip)
                    nodes.append({
                        "data": {
                            "id": f"ip_{ip.replace('.', '_')}",
                            "label": ip,
                            "type": "InternalIP" if is_internal else "ExternalIP",
                            "properties": {
                                "is_internal": is_internal,
                            }
                        }
                    })
            
            # Create port nodes for significant ports
            port = conn["dest_port"]
            port_key = f"port_{port}"
            if port_key not in seen_ports:
                seen_ports.add(port_key)
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
        
        # Create connection edges
        for conn in connections:
            source_id = f"ip_{conn['source_ip'].replace('.', '_')}"
            dest_id = f"ip_{conn['dest_ip'].replace('.', '_')}"
            port_id = f"port_{conn['dest_port']}"
            
            # Connection edge (IP to IP)
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
                        "timestamp": conn.get("timestamp"),
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
        
        return {
            "nodes": nodes,
            "edges": edges
        }


def detect_port_scan(connections: List[Dict[str, Any]], threshold: int = 10) -> List[Dict[str, Any]]:
    """
    Detect potential port scanning activity.
    
    Args:
        connections: List of parsed connections
        threshold: Minimum unique ports to consider a scan
        
    Returns:
        List of potential port scanning activities
    """
    # Group by source IP
    ip_ports = {}
    for conn in connections:
        source = conn["source_ip"]
        dest = conn["dest_ip"]
        port = conn["dest_port"]
        
        key = (source, dest)
        if key not in ip_ports:
            ip_ports[key] = set()
        ip_ports[key].add(port)
    
    # Find scanners
    scanners = []
    for (source, dest), ports in ip_ports.items():
        if len(ports) >= threshold:
            scanners.append({
                "scanner_ip": source,
                "target_ip": dest,
                "ports_scanned": len(ports),
                "ports": sorted(list(ports))[:20],  # First 20 ports
                "is_scan": True,
                "confidence": min(len(ports) / threshold, 1.0),
            })
    
    return scanners


def detect_data_exfiltration(connections: List[Dict[str, Any]], 
                             byte_threshold: int = 100_000_000) -> List[Dict[str, Any]]:
    """
    Detect potential data exfiltration (large outbound transfers).
    
    Args:
        connections: List of parsed connections
        byte_threshold: Threshold in bytes for suspicious transfer
        
    Returns:
        List of potential data exfiltration events
    """
    # Group by source IP to external destinations
    exfil_candidates = []
    
    ip_external_transfers = {}
    for conn in connections:
        if conn["source_is_internal"] and not conn["dest_is_internal"]:
            source = conn["source_ip"]
            if source not in ip_external_transfers:
                ip_external_transfers[source] = {"total_bytes": 0, "destinations": set(), "connections": 0}
            
            ip_external_transfers[source]["total_bytes"] += conn.get("bytes_sent", 0)
            ip_external_transfers[source]["destinations"].add(conn["dest_ip"])
            ip_external_transfers[source]["connections"] += 1
    
    for ip, data in ip_external_transfers.items():
        if data["total_bytes"] >= byte_threshold:
            exfil_candidates.append({
                "source_ip": ip,
                "total_bytes": data["total_bytes"],
                "unique_destinations": len(data["destinations"]),
                "connection_count": data["connections"],
                "is_suspicious": True,
            })
    
    return exfil_candidates
