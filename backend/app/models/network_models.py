"""
Network-specific Pydantic models for the Network Security Graph RAG system.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class Protocol(str, Enum):
    """Network protocols"""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SSH = "SSH"
    FTP = "FTP"
    DNS = "DNS"
    SMTP = "SMTP"
    OTHER = "OTHER"


class AnomalyType(str, Enum):
    """Types of network anomalies"""
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    UNUSUAL_PORT = "unusual_port"
    UNUSUAL_TIME = "unusual_time"
    HIGH_VOLUME = "high_volume"
    SUSPICIOUS_IP = "suspicious_ip"
    UNKNOWN = "unknown"


class NetworkLogEntry(BaseModel):
    """Model for a single network log entry"""
    timestamp: Optional[str] = Field(None, description="Timestamp of the connection")
    source_ip: str = Field(..., description="Source IP address")
    dest_ip: str = Field(..., description="Destination IP address")
    source_port: Optional[int] = Field(None, description="Source port")
    dest_port: int = Field(..., description="Destination port")
    protocol: str = Field(default="TCP", description="Network protocol")
    bytes_sent: Optional[int] = Field(0, description="Bytes sent")
    bytes_received: Optional[int] = Field(0, description="Bytes received")
    duration: Optional[float] = Field(0, description="Connection duration in seconds")
    action: Optional[str] = Field("allow", description="Action taken (allow/deny)")
    user: Optional[str] = Field(None, description="User associated with connection")
    status: Optional[str] = Field(None, description="Connection status")


class NetworkLogsInput(BaseModel):
    """Input model for batch network log upload"""
    logs: List[NetworkLogEntry] = Field(..., description="List of network log entries")
    source: Optional[str] = Field(None, description="Source of the logs (e.g., firewall, router)")


class NetworkConnection(BaseModel):
    """Parsed network connection for graph storage"""
    id: str
    source_ip: str
    dest_ip: str
    dest_port: int
    protocol: str
    timestamp: Optional[str] = None
    bytes_transferred: int = 0
    is_internal: bool = False
    anomaly_score: float = 0.0
    anomaly_types: List[str] = []


class IPNode(BaseModel):
    """IP Address node for the graph"""
    ip: str
    is_internal: bool = False
    hostname: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    total_connections: int = 0
    total_bytes: int = 0
    anomaly_score: float = 0.0


class AnomalyReport(BaseModel):
    """Report of detected anomalies"""
    graph_id: str
    total_connections: int
    anomalies_detected: int
    anomaly_percentage: float
    anomaly_rate: Optional[float] = None  # Decimal rate (0.0-1.0)
    threshold: Optional[float] = None  # Isolation Forest threshold
    anomaly_distribution: Optional[Dict[str, int]] = None  # normal/suspicious/critical counts
    anomalies: List[Dict[str, Any]]
    top_anomalies: Optional[List[Dict[str, Any]]] = None  # Detailed top anomalies
    top_suspicious_ips: List[Dict[str, Any]]
    summary: str


class NetworkGraphResponse(BaseModel):
    """Response model for network graph creation"""
    graph_id: str
    total_connections: int
    unique_ips: int
    unique_ports: int
    anomalies_detected: int
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


class PortScanResult(BaseModel):
    """Result of port scan detection"""
    scanner_ip: str
    target_ips: List[str]
    ports_scanned: List[int]
    scan_duration: Optional[float] = None
    confidence: float
    is_scan: bool
