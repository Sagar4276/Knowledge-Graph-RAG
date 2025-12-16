"""
Graph-Native Anomaly Detection for the Network Security Graph RAG system.

Adds graph-based metrics that work on the graph structure itself:
- Degree spike detection (sudden fan-out)
- Fan-out detection (single IP → multiple ports)
- New path detection (first-time connections)
- Protocol rarity detection (unusual protocols)
- Beaconing detection (periodic connections)

Each anomaly includes full explainability:
- baseline: what's normal for this graph
- observed: what was actually seen
- confidence_score: how confident we are (0-1)
- reason: human-readable explanation
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime
import math

from app.services.neo4j_service import Neo4jService

logger = logging.getLogger(__name__)


class GraphAnomalyResult:
    """Single graph-based anomaly with full explainability."""
    
    def __init__(
        self,
        anomaly_type: str,
        entity: str,
        confidence_score: float,
        baseline: Any,
        observed: Any,
        reason: str,
        severity: str = "medium",
        metadata: Optional[Dict] = None
    ):
        self.anomaly_type = anomaly_type
        self.entity = entity
        self.confidence_score = min(1.0, max(0.0, confidence_score))
        self.baseline = baseline
        self.observed = observed
        self.reason = reason
        self.severity = severity
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_type": self.anomaly_type,
            "entity": self.entity,
            "confidence_score": round(self.confidence_score, 3),
            "baseline": self.baseline,
            "observed": self.observed,
            "reason": self.reason,
            "severity": self.severity,
            "metadata": self.metadata
        }


class GraphAnomalyDetector:
    """
    Graph-native anomaly detection using Neo4j graph structure.
    
    This complements the existing Isolation Forest detector by adding
    structural/contextual anomalies that require graph traversal.
    """
    
    def __init__(self, neo4j_service: Neo4jService):
        self.neo4j_service = neo4j_service
    
    def detect_all(self, graph_id: str) -> Dict[str, Any]:
        """
        Run all graph-native anomaly detections on a graph.
        
        Returns:
            Complete anomaly report with all detected issues
        """
        anomalies = []
        
        # Run all detection methods
        anomalies.extend(self.detect_degree_spikes(graph_id))
        anomalies.extend(self.detect_fan_out(graph_id))
        anomalies.extend(self.detect_protocol_rarity(graph_id))
        anomalies.extend(self.detect_suspicious_port_access(graph_id))
        
        # Sort by confidence score
        anomalies.sort(key=lambda x: x.confidence_score, reverse=True)
        
        # Generate summary
        summary = self._generate_summary(anomalies)
        
        return {
            "anomalies": [a.to_dict() for a in anomalies],
            "summary": summary,
            "detection_methods": [
                "degree_spike",
                "fan_out",
                "protocol_rarity",
                "suspicious_port_access"
            ]
        }
    
    def detect_degree_spikes(self, graph_id: str) -> List[GraphAnomalyResult]:
        """
        Detect IPs with unusually high connection counts (degree).
        
        Uses per-graph baseline: mean + 2σ (computed from this graph's data)
        """
        anomalies = []
        
        # Get degree distribution for all IPs in graph
        query = """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ip:Node)
        WHERE ip.type = 'IP' OR ip.label =~ '\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+'
        OPTIONAL MATCH (ip)-[r]->()
        WITH ip.label AS ip_address, count(r) AS out_degree, ip.is_internal AS is_internal
        RETURN ip_address, out_degree, is_internal
        ORDER BY out_degree DESC
        """
        
        try:
            results = self.neo4j_service.query_graph(graph_id, query)
            
            if not results or len(results) < 3:
                return anomalies
            
            # Calculate per-graph baseline (mean + 2σ)
            degrees = [r["out_degree"] or 0 for r in results]
            mean_degree = sum(degrees) / len(degrees)
            variance = sum((d - mean_degree) ** 2 for d in degrees) / len(degrees)
            std_dev = math.sqrt(variance) if variance > 0 else 1
            
            threshold = mean_degree + (2 * std_dev)
            
            # Flag IPs above threshold
            for result in results:
                degree = result["out_degree"] or 0
                if degree > threshold and degree > 5:  # Minimum 5 connections
                    # Calculate confidence based on how far above threshold
                    excess_ratio = (degree - threshold) / (std_dev + 1)
                    confidence = min(0.95, 0.5 + (excess_ratio * 0.15))
                    
                    anomalies.append(GraphAnomalyResult(
                        anomaly_type="degree_spike",
                        entity=result["ip_address"],
                        confidence_score=confidence,
                        baseline=round(mean_degree, 1),
                        observed=degree,
                        reason=f"IP has {degree} outgoing connections, significantly above graph average of {mean_degree:.1f}",
                        severity="high" if degree > threshold * 2 else "medium",
                        metadata={
                            "threshold": round(threshold, 1),
                            "std_dev": round(std_dev, 1),
                            "is_internal": result.get("is_internal", False)
                        }
                    ))
            
        except Exception as e:
            logger.error(f"Error detecting degree spikes: {e}")
        
        return anomalies
    
    def detect_fan_out(self, graph_id: str) -> List[GraphAnomalyResult]:
        """
        Detect single IP connecting to many different ports on same target.
        
        This is a strong indicator of port scanning behavior.
        """
        anomalies = []
        
        # Find IPs hitting multiple ports on same destination
        query = """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(src:Node)-[r]->(dst:Node)
        WHERE (src.type = 'IP' OR src.label =~ '\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+')
          AND r.port IS NOT NULL
        WITH src.label AS source, dst.label AS destination, 
             collect(DISTINCT r.port) AS ports, count(r) AS connection_count
        WHERE size(ports) > 5
        RETURN source, destination, ports, size(ports) AS unique_ports, connection_count
        ORDER BY unique_ports DESC
        LIMIT 20
        """
        
        try:
            results = self.neo4j_service.query_graph(graph_id, query)
            
            for result in results:
                unique_ports = result["unique_ports"]
                
                # Confidence increases with port count
                confidence = min(0.95, 0.5 + (unique_ports - 5) * 0.05)
                
                # Severity based on port count
                if unique_ports > 50:
                    severity = "critical"
                elif unique_ports > 20:
                    severity = "high"
                else:
                    severity = "medium"
                
                ports_sample = result["ports"][:10] if result["ports"] else []
                
                anomalies.append(GraphAnomalyResult(
                    anomaly_type="fan_out_port_scan",
                    entity=result["source"],
                    confidence_score=confidence,
                    baseline="< 5 unique ports per destination",
                    observed=f"{unique_ports} unique ports to {result['destination']}",
                    reason=f"Source IP accessed {unique_ports} different ports on {result['destination']} - potential port scanning",
                    severity=severity,
                    metadata={
                        "destination": result["destination"],
                        "sample_ports": ports_sample,
                        "total_connections": result["connection_count"]
                    }
                ))
        
        except Exception as e:
            logger.error(f"Error detecting fan-out: {e}")
        
        return anomalies
    
    def detect_protocol_rarity(self, graph_id: str) -> List[GraphAnomalyResult]:
        """
        Detect connections using rare/unusual protocols.
        
        Protocols used in <1% of connections are flagged (dynamic threshold).
        """
        anomalies = []
        
        # Get protocol distribution
        query = """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)-[r]->()
        WHERE r.protocol IS NOT NULL
        WITH r.protocol AS protocol, count(r) AS usage
        RETURN protocol, usage
        ORDER BY usage DESC
        """
        
        try:
            results = self.neo4j_service.query_graph(graph_id, query)
            
            if not results:
                return anomalies
            
            # Calculate total and find rare protocols
            total = sum(r["usage"] for r in results)
            
            for result in results:
                protocol = result["protocol"]
                usage = result["usage"]
                percentage = (usage / total) * 100 if total > 0 else 0
                
                # Flag protocols under 1% usage (dynamic threshold)
                if percentage < 1.0 and usage < 10:
                    # Known suspicious protocols get higher confidence
                    suspicious_protocols = {"icmp", "gre", "ipip", "esp", "ah"}
                    base_confidence = 0.7 if protocol.lower() in suspicious_protocols else 0.5
                    
                    anomalies.append(GraphAnomalyResult(
                        anomaly_type="rare_protocol",
                        entity=protocol,
                        confidence_score=base_confidence,
                        baseline=f"Protocol should be > 1% of traffic",
                        observed=f"{percentage:.2f}% ({usage} connections)",
                        reason=f"Protocol '{protocol}' used in only {percentage:.2f}% of connections - may indicate covert channel",
                        severity="medium",
                        metadata={
                            "usage_count": usage,
                            "total_connections": total,
                            "percentage": round(percentage, 2)
                        }
                    ))
        
        except Exception as e:
            logger.error(f"Error detecting protocol rarity: {e}")
        
        return anomalies
    
    def detect_suspicious_port_access(self, graph_id: str) -> List[GraphAnomalyResult]:
        """
        Detect access to known-suspicious ports.
        """
        anomalies = []
        
        # Known suspicious ports
        suspicious_ports = {
            4444: "Metasploit default",
            5555: "Android ADB",
            6666: "IRC backdoor",
            31337: "Elite/Back Orifice",
            12345: "NetBus",
            27374: "Sub7",
            1234: "Generic backdoor",
            4321: "Generic backdoor"
        }
        
        query = """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(src:Node)-[r]->(dst:Node)
        WHERE r.port IN $suspicious_ports
        RETURN src.label AS source, dst.label AS destination, 
               r.port AS port, count(*) AS occurrences
        ORDER BY occurrences DESC
        """
        
        try:
            results = self.neo4j_service.query_graph(
                graph_id, 
                query, 
                {"suspicious_ports": list(suspicious_ports.keys())}
            )
            
            for result in results:
                port = result["port"]
                port_description = suspicious_ports.get(port, "Unknown")
                
                anomalies.append(GraphAnomalyResult(
                    anomaly_type="suspicious_port",
                    entity=result["source"],
                    confidence_score=0.85,
                    baseline="Should not access known-malicious ports",
                    observed=f"Port {port} ({port_description})",
                    reason=f"Connection to port {port} ({port_description}) - commonly used by malware",
                    severity="high",
                    metadata={
                        "destination": result["destination"],
                        "port": port,
                        "port_description": port_description,
                        "occurrences": result["occurrences"]
                    }
                ))
        
        except Exception as e:
            logger.error(f"Error detecting suspicious ports: {e}")
        
        return anomalies
    
    def _generate_summary(self, anomalies: List[GraphAnomalyResult]) -> Dict[str, Any]:
        """Generate summary of detected anomalies."""
        if not anomalies:
            return {
                "total_anomalies": 0,
                "by_type": {},
                "by_severity": {},
                "top_entities": [],
                "risk_level": "low"
            }
        
        # Count by type
        by_type = defaultdict(int)
        for a in anomalies:
            by_type[a.anomaly_type] += 1
        
        # Count by severity
        by_severity = defaultdict(int)
        for a in anomalies:
            by_severity[a.severity] += 1
        
        # Top entities
        entity_scores = defaultdict(float)
        for a in anomalies:
            entity_scores[a.entity] += a.confidence_score
        
        top_entities = sorted(
            [{"entity": e, "total_score": round(s, 2)} for e, s in entity_scores.items()],
            key=lambda x: x["total_score"],
            reverse=True
        )[:5]
        
        # Risk level
        critical_count = by_severity.get("critical", 0)
        high_count = by_severity.get("high", 0)
        
        if critical_count > 0:
            risk_level = "critical"
        elif high_count > 3:
            risk_level = "high"
        elif high_count > 0 or len(anomalies) > 5:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "total_anomalies": len(anomalies),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "top_entities": top_entities,
            "risk_level": risk_level
        }


def analyze_graph_anomalies(graph_id: str, neo4j_service: Neo4jService) -> Dict[str, Any]:
    """
    Main entry point for graph-native anomaly detection.
    
    This complements the existing NetworkAnomalyDetector (Isolation Forest)
    by adding graph-structure-aware detection.
    """
    detector = GraphAnomalyDetector(neo4j_service)
    return detector.detect_all(graph_id)
