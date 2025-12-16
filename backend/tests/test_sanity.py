"""
Sanity tests for the Network Security Graph RAG system.

These tests verify basic functionality without requiring external services.
"""

import pytest
from unittest.mock import Mock, patch


class TestNetworkParser:
    """Test network log parsing."""
    
    def test_parse_logs_basic(self):
        """Test that parser handles basic log entries."""
        from app.services.network_parser import NetworkLogParser
        
        parser = NetworkLogParser()
        
        logs = [
            {
                "source_ip": "192.168.1.10",
                "dest_ip": "10.0.0.5",
                "dest_port": 80,
                "protocol": "TCP",
                "bytes_sent": 1000,
            },
            {
                "source_ip": "192.168.1.10",
                "dest_ip": "8.8.8.8",
                "dest_port": 443,
                "protocol": "TCP",
                "bytes_sent": 500,
            },
        ]
        
        connections = parser.parse_logs(logs)
        
        assert len(connections) == 2
        assert connections[0]["source_ip"] == "192.168.1.10"
        assert connections[1]["dest_port"] == 443
    
    def test_connections_to_graph_node_count(self):
        """Test that graph has expected node structure."""
        from app.services.network_parser import NetworkLogParser
        
        parser = NetworkLogParser()
        
        logs = [
            {
                "source_ip": "192.168.1.1",
                "dest_ip": "10.0.0.1",
                "dest_port": 22,
                "protocol": "TCP",
            }
        ]
        
        connections = parser.parse_logs(logs)
        graph = parser.connections_to_graph(connections)
        
        # Should have: 2 IPs + 1 port + 1 protocol = 4 nodes minimum
        assert len(graph["nodes"]) >= 3
        assert len(graph["edges"]) >= 1


class TestAnomalyDetector:
    """Test anomaly detection."""
    
    def test_rule_based_detection(self):
        """Test rule-based detection flags suspicious ports."""
        from app.services.anomaly_detector import NetworkAnomalyDetector
        
        detector = NetworkAnomalyDetector(contamination=0.1)
        
        # Suspicious port connection
        conn = {
            "source_ip": "192.168.1.10",
            "dest_ip": "10.0.0.5",
            "dest_port": 4444,  # Metasploit default
            "source_is_internal": True,
            "dest_is_internal": False,
            "is_suspicious_port": True,
        }
        
        anomalies = detector._rule_based_detection(conn)
        
        assert "suspicious_port" in anomalies or "known_malware_port" in anomalies


class TestCypherQueryService:
    """Test Cypher query construction."""
    
    def test_query_intent_enum(self):
        """Test that all intents have templates."""
        from app.services.cypher_query_service import QueryIntent, CYPHER_TEMPLATES
        
        for intent in QueryIntent:
            assert intent in CYPHER_TEMPLATES, f"Missing template for {intent}"
    
    def test_cypher_templates_have_graph_id(self):
        """Test that all templates use $graph_id parameter."""
        from app.services.cypher_query_service import CYPHER_TEMPLATES
        
        for intent, template in CYPHER_TEMPLATES.items():
            assert "$graph_id" in template, f"Template {intent} missing $graph_id"


class TestGraphAnomalyDetector:
    """Test graph-native anomaly detection."""
    
    def test_anomaly_result_format(self):
        """Test that anomaly results have required fields."""
        from app.services.graph_anomaly_detector import GraphAnomalyResult
        
        result = GraphAnomalyResult(
            anomaly_type="degree_spike",
            entity="192.168.1.10",
            confidence_score=0.85,
            baseline=10.5,
            observed=47,
            reason="IP has unusually high connections",
            severity="high"
        )
        
        result_dict = result.to_dict()
        
        # Required fields for explainability
        assert "anomaly_type" in result_dict
        assert "confidence_score" in result_dict
        assert "baseline" in result_dict
        assert "observed" in result_dict
        assert "reason" in result_dict
        
        # Confidence should be bounded
        assert 0 <= result_dict["confidence_score"] <= 1
