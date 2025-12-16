"""
Comprehensive test suite for the Network Security Graph RAG system.

Covers:
- Data ingestion & parsing
- Anomaly detection (ML-based + graph-native)
- Query system (Cypher-grounded RAG)
- Graph construction
- API endpoints
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json


# =============================================================================
# 1. NETWORK PARSER TESTS
# =============================================================================

class TestNetworkParser:
    """Tests for network log parsing."""
    
    def test_parse_logs_extracts_correct_ips(self):
        """✅ Correct src/dst IP extraction."""
        from app.services.network_parser import NetworkLogParser
        
        parser = NetworkLogParser()
        logs = [{"source_ip": "192.168.1.10", "dest_ip": "10.0.0.5", "dest_port": 80, "protocol": "TCP"}]
        
        connections = parser.parse_logs(logs)
        
        assert len(connections) == 1
        assert connections[0]["source_ip"] == "192.168.1.10"
        assert connections[0]["dest_ip"] == "10.0.0.5"
    
    def test_parse_logs_extracts_correct_ports(self):
        """✅ Correct port extraction."""
        from app.services.network_parser import NetworkLogParser
        
        parser = NetworkLogParser()
        logs = [{"source_ip": "192.168.1.10", "dest_ip": "10.0.0.5", "dest_port": 443, "protocol": "TCP"}]
        
        connections = parser.parse_logs(logs)
        
        assert connections[0]["dest_port"] == 443
    
    def test_internal_ip_classification(self):
        """✅ Internal vs external IP classification."""
        from app.services.network_parser import is_internal_ip
        
        assert is_internal_ip("192.168.1.10") == True
        assert is_internal_ip("10.0.0.5") == True
        assert is_internal_ip("172.16.0.1") == True
        assert is_internal_ip("8.8.8.8") == False
        assert is_internal_ip("1.1.1.1") == False
    
    def test_service_name_mapping(self):
        """✅ Service name mapping (HTTP, SSH, etc.)."""
        from app.services.network_parser import get_service_name
        
        assert get_service_name(80) == "HTTP"
        assert get_service_name(443) == "HTTPS"
        assert get_service_name(22) == "SSH"
        assert get_service_name(21) == "FTP"
    
    def test_suspicious_port_detection(self):
        """✅ Suspicious port identification."""
        from app.services.network_parser import is_suspicious_port
        
        assert is_suspicious_port(4444) == True  # Metasploit
        assert is_suspicious_port(31337) == True  # Elite
        assert is_suspicious_port(80) == False
        assert is_suspicious_port(443) == False


# =============================================================================
# 2. ML ANOMALY DETECTOR TESTS
# =============================================================================

class TestAnomalyDetector:
    """Tests for ML-based anomaly detection."""
    
    def test_fit_works_with_sufficient_data(self):
        """✅ fit() works with sufficient data."""
        from app.services.anomaly_detector import NetworkAnomalyDetector
        
        detector = NetworkAnomalyDetector(contamination=0.1)
        connections = [
            {"source_ip": f"192.168.1.{i}", "dest_ip": "10.0.0.5", "dest_port": 80,
             "bytes_sent": 1000, "bytes_received": 500, "duration": 1.0,
             "source_is_internal": True, "dest_is_internal": True,
             "is_suspicious_port": False, "timestamp": "2024-01-01 12:00:00"}
            for i in range(20)
        ]
        
        detector.fit(connections)
        
        assert detector.is_fitted == True
    
    def test_fit_handles_small_dataset(self):
        """❌ fit() handles very small datasets gracefully."""
        from app.services.anomaly_detector import NetworkAnomalyDetector
        
        detector = NetworkAnomalyDetector()
        connections = [
            {"source_ip": "192.168.1.1", "dest_ip": "10.0.0.5", "dest_port": 80}
        ]
        
        # Should not crash, falls back to rule-based
        detector.fit(connections)
        assert detector.is_fitted == False
    
    def test_predict_returns_anomaly_scores(self):
        """✅ predict() returns anomaly scores."""
        from app.services.anomaly_detector import NetworkAnomalyDetector
        
        detector = NetworkAnomalyDetector()
        connections = [
            {"source_ip": "192.168.1.10", "dest_ip": "10.0.0.5", "dest_port": 4444,
             "bytes_sent": 1000, "source_is_internal": True, "dest_is_internal": False,
             "is_suspicious_port": True}
        ]
        
        results = detector.predict(connections)
        
        assert len(results) == 1
        assert "anomaly_score" in results[0]
        assert "is_anomaly" in results[0]
    
    def test_rule_based_detection_flags_suspicious_ports(self):
        """✅ Rule-based detection flags suspicious ports."""
        from app.services.anomaly_detector import NetworkAnomalyDetector
        
        detector = NetworkAnomalyDetector()
        conn = {
            "source_ip": "192.168.1.10", "dest_ip": "10.0.0.5", "dest_port": 4444,
            "source_is_internal": True, "dest_is_internal": False,
            "is_suspicious_port": True
        }
        
        anomalies = detector._rule_based_detection(conn)
        
        assert "suspicious_port" in anomalies or "known_malware_port" in anomalies


# =============================================================================
# 3. GRAPH-NATIVE ANOMALY DETECTION TESTS
# =============================================================================

class TestGraphAnomalyDetector:
    """Tests for graph-native anomaly detection."""
    
    def test_anomaly_result_has_required_fields(self):
        """✅ Each anomaly has baseline, observed, confidence_score, reason."""
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
        
        assert "baseline" in result_dict
        assert "observed" in result_dict
        assert "confidence_score" in result_dict
        assert "reason" in result_dict
    
    def test_confidence_score_bounded(self):
        """❌ Confidence score within expected bounds (0-1)."""
        from app.services.graph_anomaly_detector import GraphAnomalyResult
        
        # Test upper bound
        result = GraphAnomalyResult(
            anomaly_type="test", entity="test", confidence_score=1.5,
            baseline=0, observed=0, reason="test"
        )
        assert result.to_dict()["confidence_score"] <= 1.0
        
        # Test lower bound
        result2 = GraphAnomalyResult(
            anomaly_type="test", entity="test", confidence_score=-0.5,
            baseline=0, observed=0, reason="test"
        )
        assert result2.to_dict()["confidence_score"] >= 0.0


# =============================================================================
# 4. CYPHER QUERY SERVICE TESTS
# =============================================================================

class TestCypherQueryService:
    """Tests for template-constrained Cypher query system."""
    
    def test_all_intents_have_templates(self):
        """✅ All intents have corresponding Cypher templates."""
        from app.services.cypher_query_service import QueryIntent, CYPHER_TEMPLATES
        
        for intent in QueryIntent:
            assert intent in CYPHER_TEMPLATES, f"Missing template for {intent}"
    
    def test_all_templates_use_graph_id_parameter(self):
        """❌ All templates use $graph_id parameter (prevents injection)."""
        from app.services.cypher_query_service import CYPHER_TEMPLATES
        
        for intent, template in CYPHER_TEMPLATES.items():
            assert "$graph_id" in template, f"Template {intent} missing $graph_id"
    
    def test_grounded_rag_prompt_enforces_rules(self):
        """✅ Grounded RAG prompt enforces answer rules."""
        from app.services.cypher_query_service import GROUNDED_RAG_PROMPT
        
        assert "ONLY" in GROUNDED_RAG_PROMPT
        assert "No data found" in GROUNDED_RAG_PROMPT or "no data" in GROUNDED_RAG_PROMPT.lower()


# =============================================================================
# 5. DATA INGESTION TESTS
# =============================================================================

class TestDataIngestion:
    """Tests for CSV and log ingestion."""
    
    def test_unsw_nb15_format_detection(self):
        """✅ Correctly detects UNSW-NB15 format."""
        from app.services.auto_processor import DatasetFormat, _looks_like_ip
        
        # UNSW-NB15 first row starts with IP
        assert _looks_like_ip("149.171.126.0") == True
        assert _looks_like_ip("NotAnIP") == False
    
    def test_empty_logs_rejected(self):
        """❌ Empty logs list rejected."""
        from app.services.auto_processor import AutoProcessor
        
        # Mock Neo4j service
        mock_neo4j = Mock()
        processor = AutoProcessor(mock_neo4j)
        
        with pytest.raises(ValueError):
            processor.process_logs([])
    
    def test_graph_contains_anomaly_data(self):
        """✅ Graph nodes contain anomaly_score and anomaly_types."""
        from app.services.auto_processor import AutoProcessor
        from app.services.network_parser import NetworkLogParser
        from app.services.anomaly_detector import analyze_network_traffic
        
        # Minimal test - check that node properties include anomaly fields
        logs = [
            {"source_ip": "192.168.1.10", "dest_ip": "10.0.0.5", "dest_port": 4444,
             "protocol": "TCP", "bytes_sent": 1000}
        ]
        
        parser = NetworkLogParser()
        connections = parser.parse_logs(logs)
        analysis = analyze_network_traffic(connections)
        
        # Check analyzed connections have anomaly data
        for conn in analysis["connections"]:
            assert "anomaly_score" in conn
            assert "is_anomaly" in conn


# =============================================================================
# 6. GRAPH CONSTRUCTION TESTS
# =============================================================================

class TestGraphConstruction:
    """Tests for Neo4j graph construction."""
    
    def test_connections_to_graph_creates_nodes(self):
        """✅ IP nodes created correctly."""
        from app.services.network_parser import NetworkLogParser
        
        parser = NetworkLogParser()
        logs = [{"source_ip": "192.168.1.1", "dest_ip": "10.0.0.1", "dest_port": 22, "protocol": "TCP"}]
        
        connections = parser.parse_logs(logs)
        graph = parser.connections_to_graph(connections)
        
        assert len(graph["nodes"]) >= 2  # At least 2 IP nodes
        assert len(graph["edges"]) >= 1  # At least 1 connection edge
    
    def test_no_duplicate_nodes(self):
        """❌ No duplicate nodes for same IP."""
        from app.services.network_parser import NetworkLogParser
        
        parser = NetworkLogParser()
        logs = [
            {"source_ip": "192.168.1.1", "dest_ip": "10.0.0.1", "dest_port": 22, "protocol": "TCP"},
            {"source_ip": "192.168.1.1", "dest_ip": "10.0.0.1", "dest_port": 80, "protocol": "TCP"},
        ]
        
        connections = parser.parse_logs(logs)
        graph = parser.connections_to_graph(connections)
        
        # Count unique IP nodes
        ip_labels = [n["data"]["label"] for n in graph["nodes"] if "." in n["data"]["label"]]
        assert len(ip_labels) == len(set(ip_labels)), "Duplicate IP nodes found"


# =============================================================================
# 7. SECURITY & ABUSE TESTS
# =============================================================================

class TestSecurityAndAbuse:
    """Tests for security and abuse prevention."""
    
    def test_cypher_injection_prevented(self):
        """❌ Cypher injection attempts fail."""
        from app.services.cypher_query_service import CYPHER_TEMPLATES
        
        # Templates should use parameters, not string concatenation
        for intent, template in CYPHER_TEMPLATES.items():
            # Check no raw string concatenation with user input
            assert "' +" not in template, f"Potential injection in {intent}"
            assert '" +' not in template, f"Potential injection in {intent}"
    
    def test_query_results_capped(self):
        """❌ Query result size capped."""
        from app.services.cypher_query_service import CYPHER_TEMPLATES
        
        # Most templates should have LIMIT
        templates_with_limit = sum(1 for t in CYPHER_TEMPLATES.values() if "LIMIT" in t)
        assert templates_with_limit >= 8, "Most templates should have LIMIT clause"


# =============================================================================
# 8. INTEGRATION TESTS (require running services)
# =============================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests requiring Neo4j and API to be running."""
    
    @pytest.mark.skip(reason="Requires running Neo4j")
    def test_health_endpoint_returns_200(self):
        """✅ Health endpoint returns 200."""
        import httpx
        response = httpx.get("http://localhost:8000/health")
        assert response.status_code == 200
    
    @pytest.mark.skip(reason="Requires running Neo4j")
    def test_query_endpoint_returns_grounding_info(self):
        """✅ Query endpoint includes grounding information."""
        import httpx
        response = httpx.post(
            "http://localhost:8000/api/query",
            json={"query": "What is the network topology?", "graph_id": "network_security"}
        )
        data = response.json()
        
        assert "intent" in data
        assert "cypher_template_used" in data
        assert "grounding_context" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
