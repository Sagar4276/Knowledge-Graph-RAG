"""
Anomaly detection module for the Network Security Graph RAG system.
Uses Isolation Forest and rule-based detection for network anomalies.
"""

import logging
from typing import List, Dict, Any, Tuple
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)

# Try to import sklearn, but provide fallback if not available
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available, using rule-based detection only")


class NetworkAnomalyDetector:
    """
    Detects anomalies in network traffic using ML and rule-based approaches.
    """
    
    def __init__(self, contamination: float = 0.1):
        """
        Initialize the anomaly detector.
        
        Args:
            contamination: Expected proportion of anomalies (0.0 to 0.5)
        """
        self.contamination = contamination
        self.model = None
        self.scaler = None
        self.is_fitted = False
        
        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100
            )
            self.scaler = StandardScaler()
    
    def extract_features(self, connections: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[str]]:
        """
        Extract features from network connections for anomaly detection.
        
        Args:
            connections: List of parsed connection dictionaries
            
        Returns:
            Tuple of (feature_matrix, feature_names)
        """
        features = []
        
        for conn in connections:
            feature_vector = [
                conn.get("dest_port", 0),
                1 if conn.get("source_is_internal", False) else 0,
                1 if conn.get("dest_is_internal", False) else 0,
                conn.get("bytes_sent", 0),
                conn.get("bytes_received", 0),
                conn.get("duration", 0),
                1 if conn.get("is_suspicious_port", False) else 0,
                self._port_rarity_score(conn.get("dest_port", 0)),
                self._time_score(conn.get("timestamp")),
            ]
            features.append(feature_vector)
        
        feature_names = [
            "dest_port",
            "source_is_internal",
            "dest_is_internal", 
            "bytes_sent",
            "bytes_received",
            "duration",
            "is_suspicious_port",
            "port_rarity",
            "time_score"
        ]
        
        return np.array(features), feature_names
    
    def _port_rarity_score(self, port: int) -> float:
        """Score how unusual a port is (higher = more unusual)."""
        common_ports = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3306, 5432, 8080}
        if port in common_ports:
            return 0.0
        elif port < 1024:
            return 0.3
        elif port < 49152:
            return 0.5
        else:
            return 0.8
    
    def _time_score(self, timestamp: str) -> float:
        """Score based on time of day (higher during unusual hours)."""
        if not timestamp:
            return 0.5
        
        try:
            # Try to parse various timestamp formats
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]:
                try:
                    dt = datetime.strptime(timestamp[:19], fmt)
                    hour = dt.hour
                    # Score higher for unusual hours (night time)
                    if 2 <= hour <= 5:
                        return 1.0
                    elif 23 <= hour or hour <= 1:
                        return 0.7
                    elif 6 <= hour <= 8 or 18 <= hour <= 22:
                        return 0.3
                    else:
                        return 0.1
                except ValueError:
                    continue
        except Exception:
            pass
        
        return 0.5
    
    def fit(self, connections: List[Dict[str, Any]]):
        """
        Fit the anomaly detection model on training data.
        
        Args:
            connections: List of connection dictionaries to train on
        """
        if not SKLEARN_AVAILABLE or len(connections) < 10:
            logger.info("Using rule-based detection (insufficient data or sklearn unavailable)")
            return
        
        features, _ = self.extract_features(connections)
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Fit isolation forest
        self.model.fit(features_scaled)
        self.is_fitted = True
        
        logger.info(f"Fitted anomaly detector on {len(connections)} connections")
    
    def predict(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Predict anomalies in connections.
        
        Args:
            connections: List of connection dictionaries to analyze
            
        Returns:
            List of connections with anomaly scores and flags
        """
        results = []
        
        if SKLEARN_AVAILABLE and self.is_fitted and len(connections) > 0:
            # Use ML-based detection
            features, _ = self.extract_features(connections)
            features_scaled = self.scaler.transform(features)
            
            # Get predictions (-1 = anomaly, 1 = normal)
            predictions = self.model.predict(features_scaled)
            scores = self.model.score_samples(features_scaled)
            
            for i, conn in enumerate(connections):
                conn_copy = conn.copy()
                conn_copy["ml_anomaly"] = predictions[i] == -1
                conn_copy["ml_score"] = float(-scores[i])  # Convert to positive (higher = more anomalous)
                
                # Also apply rule-based detection
                rule_anomalies = self._rule_based_detection(conn)
                conn_copy["rule_anomalies"] = rule_anomalies
                
                # Combine scores
                rule_score = len(rule_anomalies) * 0.2
                conn_copy["anomaly_score"] = min(conn_copy["ml_score"] + rule_score, 1.0)
                conn_copy["is_anomaly"] = conn_copy["ml_anomaly"] or len(rule_anomalies) > 0
                conn_copy["anomaly_types"] = rule_anomalies
                
                results.append(conn_copy)
        else:
            # Use rule-based detection only
            for conn in connections:
                conn_copy = conn.copy()
                rule_anomalies = self._rule_based_detection(conn)
                
                conn_copy["anomaly_score"] = min(len(rule_anomalies) * 0.25, 1.0)
                conn_copy["is_anomaly"] = len(rule_anomalies) > 0
                conn_copy["anomaly_types"] = rule_anomalies
                conn_copy["rule_anomalies"] = rule_anomalies
                
                results.append(conn_copy)
        
        return results
    
    def _rule_based_detection(self, conn: Dict[str, Any]) -> List[str]:
        """
        Apply rule-based anomaly detection.
        
        Args:
            conn: Single connection dictionary
            
        Returns:
            List of detected anomaly types
        """
        anomalies = []
        
        # Check for suspicious ports
        if conn.get("is_suspicious_port", False):
            anomalies.append("suspicious_port")
        
        # Check for unusual external connections
        if conn.get("source_is_internal", False) and not conn.get("dest_is_internal", False):
            # Internal to external
            if conn.get("dest_port", 0) in [4444, 5555, 6666, 31337]:
                anomalies.append("known_malware_port")
            
            # Large data transfer to external
            if conn.get("bytes_sent", 0) > 10_000_000:  # 10MB
                anomalies.append("large_external_transfer")
        
        # Check for unusual time
        if self._time_score(conn.get("timestamp")) > 0.7:
            anomalies.append("unusual_time")
        
        # Check for raw TCP/UDP on unusual ports
        if conn.get("protocol") in ["TCP", "UDP"]:
            port = conn.get("dest_port", 0)
            if port > 49152 and port not in [49152, 49153]:
                anomalies.append("high_ephemeral_port")
        
        return anomalies
    
    def get_summary(self, analyzed_connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of anomalies detected.
        
        Args:
            analyzed_connections: List of connections with anomaly scores
            
        Returns:
            Summary dictionary
        """
        total = len(analyzed_connections)
        anomalies = [c for c in analyzed_connections if c.get("is_anomaly", False)]
        anomaly_count = len(anomalies)
        
        # Group by anomaly type
        anomaly_types = {}
        for conn in anomalies:
            for atype in conn.get("anomaly_types", []):
                anomaly_types[atype] = anomaly_types.get(atype, 0) + 1
        
        # Top suspicious IPs
        ip_scores = {}
        for conn in analyzed_connections:
            source = conn.get("source_ip", "unknown")
            score = conn.get("anomaly_score", 0)
            if source not in ip_scores:
                ip_scores[source] = {"total_score": 0, "anomaly_count": 0}
            ip_scores[source]["total_score"] += score
            if conn.get("is_anomaly", False):
                ip_scores[source]["anomaly_count"] += 1
        
        top_ips = sorted(
            [{"ip": ip, **data} for ip, data in ip_scores.items()],
            key=lambda x: x["total_score"],
            reverse=True
        )[:10]
        
        return {
            "total_connections": total,
            "anomalies_detected": anomaly_count,
            "anomaly_percentage": (anomaly_count / total * 100) if total > 0 else 0,
            "anomaly_types": anomaly_types,
            "top_suspicious_ips": top_ips,
        }


def analyze_network_traffic(connections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Main function to analyze network traffic for anomalies.
    
    Args:
        connections: List of parsed connection dictionaries
        
    Returns:
        Analysis results with anomalies and summary
    """
    detector = NetworkAnomalyDetector(contamination=0.1)
    
    # Fit on the data (in production, you'd fit on historical "normal" data)
    detector.fit(connections)
    
    # Predict anomalies
    analyzed = detector.predict(connections)
    
    # Get summary
    summary = detector.get_summary(analyzed)
    
    return {
        "connections": analyzed,
        "summary": summary
    }
