"""
Network security API endpoints for the Network Security Graph RAG system.
"""

from fastapi import APIRouter, HTTPException
from typing import List, Optional
import logging
import uuid
from datetime import datetime

from app.models.network_models import (
    NetworkLogsInput, NetworkLogEntry, NetworkGraphResponse, 
    AnomalyReport, PortScanResult
)
from app.services.network_parser import (
    NetworkLogParser, detect_port_scan, detect_data_exfiltration
)
from app.services.anomaly_detector import analyze_network_traffic
from app.services.neo4j_service import Neo4jService
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize Neo4j service
neo4j_service = Neo4jService(
    uri=settings.neo4j_uri,
    user=settings.neo4j_user,
    password=settings.neo4j_password
)


@router.post("/network/ingest", response_model=NetworkGraphResponse)
async def ingest_network_logs(input_data: NetworkLogsInput):
    """
    Ingest network logs and create a security knowledge graph.
    
    Parses network log entries, detects anomalies, and stores
    as a graph in Neo4j for querying.
    """
    try:
        logger.info(f"Ingesting {len(input_data.logs)} network log entries")
        
        # Parse logs
        parser = NetworkLogParser()
        logs_as_dicts = [log.model_dump() for log in input_data.logs]
        connections = parser.parse_logs(logs_as_dicts)
        
        if not connections:
            raise HTTPException(status_code=400, detail="No valid connections found in logs")
        
        # Analyze for anomalies
        analysis = analyze_network_traffic(connections)
        analyzed_connections = analysis["connections"]
        summary = analysis["summary"]
        
        # Convert to graph format
        graph_data = parser.connections_to_graph(analyzed_connections)
        
        # Add anomaly information to nodes
        for node in graph_data["nodes"]:
            if node["data"]["type"] in ["InternalIP", "ExternalIP"]:
                ip = node["data"]["label"]
                # Find anomaly score for this IP
                ip_anomalies = [c for c in analyzed_connections 
                               if c.get("source_ip") == ip and c.get("is_anomaly")]
                if ip_anomalies:
                    node["data"]["properties"]["anomaly_count"] = len(ip_anomalies)
                    node["data"]["properties"]["is_suspicious"] = True
        
        # Store in Neo4j
        graph_id = neo4j_service.store_graph(graph_data)
        
        # Get unique counts
        unique_ips = len(set(c["source_ip"] for c in connections) | 
                        set(c["dest_ip"] for c in connections))
        unique_ports = len(set(c["dest_port"] for c in connections))
        
        logger.info(f"Created network graph {graph_id} with {len(graph_data['nodes'])} nodes")
        
        return NetworkGraphResponse(
            graph_id=graph_id,
            total_connections=len(connections),
            unique_ips=unique_ips,
            unique_ports=unique_ports,
            anomalies_detected=summary["anomalies_detected"],
            nodes=graph_data["nodes"],
            edges=graph_data["edges"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error ingesting network logs: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing network logs: {str(e)}")


@router.get("/network/anomalies/{graph_id}", response_model=AnomalyReport)
async def get_anomalies(graph_id: str):
    """
    Get detected anomalies for a network graph.
    
    Returns a summary of all anomalies detected in the specified graph.
    Now includes: anomaly_score, anomaly_types, and connection_count.
    """
    try:
        # Query for IP nodes with anomaly data (not ports)
        cypher_query = """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
        WHERE n.is_anomaly = true OR n.anomaly_score > 0.5
        AND NOT n.type = 'Port'
        RETURN n.label AS ip, 
               n.type AS type,
               n.anomaly_score AS anomaly_score,
               n.anomaly_types AS anomaly_types,
               n.connection_count AS connection_count,
               n.is_anomaly AS is_anomaly
        ORDER BY n.anomaly_score DESC
        LIMIT 30
        """
        
        results = neo4j_service.query_graph(
            graph_id=graph_id,
            cypher_query=cypher_query
        )
        
        anomalies = []
        for r in results:
            # Format anomaly types with details
            types = r.get("anomaly_types", []) or []
            
            anomalies.append({
                "ip": r.get("ip"),
                "type": r.get("type"),
                "anomaly_score": r.get("anomaly_score", 0),
                "anomaly_types": types,
                "connection_count": r.get("connection_count", 0),
                "anomaly_count": len(types) if types else (1 if r.get("is_anomaly") else 0)
            })
        
        # Get total IP node count (exclude ports)
        count_query = """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
        WHERE n.type IN ['InternalIP', 'ExternalIP']
        RETURN count(n) AS total
        """
        count_result = neo4j_service.query_graph(graph_id=graph_id, cypher_query=count_query)
        total = count_result[0]["total"] if count_result else 0
        
        anomaly_count = len(anomalies)
        
        return AnomalyReport(
            graph_id=graph_id,
            total_connections=total,
            anomalies_detected=anomaly_count,
            anomaly_percentage=(anomaly_count / total * 100) if total > 0 else 0,
            anomalies=anomalies,
            top_suspicious_ips=anomalies[:10],
            summary=f"Detected {anomaly_count} anomalous IPs out of {total} total IPs. Top threat: {anomalies[0]['ip'] if anomalies else 'None'} (score: {anomalies[0]['anomaly_score']:.2f})" if anomalies else f"No anomalies detected in {total} IPs"
        )
        
    except Exception as e:
        logger.error(f"Error getting anomalies: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving anomalies: {str(e)}")


@router.get("/network/connections/{ip}")
async def get_ip_connections(ip: str, graph_id: Optional[str] = None):
    """
    Get all connections for a specific IP address.
    
    Returns incoming and outgoing connections for the specified IP.
    """
    try:
        ip_node_id = f"ip_{ip.replace('.', '_')}"
        
        # Query for connections
        cypher_query = """
        MATCH (n:Node {id: $node_id})
        OPTIONAL MATCH (n)-[r_out]->(target)
        OPTIONAL MATCH (source)-[r_in]->(n)
        RETURN n.label AS ip,
               collect(DISTINCT {type: type(r_out), target: target.label}) AS outgoing,
               collect(DISTINCT {type: type(r_in), source: source.label}) AS incoming
        """
        
        if graph_id:
            results = neo4j_service.query_graph(
                graph_id=graph_id,
                cypher_query=cypher_query,
                params={"node_id": ip_node_id}
            )
        else:
            # Search across all graphs
            results = neo4j_service.execute_query(cypher_query, {"node_id": ip_node_id})
        
        if not results:
            raise HTTPException(status_code=404, detail=f"IP {ip} not found in graph")
        
        result = results[0]
        return {
            "ip": ip,
            "outgoing_connections": [c for c in result.get("outgoing", []) if c.get("target")],
            "incoming_connections": [c for c in result.get("incoming", []) if c.get("source")],
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting connections for IP {ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving connections: {str(e)}")


@router.post("/network/detect-scan")
async def detect_port_scanning(input_data: NetworkLogsInput, threshold: int = 10):
    """
    Detect port scanning activity in network logs.
    
    Analyzes the provided logs for potential port scanning behavior.
    """
    try:
        # Parse logs
        parser = NetworkLogParser()
        logs_as_dicts = [log.model_dump() for log in input_data.logs]
        connections = parser.parse_logs(logs_as_dicts)
        
        # Detect port scans
        scanners = detect_port_scan(connections, threshold)
        
        results = []
        for scanner in scanners:
            results.append(PortScanResult(
                scanner_ip=scanner["scanner_ip"],
                target_ips=[scanner["target_ip"]],
                ports_scanned=scanner["ports"],
                confidence=scanner["confidence"],
                is_scan=scanner["is_scan"]
            ))
        
        return {
            "scans_detected": len(results),
            "scanners": results
        }
        
    except Exception as e:
        logger.error(f"Error detecting port scans: {e}")
        raise HTTPException(status_code=500, detail=f"Error detecting scans: {str(e)}")


@router.post("/network/detect-exfiltration")
async def detect_data_exfil(input_data: NetworkLogsInput, threshold_mb: int = 100):
    """
    Detect potential data exfiltration in network logs.
    
    Identifies large outbound data transfers to external destinations.
    """
    try:
        # Parse logs
        parser = NetworkLogParser()
        logs_as_dicts = [log.model_dump() for log in input_data.logs]
        connections = parser.parse_logs(logs_as_dicts)
        
        # Detect exfiltration
        threshold_bytes = threshold_mb * 1_000_000
        exfil_events = detect_data_exfiltration(connections, threshold_bytes)
        
        return {
            "potential_exfiltration_events": len(exfil_events),
            "events": exfil_events
        }
        
    except Exception as e:
        logger.error(f"Error detecting data exfiltration: {e}")
        raise HTTPException(status_code=500, detail=f"Error detecting exfiltration: {str(e)}")


@router.get("/network/stats/{graph_id}")
async def get_network_stats(graph_id: str):
    """
    Get network statistics for a graph.
    
    Returns summary statistics about the network traffic.
    """
    try:
        # Query for stats - handle null types gracefully
        stats_query = """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
        WITH n,
             CASE 
                 WHEN n.type = 'InternalIP' OR (n.is_internal = true AND n.label =~ '\\d+\\.\\d+\\.\\d+\\.\\d+') THEN 1 
                 ELSE 0 
             END AS is_internal,
             CASE 
                 WHEN n.type = 'ExternalIP' OR (n.is_internal = false AND n.label =~ '\\d+\\.\\d+\\.\\d+\\.\\d+') THEN 1 
                 ELSE 0 
             END AS is_external,
             CASE 
                 WHEN n.type = 'Port' OR n.label CONTAINS 'Port' THEN 1 
                 ELSE 0 
             END AS is_port
        RETURN 
            count(n) AS total_nodes,
            sum(is_internal) AS internal_ips,
            sum(is_external) AS external_ips,
            sum(is_port) AS unique_ports
        """
        
        results = neo4j_service.query_graph(graph_id=graph_id, cypher_query=stats_query)
        
        if not results:
            raise HTTPException(status_code=404, detail=f"Graph {graph_id} not found")
        
        stats = results[0]
        
        # Get edge count (actual connections)
        edge_query = """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)-[r:CONNECTED_TO]->(m:Node)
        RETURN count(r) AS total_edges
        """
        edge_result = neo4j_service.query_graph(graph_id=graph_id, cypher_query=edge_query)
        total_edges = edge_result[0]["total_edges"] if edge_result else 0
        
        # Get anomaly stats
        anomaly_query = """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
        WHERE n.is_anomaly = true
        RETURN count(n) AS anomaly_count, avg(n.anomaly_score) AS avg_score
        """
        anomaly_result = neo4j_service.query_graph(graph_id=graph_id, cypher_query=anomaly_query)
        anomaly_stats = anomaly_result[0] if anomaly_result else {}
        
        return {
            "graph_id": graph_id,
            "total_nodes": stats.get("total_nodes", 0),
            "internal_ips": stats.get("internal_ips", 0),
            "external_ips": stats.get("external_ips", 0),
            "unique_ports": stats.get("unique_ports", 0),
            "total_connections": total_edges,
            "anomaly_count": anomaly_stats.get("anomaly_count", 0),
            "avg_anomaly_score": round(anomaly_stats.get("avg_score", 0) or 0, 3),
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting network stats: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving stats: {str(e)}")


# ============================================
# AUTOMATED PIPELINE ENDPOINTS
# ============================================

from fastapi import UploadFile, File
import tempfile
import os
import shutil

from app.services.auto_processor import AutoProcessor, convert_csv_to_logs


@router.post("/network/upload-csv")
async def upload_and_process_csv(
    file: UploadFile = File(...),
    max_rows: int = 5000
):
    """
    Upload a CSV file and automatically process it through the entire pipeline.
    
    Auto-detects format (UNSW-NB15, CICIDS2017, etc.), converts to logs,
    ingests into graph, and runs all security analyses.
    
    Returns complete analysis results including graph_id for further queries.
    """
    try:
        if not file.filename.endswith('.csv'):
            raise HTTPException(status_code=400, detail="Only CSV files are supported")
        
        logger.info(f"Received CSV upload: {file.filename}")
        
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.csv') as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name
        
        try:
            # Process the uploaded CSV
            processor = AutoProcessor(neo4j_service)
            result = processor.process_csv(tmp_path, max_rows=max_rows)
            result["filename"] = file.filename
            
            return result
            
        finally:
            # Clean up temp file
            os.unlink(tmp_path)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing uploaded CSV: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing CSV: {str(e)}")


@router.post("/network/process-logs")
async def process_logs_auto(input_data: NetworkLogsInput, run_analysis: bool = True):
    """
    Process network logs through the automated pipeline.
    
    Similar to /network/ingest but includes full security analysis
    and enhanced graph with attack type nodes.
    """
    try:
        logger.info(f"Processing {len(input_data.logs)} logs through auto-pipeline")
        
        logs_as_dicts = [log.model_dump() for log in input_data.logs]
        
        processor = AutoProcessor(neo4j_service)
        result = processor.process_logs(logs_as_dicts)
        
        return result
        
    except Exception as e:
        logger.error(f"Error in auto-processing: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing logs: {str(e)}")


@router.get("/network/analyze/{graph_id}")
async def analyze_graph(graph_id: str):
    """
    Run all security analyses on an existing graph.
    
    Returns comprehensive analysis including:
    - Anomaly detection results (ML-based)
    - Graph-native anomaly detection (structural)
    - Port scan detection
    - Data exfiltration detection
    - Attack type summary
    
    Each anomaly includes full explainability:
    - baseline: what's normal for this graph
    - observed: what was actually seen
    - confidence_score: 0-1 confidence level
    - reason: human-readable explanation
    """
    try:
        # Import graph anomaly detector
        from app.services.graph_anomaly_detector import analyze_graph_anomalies
        
        # Get graph data
        graph = neo4j_service.get_graph(graph_id)
        if not graph:
            raise HTTPException(status_code=404, detail=f"Graph {graph_id} not found")
        
        # Run graph-native anomaly detection
        graph_anomalies = analyze_graph_anomalies(graph_id, neo4j_service)
        
        # Extract attack types from graph nodes
        attack_types = set()
        suspicious_ips = []
        attacker_ips = []
        
        for node in graph.get("nodes", []):
            data = node.get("data", {})
            props = data.get("properties", {})
            
            if data.get("type") == "AttackType":
                attack_types.add(data.get("label"))
            
            if props.get("is_attacker"):
                attacker_ips.append(data.get("label"))
            
            if props.get("is_anomaly") or props.get("is_suspicious"):
                suspicious_ips.append(data.get("label"))
        
        # Count nodes by type
        node_types = {}
        for node in graph.get("nodes", []):
            node_type = node.get("data", {}).get("type", "Unknown")
            node_types[node_type] = node_types.get(node_type, 0) + 1
        
        return {
            "graph_id": graph_id,
            "analysis": {
                "total_nodes": len(graph.get("nodes", [])),
                "total_edges": len(graph.get("edges", [])),
                "node_types": node_types,
                "attack_types_found": list(attack_types),
                "attacker_ips": attacker_ips[:20],
                "suspicious_ips": list(set(suspicious_ips))[:20],
            },
            "graph_anomalies": graph_anomalies,  # NEW: Graph-native anomalies with explainability
            "security_summary": {
                "has_attacks": len(attack_types) > 0,
                "attack_count": len(attack_types),
                "attacker_count": len(attacker_ips),
                "graph_anomaly_count": graph_anomalies.get("summary", {}).get("total_anomalies", 0),
                "risk_level": graph_anomalies.get("summary", {}).get("risk_level", "unknown"),
                "threat_level": "high" if len(attack_types) > 3 else "medium" if len(attack_types) > 0 else "low"
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing graph: {e}")
        raise HTTPException(status_code=500, detail=f"Error analyzing graph: {str(e)}")


@router.get("/network/summary/{graph_id}")
async def get_security_summary(graph_id: str):
    """
    Get a complete security summary for a graph.
    
    This endpoint provides all information needed for RAG queries,
    including attack types, suspicious entities, and network topology.
    """
    try:
        # Get the full analysis
        analysis = await analyze_graph(graph_id)
        
        # Get stats
        stats_response = await get_network_stats(graph_id)
        
        # Get anomaly report
        anomaly_response = await get_anomalies(graph_id)
        
        return {
            "graph_id": graph_id,
            "network_overview": {
                "total_nodes": stats_response.get("total_nodes", 0),
                "total_connections": stats_response.get("total_connections", 0),
                "internal_ips": stats_response.get("internal_ips", 0),
                "external_ips": stats_response.get("external_ips", 0),
                "unique_ports": stats_response.get("unique_ports", 0),
            },
            "security_findings": {
                "threat_level": analysis["security_summary"]["threat_level"],
                "attack_types": analysis["analysis"]["attack_types_found"],
                "attacker_ips": analysis["analysis"]["attacker_ips"],
                "anomalies_detected": anomaly_response.anomalies_detected,
                "anomaly_percentage": anomaly_response.anomaly_percentage,
            },
            "summary_text": _generate_summary_text(analysis, anomaly_response)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting security summary: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting summary: {str(e)}")


def _generate_summary_text(analysis: dict, anomaly_response) -> str:
    """Generate a human-readable security summary."""
    attack_types = analysis["analysis"]["attack_types_found"]
    attacker_count = len(analysis["analysis"]["attacker_ips"])
    threat_level = analysis["security_summary"]["threat_level"]
    
    summary_parts = []
    
    summary_parts.append(f"Network threat level: {threat_level.upper()}")
    
    if attack_types:
        summary_parts.append(f"Detected attack types: {', '.join(attack_types)}")
        summary_parts.append(f"Number of attacker IPs identified: {attacker_count}")
    else:
        summary_parts.append("No known attack patterns detected in this dataset.")
    
    if anomaly_response.anomalies_detected > 0:
        summary_parts.append(
            f"ML-based anomaly detection found {anomaly_response.anomalies_detected} "
            f"suspicious entities ({anomaly_response.anomaly_percentage:.1f}% of total)"
        )
    
    return " | ".join(summary_parts)


@router.get("/network/graphs")
async def list_network_graphs():
    """
    List all available network graphs.
    """
    try:
        graphs = neo4j_service.list_graphs()
        return {
            "graphs": graphs,
            "count": len(graphs)
        }
    except Exception as e:
        logger.error(f"Error listing graphs: {e}")
        raise HTTPException(status_code=500, detail=f"Error listing graphs: {str(e)}")


@router.post("/network/merge-graphs")
async def merge_graphs(
    semantic_graph_id: str,
    telemetry_graph_id: str,
    merged_graph_id: Optional[str] = None
):
    """
    Merge a text-derived semantic graph with a CSV-derived telemetry graph.
    
    This enables correlation between:
    - Analyst findings from threat reports (semantic)
    - Raw network traffic data (telemetry)
    
    The merger:
    - Deduplicates entities (IPs, ports) by label matching
    - Tracks source provenance (which graph each entity came from)
    - Identifies cross-references (entities in both graphs)
    - Aggregates confidence scores and anomaly data
    
    Example use case:
    1. Upload network CSV → graph ID "network_security"
    2. Process threat report text → graph ID "abc123"
    3. Merge them → find IPs mentioned in report that also appear anomalous in logs
    """
    try:
        from app.services.graph_merger import GraphMerger
        
        merger = GraphMerger(neo4j_service)
        result = merger.merge_graphs(
            semantic_graph_id=semantic_graph_id,
            telemetry_graph_id=telemetry_graph_id,
            merged_graph_id=merged_graph_id
        )
        
        return {
            "status": "success",
            "merged_graph_id": result["merged_graph_id"],
            "statistics": result["statistics"],
            "correlations_found": result["correlations_found"],
            "message": result["message"],
            "next_steps": [
                f"Query the merged graph: POST /api/query with graph_id='{result['merged_graph_id']}'",
                f"Find correlations: GET /api/network/correlations/{result['merged_graph_id']}"
            ]
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error merging graphs: {e}")
        raise HTTPException(status_code=500, detail=f"Error merging graphs: {str(e)}")


@router.get("/network/correlations/{graph_id}")
async def get_graph_correlations(graph_id: str):
    """
    Find entities that appear in multiple source graphs.
    
    These are valuable correlations between analyst findings and raw network data.
    For example: An IP mentioned in a threat report that also shows anomalous behavior.
    """
    try:
        from app.services.graph_merger import GraphMerger
        
        merger = GraphMerger(neo4j_service)
        correlations = merger.find_correlations(graph_id)
        
        return {
            "graph_id": graph_id,
            "correlations_found": len(correlations),
            "correlations": correlations,
            "summary": f"Found {len(correlations)} entities that appear in multiple data sources"
        }
        
    except Exception as e:
        logger.error(f"Error finding correlations: {e}")
        raise HTTPException(status_code=500, detail=f"Error finding correlations: {str(e)}")
