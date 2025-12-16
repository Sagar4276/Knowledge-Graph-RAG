"""
Graph Merging Service for Network Security Graph RAG.

Merges text-derived semantic graphs with CSV-derived telemetry graphs,
enabling correlation between analyst findings and raw network data.

Key features:
- Entity deduplication based on label matching (IPs, ports, domains)
- Relationship consolidation
- Confidence score aggregation
- Source tracking (text_inference vs network_telemetry)
"""

import logging
from typing import Dict, Any, List, Optional
import uuid

logger = logging.getLogger(__name__)


class GraphMerger:
    """
    Merges graphs from different sources (text, CSV, API) into a unified graph.
    
    Deduplication strategy:
    - IPs: Match by exact label (e.g., "192.168.1.10")
    - Ports: Match by port number
    - Devices: Match by normalized name (lowercase, stripped)
    - Threats: Keep separate (different confidence levels)
    """
    
    def __init__(self, neo4j_service):
        self.neo4j_service = neo4j_service
    
    def merge_graphs(
        self, 
        semantic_graph_id: str, 
        telemetry_graph_id: str,
        merged_graph_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Merge a text-derived semantic graph with a CSV-derived telemetry graph.
        
        Args:
            semantic_graph_id: ID of the text-extracted graph
            telemetry_graph_id: ID of the network log graph
            merged_graph_id: Optional ID for the merged graph (auto-generated if not provided)
            
        Returns:
            Dict with merge statistics and the new graph ID
        """
        merged_graph_id = merged_graph_id or f"merged_{uuid.uuid4().hex[:8]}"
        
        # Get both graphs
        semantic_data = self.neo4j_service.get_graph(semantic_graph_id)
        telemetry_data = self.neo4j_service.get_graph(telemetry_graph_id)
        
        if not semantic_data or not telemetry_data:
            raise ValueError("One or both graphs not found")
        
        # Track merge statistics
        stats = {
            "semantic_nodes": len(semantic_data.get("nodes", [])),
            "telemetry_nodes": len(telemetry_data.get("nodes", [])),
            "merged_nodes": 0,
            "deduplicated": 0,
            "new_correlations": 0,
        }
        
        # Build entity index for deduplication
        # Key: normalized label, Value: node data
        entity_index = {}
        merged_nodes = []
        merged_edges = []
        old_to_new_ids = {}  # Map old IDs to merged IDs
        
        # Process semantic nodes first (they have confidence scores)
        for node in semantic_data.get("nodes", []):
            node_data = node.get("data", {})
            key = self._normalize_key(node_data)
            
            if key not in entity_index:
                new_id = str(uuid.uuid4())
                old_to_new_ids[node_data.get("id")] = new_id
                
                # Mark source
                props = node_data.get("properties", {})
                props["sources"] = ["semantic"]
                props["graph_origins"] = [semantic_graph_id]
                
                entity_index[key] = {
                    "id": new_id,
                    "label": node_data.get("label"),
                    "type": node_data.get("type"),
                    "properties": props
                }
            else:
                # Duplicate - map to existing
                old_to_new_ids[node_data.get("id")] = entity_index[key]["id"]
                stats["deduplicated"] += 1
        
        # Process telemetry nodes - merge with existing or add new
        for node in telemetry_data.get("nodes", []):
            node_data = node.get("data", {})
            key = self._normalize_key(node_data)
            
            if key in entity_index:
                # MERGE: Entity exists in both graphs!
                existing = entity_index[key]
                old_to_new_ids[node_data.get("id")] = existing["id"]
                
                # Update sources
                if "telemetry" not in existing["properties"].get("sources", []):
                    existing["properties"]["sources"].append("telemetry")
                if telemetry_graph_id not in existing["properties"].get("graph_origins", []):
                    existing["properties"]["graph_origins"].append(telemetry_graph_id)
                
                # Merge properties (telemetry can provide anomaly_score, etc.)
                telemetry_props = node_data.get("properties", {})
                for prop_key in ["anomaly_score", "is_anomaly", "anomaly_types", "connection_count"]:
                    if prop_key in telemetry_props:
                        existing["properties"][prop_key] = telemetry_props[prop_key]
                
                stats["new_correlations"] += 1
                stats["deduplicated"] += 1
            else:
                # New entity from telemetry
                new_id = str(uuid.uuid4())
                old_to_new_ids[node_data.get("id")] = new_id
                
                props = node_data.get("properties", {})
                props["sources"] = ["telemetry"]
                props["graph_origins"] = [telemetry_graph_id]
                
                entity_index[key] = {
                    "id": new_id,
                    "label": node_data.get("label"),
                    "type": node_data.get("type"),
                    "properties": props
                }
        
        # Convert entity index to node list
        for key, entity in entity_index.items():
            merged_nodes.append({
                "data": entity
            })
        
        stats["merged_nodes"] = len(merged_nodes)
        
        # Process edges from both graphs
        seen_edges = set()
        
        for graph_data in [semantic_data, telemetry_data]:
            for edge in graph_data.get("edges", []):
                edge_data = edge.get("data", {})
                
                old_source = edge_data.get("source")
                old_target = edge_data.get("target")
                
                new_source = old_to_new_ids.get(old_source)
                new_target = old_to_new_ids.get(old_target)
                
                if new_source and new_target:
                    # Deduplicate edges
                    edge_key = (new_source, new_target, edge_data.get("label"))
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        merged_edges.append({
                            "data": {
                                "id": f"e_{uuid.uuid4().hex[:8]}",
                                "source": new_source,
                                "target": new_target,
                                "label": edge_data.get("label"),
                                "properties": edge_data.get("properties", {})
                            }
                        })
        
        stats["merged_edges"] = len(merged_edges)
        
        # Create merged graph
        merged_graph = {
            "graph_id": merged_graph_id,
            "nodes": merged_nodes,
            "edges": merged_edges,
            "properties": {
                "graph_type": "merged",
                "source_graphs": [semantic_graph_id, telemetry_graph_id],
                "merge_stats": stats
            }
        }
        
        # Store the merged graph
        self.neo4j_service.store_graph(merged_graph)
        
        logger.info(f"Merged graphs: {stats}")
        
        return {
            "merged_graph_id": merged_graph_id,
            "statistics": stats,
            "correlations_found": stats["new_correlations"],
            "message": f"Successfully merged {stats['semantic_nodes']} semantic + {stats['telemetry_nodes']} telemetry nodes into {stats['merged_nodes']} unified nodes"
        }
    
    def _normalize_key(self, node_data: Dict[str, Any]) -> str:
        """
        Create a normalized key for entity deduplication.
        
        Different normalization strategies per entity type:
        - IPs: Exact match
        - Ports: Numeric normalization
        - Devices/Persons: Lowercase, stripped
        """
        label = node_data.get("label", "").strip()
        node_type = node_data.get("type", "")
        
        # IP addresses: exact match
        if node_type in ["InternalIP", "ExternalIP", "IPAddress"]:
            return f"ip:{label}"
        
        # Ports: extract numeric value
        if node_type == "Port":
            # Handle "Port 22" or "22" or "SSH (22)"
            import re
            port_match = re.search(r"\d+", label)
            if port_match:
                return f"port:{port_match.group()}"
            return f"port:{label.lower()}"
        
        # Protocols: normalize
        if node_type == "Protocol":
            return f"protocol:{label.upper()}"
        
        # Devices: normalize name
        if node_type == "Device":
            # "Workstation WS-23" and "WS-23" should match
            normalized = label.lower().replace("workstation", "").replace("server", "").strip()
            return f"device:{normalized}"
        
        # Default: type + lowercase label
        return f"{node_type.lower()}:{label.lower()}"
    
    def find_correlations(self, graph_id: str) -> List[Dict[str, Any]]:
        """
        Find entities that appear in multiple source graphs.
        These are valuable correlations between analyst findings and raw data.
        """
        query = """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
        WHERE size(n.sources) > 1
        RETURN 
          n.label AS entity,
          n.type AS entity_type,
          n.sources AS sources,
          n.graph_origins AS origin_graphs,
          n.confidence AS semantic_confidence,
          n.anomaly_score AS telemetry_score
        ORDER BY 
          CASE WHEN n.anomaly_score IS NOT NULL THEN n.anomaly_score ELSE 0 END DESC
        """
        
        results = self.neo4j_service.query_graph(
            graph_id=graph_id,
            cypher_query=query
        )
        
        return [
            {
                "entity": r.get("entity"),
                "type": r.get("entity_type"),
                "sources": r.get("sources"),
                "confidence": r.get("semantic_confidence"),
                "anomaly_score": r.get("telemetry_score"),
                "insight": self._generate_insight(r)
            }
            for r in results
        ]
    
    def _generate_insight(self, correlation: Dict[str, Any]) -> str:
        """Generate human-readable insight for a correlation."""
        entity = correlation.get("entity", "Unknown")
        sources = correlation.get("sources", [])
        
        if "semantic" in sources and "telemetry" in sources:
            anomaly_score = correlation.get("telemetry_score")
            if anomaly_score and anomaly_score > 0.7:
                return f"⚠️ {entity} mentioned in threat report AND flagged as anomaly (score: {anomaly_score:.2f})"
            else:
                return f"✓ {entity} cross-referenced between analyst findings and network data"
        
        return f"Entity {entity} found in: {', '.join(sources)}"


def merge_semantic_and_telemetry(
    neo4j_service,
    semantic_graph_id: str,
    telemetry_graph_id: str
) -> Dict[str, Any]:
    """
    Convenience function to merge graphs.
    
    Example:
        result = merge_semantic_and_telemetry(
            neo4j_service,
            semantic_graph_id="f1de16a6-06c9-4cb9-8e66-e1120cd0b4d1",  # From text processing
            telemetry_graph_id="network_security"  # From CSV upload
        )
    """
    merger = GraphMerger(neo4j_service)
    return merger.merge_graphs(semantic_graph_id, telemetry_graph_id)
