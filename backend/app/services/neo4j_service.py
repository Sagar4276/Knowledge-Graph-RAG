from typing import Dict, Any, List, Optional
from neo4j import GraphDatabase
import uuid
import logging
import time
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Neo4jService:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.setup_constraints()
        self.ensure_indexes()  # Add indexes for performance
        
        # Session cache for connection pooling
        self._session_cache = {}
    
    def close(self):
        """Close the Neo4j driver and any cached sessions."""
        for session in self._session_cache.values():
            try:
                session.close()
            except Exception as e:
                logger.warning(f"Error closing session: {e}")
        self.driver.close()
    
    def setup_constraints(self):
        """Set up constraints for the Neo4j database."""
        with self.driver.session() as session:
            try:
                session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Node) REQUIRE n.id IS UNIQUE")
            except Exception as e:
                logger.error(f"Could not create constraint: {e}")
    
    def ensure_indexes(self):
        """Create indexes to improve query performance."""
        start_time = time.time()
        try:
            with self.driver.session() as session:
                session.run("CREATE INDEX IF NOT EXISTS FOR (g:Graph) ON (g.id)")
                session.run("CREATE INDEX IF NOT EXISTS FOR (n:Node) ON (n.label)")
                try:
                    session.run("CREATE TEXT INDEX node_label_idx IF NOT EXISTS FOR (n:Node) ON (n.label)")
                except Exception as e:
                    logger.info("Text index not supported, using standard index")
                    logger.debug(f"Error creating text index: {e}")
                    
            logger.info(f"Neo4j indexes created in {time.time() - start_time:.2f}s")
        except Exception as e:
            logger.error(f"Error creating Neo4j indexes: {e}")
    
    def get_session(self):
        """Get a cached session for the current thread."""
        thread_id = threading.current_thread().ident
        if thread_id not in self._session_cache:
            self._session_cache[thread_id] = self.driver.session()
        return self._session_cache[thread_id]
    
    def store_graph(self, graph: Dict[str, Any], batch_size: int = 50) -> str:
        """
        Store a knowledge graph in Neo4j with batch processing for better performance.
        
        Args:
            graph: Dictionary containing nodes and edges.
            batch_size: Number of nodes/edges to process in each batch.
            
        Returns:
            graph_id: Unique identifier for the stored graph.
        """
        graph_id = str(uuid.uuid4())
        return self._store_graph_internal(graph, graph_id, batch_size, use_merge=False)
    
    def store_graph_merge(self, graph: Dict[str, Any], graph_id: str = None, batch_size: int = 50) -> str:
        """
        Store a knowledge graph using MERGE to allow combining multiple datasets.
        
        This method uses MERGE instead of CREATE, so:
        - Nodes with the same ID will be updated instead of causing errors
        - Multiple CSVs can contribute to the same unified graph
        - Properties are merged/updated
        
        Args:
            graph: Dictionary containing nodes and edges.
            graph_id: Optional graph ID. If provided, adds to existing graph.
            batch_size: Number of nodes/edges to process in each batch.
            
        Returns:
            graph_id: Unique identifier for the stored graph.
        """
        if graph_id is None:
            graph_id = "network_security"  # Default unified graph ID
        return self._store_graph_internal(graph, graph_id, batch_size, use_merge=True)
    
    def _store_graph_internal(self, graph: Dict[str, Any], graph_id: str, batch_size: int, use_merge: bool) -> str:
        """
        Internal method to store graph with either CREATE or MERGE using true batch processing.
        """
        start_time = time.time()
        
        with self.driver.session() as session:
            # Create or merge graph container
            if use_merge:
                session.run(
                    "MERGE (g:Graph {id: $graph_id}) ON CREATE SET g.created = datetime() ON MATCH SET g.updated = datetime()",
                    graph_id=graph_id
                )
            else:
                session.run(
                    "CREATE (g:Graph {id: $graph_id, created: datetime()})",
                    graph_id=graph_id
                )
            
            # Process nodes in batches using UNWIND for efficiency
            nodes_list = []
            for node in graph["nodes"]:
                node_data = node["data"]
                nodes_list.append({
                    "id": node_data["id"],
                    "label": node_data.get("label", ""),
                    "type": node_data.get("type", "Entity"),
                    "properties": node_data.get("properties", {})
                })
            
            # Batch insert nodes using UNWIND (much faster than individual inserts)
            for i in range(0, len(nodes_list), batch_size):
                batch = nodes_list[i:i + batch_size]
                
                if use_merge:
                    cypher = """
                    UNWIND $nodes AS node
                    MERGE (n:Node {id: node.id})
                    ON CREATE SET n.label = node.label, n.type = node.type
                    ON MATCH SET n.label = CASE WHEN n.label IS NULL OR n.label = '' THEN node.label ELSE n.label END
                    SET n += node.properties
                    WITH n
                    MATCH (g:Graph {id: $graph_id})
                    MERGE (g)-[:CONTAINS]->(n)
                    """
                else:
                    cypher = """
                    UNWIND $nodes AS node
                    CREATE (n:Node {id: node.id, label: node.label, type: node.type})
                    SET n += node.properties
                    WITH n
                    MATCH (g:Graph {id: $graph_id})
                    CREATE (g)-[:CONTAINS]->(n)
                    """
                
                session.run(cypher, nodes=batch, graph_id=graph_id)
            
            # Process edges in batches using UNWIND
            edges_list = []
            for edge in graph["edges"]:
                edge_data = edge["data"]
                edges_list.append({
                    "id": edge_data["id"],
                    "source": edge_data["source"],
                    "target": edge_data["target"],
                    "label": edge_data.get("label", "RELATED_TO"),
                    "properties": edge_data.get("properties", {})
                })
            
            for i in range(0, len(edges_list), batch_size):
                batch = edges_list[i:i + batch_size]
                
                if use_merge:
                    cypher = """
                    UNWIND $edges AS edge
                    MATCH (source:Node {id: edge.source})
                    MATCH (target:Node {id: edge.target})
                    MERGE (source)-[r:CONNECTED_TO]->(target)
                    SET r.id = edge.id, r += edge.properties
                    """
                else:
                    cypher = """
                    UNWIND $edges AS edge
                    MATCH (source:Node {id: edge.source})
                    MATCH (target:Node {id: edge.target})
                    CREATE (source)-[r:CONNECTED_TO {id: edge.id}]->(target)
                    """
                
                session.run(cypher, edges=batch)
        
        logger.info(f"Graph {graph_id} {'merged' if use_merge else 'created'} in {time.time() - start_time:.2f}s with {len(graph['nodes'])} nodes and {len(graph['edges'])} edges")
        return graph_id
    
    def get_graph(self, graph_id: str, node_limit: int = 1000, edge_limit: int = 2000) -> Optional[Dict[str, Any]]:
        """
        Retrieve a knowledge graph from Neo4j.
        
        Args:
            graph_id: ID of the graph to retrieve.
            node_limit: Maximum number of nodes to retrieve.
            edge_limit: Maximum number of edges to retrieve.
            
        Returns:
            graph: Dictionary containing nodes and edges, or None if not found.
        """
        start_time = time.time()
        with self.driver.session() as session:
            # Check if graph exists
            graph_exists = session.run(
                "MATCH (g:Graph {id: $graph_id}) RETURN count(g) as count",
                graph_id=graph_id
            ).single()["count"]
            
            if graph_exists == 0:
                return None
            
            # Get nodes with optimized query
            nodes_result = session.run(
                """
                MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
                RETURN n.id AS id, labels(n) as labels, properties(n) AS properties
                LIMIT $node_limit
                """,
                graph_id=graph_id,
                node_limit=node_limit
            )
            
            nodes = []
            for record in nodes_result:
                node_id = record["id"]
                labels = record["labels"]
                properties = record["properties"]
                
                if "id" in properties:
                    del properties["id"]
                
                node_type = next((label for label in labels if label != "Node"), "Entity")
                
                nodes.append({
                    "data": {
                        "id": node_id,
                        "label": properties.get("label", node_id),
                        "type": node_type,
                        "properties": properties
                    }
                })
            
            # Get edges with optimized query
            edges_result = session.run(
                """
                MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(source:Node)-[r]->(target:Node)
                RETURN source.id AS source_id, target.id AS target_id, type(r) AS type, r.id AS id
                LIMIT $edge_limit
                """,
                graph_id=graph_id,
                edge_limit=edge_limit
            )
            
            edges = []
            for record in edges_result:
                source_id = record["source_id"]
                target_id = record["target_id"]
                edge_type = record["type"]
                edge_id = record.get("id", f"e-{source_id}-{target_id}")
                
                edges.append({
                    "data": {
                        "id": edge_id,
                        "source": source_id,
                        "target": target_id,
                        "label": edge_type
                    }
                })
                
            logger.info(f"Retrieved graph {graph_id} in {time.time() - start_time:.2f}s")
            return {
                "nodes": nodes,
                "edges": edges
            }
    
    def list_graphs(self) -> List[str]:
        """
        List all available graph IDs.
        
        Returns:
            List of graph IDs.
        """
        with self.driver.session() as session:
            result = session.run("MATCH (g:Graph) RETURN g.id as id ORDER BY g.created DESC")
            return [record["id"] for record in result]
    
    def delete_graph(self, graph_id: str) -> bool:
        """
        Delete a graph and all its connected nodes.
        
        Args:
            graph_id: ID of the graph to delete.
            
        Returns:
            True if deleted successfully.
        """
        with self.driver.session() as session:
            # Delete all nodes connected to this graph, then the graph itself
            result = session.run("""
                MATCH (g:Graph {id: $graph_id})
                OPTIONAL MATCH (g)-[:CONTAINS]->(n:Node)
                DETACH DELETE n, g
                RETURN count(n) as deleted_nodes
            """, graph_id=graph_id)
            
            record = result.single()
            deleted = record["deleted_nodes"] if record else 0
            logger.info(f"Deleted graph {graph_id} with {deleted} nodes")
            return True
    
    def filter_graph(self, graph_id: str, node_types: List[str] = None, edge_types: List[str] = None, search_term: str = None) -> Optional[Dict[str, Any]]:
        """
        Filter a graph based on node types, edge types, and search term.
        
        Args:
            graph_id: ID of the graph to filter.
            node_types: List of node types to include.
            edge_types: List of edge types to include.
            search_term: Search term to filter node labels.
            
        Returns:
            Filtered graph.
        """
        graph = self.get_graph(graph_id)
        if not graph:
            return None
        
        filtered_nodes = graph["nodes"]
        
        # Filter by node type
        if node_types:
            filtered_nodes = [node for node in filtered_nodes if node["data"]["type"] in node_types]
        
        # Filter by search term
        if search_term:
            search_term = search_term.lower()
            filtered_nodes = [
                node for node in filtered_nodes 
                if search_term in node["data"]["label"].lower()
            ]
        
        # Get IDs of filtered nodes
        node_ids = [node["data"]["id"] for node in filtered_nodes]
        
        # Filter edges
        filtered_edges = [
            edge for edge in graph["edges"]
            if (edge["data"]["source"] in node_ids and edge["data"]["target"] in node_ids) and
               (not edge_types or edge["data"]["label"] in edge_types)
        ]
        
        return {
            "nodes": filtered_nodes,
            "edges": filtered_edges
        }
    
    def query_graph(self, graph_id: str, cypher_query: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Run a Cypher query against a specific graph.
        
        Args:
            graph_id: ID of the graph to query.
            cypher_query: Cypher query to execute.
            params: Query parameters.
            
        Returns:
            results: List of query results.
        """
        start_time = time.time()
        if params is None:
            params = {}
        
        params["graph_id"] = graph_id
        
        try:
            with self.driver.session() as session:
                result = session.run(cypher_query, params)
                records = [record.data() for record in result]
                
            logger.debug(f"Neo4j query executed in {time.time() - start_time:.3f}s")
            return records
        except Exception as e:
            logger.error(f"Query error: {e}, query: {cypher_query}, params: {params}")
            return []
    
    def validate_entities(
        self, 
        graph_id: str, 
        ip: Optional[str] = None, 
        port: Optional[str] = None, 
        protocol: Optional[str] = None,
        attack_type: Optional[str] = None
    ) -> Dict[str, bool]:
        """
        Validate that entities exist in the graph before query execution.
        
        This prevents "confidently wrong" answers by checking if the
        user-mentioned entities actually exist in the data.
        
        Args:
            graph_id: ID of the graph to check.
            ip: IP address to validate.
            port: Port number to validate.
            protocol: Protocol to validate.
            attack_type: Attack type to validate.
            
        Returns:
            Dict mapping entity keys to existence boolean.
            Example: {"ip": True, "port": False}
        """
        results = {}
        
        with self.driver.session() as session:
            # Validate IP
            if ip:
                ip_query = """
                MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
                WHERE n.label = $ip OR n.id CONTAINS $ip OR n.label CONTAINS $ip
                RETURN count(n) > 0 AS exists
                """
                result = session.run(ip_query, graph_id=graph_id, ip=str(ip))
                record = result.single()
                results["ip"] = record["exists"] if record else False
            
            # Validate Port
            if port:
                port_str = str(port)
                port_query = """
                MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
                WHERE n.type = 'Port' OR n.label CONTAINS $port OR n.port = $port
                RETURN count(n) > 0 AS exists
                """
                result = session.run(port_query, graph_id=graph_id, port=port_str)
                record = result.single()
                results["port"] = record["exists"] if record else False
            
            # Validate Protocol
            if protocol:
                protocol_query = """
                MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
                WHERE n.type = 'Protocol' OR toLower(n.protocol) = toLower($protocol) 
                      OR toLower(n.label) = toLower($protocol)
                RETURN count(n) > 0 AS exists
                """
                result = session.run(protocol_query, graph_id=graph_id, protocol=str(protocol))
                record = result.single()
                results["protocol"] = record["exists"] if record else False
            
            # Validate Attack Type
            if attack_type:
                attack_query = """
                MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
                WHERE n.type IN ['Attack', 'AttackType'] 
                      OR toLower(n.label) CONTAINS toLower($attack_type)
                      OR toLower(n.attack_category) CONTAINS toLower($attack_type)
                RETURN count(n) > 0 AS exists
                """
                result = session.run(attack_query, graph_id=graph_id, attack_type=str(attack_type))
                record = result.single()
                results["attack_type"] = record["exists"] if record else False
        
        logger.debug(f"Entity validation for graph {graph_id}: {results}")
        return results
