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
                session.run("CREATE CONSTRAINT IF NOT EXISTS ON (n:Node) ASSERT n.id IS UNIQUE")
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
        start_time = time.time()
        
        with self.driver.session() as session:
            # Create graph container
            session.run(
                "CREATE (g:Graph {id: $graph_id, created: datetime()})",
                graph_id=graph_id
            )
            
            # Process nodes in batches
            node_batches = [graph["nodes"][i:i + batch_size] for i in range(0, len(graph["nodes"]), batch_size)]
            
            for batch in node_batches:
                for node in batch:
                    node_data = node["data"]
                    node_id = node_data["id"]
                    node_label = node_data.get("label", "")
                    node_type = node_data.get("type", "Entity")
                    properties = node_data.get("properties", {})
                    
                    cypher = f"""
                    CREATE (n:Node:`{node_type}` {{id: $id, label: $label}})
                    SET n += $properties
                    WITH n
                    MATCH (g:Graph {{id: $graph_id}})
                    CREATE (g)-[:CONTAINS]->(n)
                    """
                    
                    session.run(
                        cypher,
                        id=node_id,
                        label=node_label,
                        properties=properties,
                        graph_id=graph_id
                    )
            
            # Process edges in batches
            edge_batches = [graph["edges"][i:i + batch_size] for i in range(0, len(graph["edges"]), batch_size)]
            
            for batch in edge_batches:
                for edge in batch:
                    edge_data = edge["data"]
                    edge_id = edge_data["id"]
                    source_id = edge_data["source"]
                    target_id = edge_data["target"]
                    edge_label = edge_data.get("label", "RELATED_TO")
                    
                    cypher = f"""
                    MATCH (source:Node {{id: $source_id}})
                    MATCH (target:Node {{id: $target_id}})
                    CREATE (source)-[r:`{edge_label}` {{id: $edge_id}}]->(target)
                    """
                    
                    session.run(
                        cypher,
                        source_id=source_id,
                        target_id=target_id,
                        edge_id=edge_id
                    )
        
        logger.info(f"Graph {graph_id} created in {time.time() - start_time:.2f}s with {len(graph['nodes'])} nodes and {len(graph['edges'])} edges")
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
