from typing import Dict, Any, List, Optional, Tuple
import os
import json
import uuid
import logging
import re
from app.services.llm_factory import get_llm

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define entity types and relation types for our knowledge graph
# SECURITY-GRADE SCHEMA: Connection is a first-class entity, not just an edge
ENTITY_TYPES = [
    # General entity types
    "Person", 
    "Organization", 
    "Location", 
    "Concept", 
    "Event", 
    "Product", 
    "Date",
    "Document",
    "Technology",
    
    # Network Security Entity Types (Telemetry)
    "IPAddress",
    "InternalIP",
    "ExternalIP",
    "Port",
    "Protocol",
    "Service",
    "Device",
    "Domain",
    
    # CRITICAL: Connection as a first-class entity (not just an edge)
    # This allows attaching properties like timestamp, bytes, protocol to the connection itself
    "Connection",          # A network connection event
    "Session",             # A user session (login/logout)
    
    # Security Semantic Types
    "Vulnerability",
    "Threat",              # General threat classification
    "Attack",              # Specific attack instance
    "AttackChain",         # Sequence of related attacks (kill chain)
    "Indicator",           # IOC - Indicator of Compromise
    "Evidence",            # Supporting evidence for a finding
    
    # Attack Types (MITRE ATT&CK aligned)
    "InitialAccess",       # T1190, T1133, etc.
    "Execution",           # T1059, T1204, etc.
    "Persistence",         # T1098, T1136, etc.
    "PrivilegeEscalation",
    "CredentialAccess",    # T1003, T1110, etc.
    "LateralMovement",     # T1021, T1080, etc.
    "Collection",          # T1005, T1039, etc.
    "Exfiltration",        # T1041, T1048, etc.
    "CommandAndControl",   # T1071, T1095, etc.
]

RELATION_TYPES = [
    # General relationship types
    "WORKS_FOR",
    "LOCATED_IN",
    "FOUNDED_BY",
    "FOUNDED",
    "RELATED_TO",
    "PART_OF",
    "HAS_ROLE",
    "CREATED",
    "KNOWS",
    "INVOLVED_IN",
    "OWNS",
    "USES",
    "MENTIONS",
    "HAPPENED_ON",
    "HAS_PROPERTY",
    "FOUNDED_ON",
    "ACQUIRED_ON",
    "FOUNDER_OF",
    "EMPLOYED_BY",
    "CEO_OF",
    "RESIDES_IN",
    "LAUNCHED_ON",
    "RELEASED_ON",
    "OCCURRED_ON",
    "USES_TECHNOLOGY",
    "ACQUIRED",
    
    # Network Security Relationship Types
    "CONNECTED_TO",
    "USES_PORT",
    "RESOLVES_TO",
    "LOGGED_IN",
    "RUNS_SERVICE",
    "TRANSFERRED_TO",
    "FLAGGED_AS",
    "SCANNED",
    "ATTACKED",
    "EXPLOITS",
    "TARGETS",
    
    # ATTACK CHAIN RELATIONSHIPS (causal/temporal ordering)
    "LEADS_TO",            # A → B where A enables B (e.g., credential compromise → lateral movement)
    "FOLLOWED_BY",         # Temporal: A happened before B
    "RESULTS_IN",          # Causal: A caused B
    "PRECEDED_BY",         # Temporal: A happened after B
    "ENABLES",             # A makes B possible
    "INDICATES",           # A is evidence of B
    
    # CONNECTION-CENTRIC RELATIONSHIPS (Connection as a node)
    "INITIATED",           # Actor → Connection (who started the connection)
    "SOURCE_OF",           # IP/Device → Connection (source of connection)
    "TARGET_OF",           # IP/Device → Connection (destination of connection)
    "USED_PROTOCOL",       # Connection → Protocol
    "USED_PORT",           # Connection → Port
    "OCCURRED_AT",         # Connection/Event → Timestamp
    "TRANSFERRED_DATA",    # Connection → data volume info
    
    # EVIDENCE RELATIONSHIPS
    "SUPPORTED_BY",        # Finding → Evidence
    "OBSERVED_IN",         # Indicator → Where it was seen
    "ATTRIBUTED_TO",       # Attack → Threat actor
]

# Semantic relationship mapping for normalization
SEMANTIC_RELATIONSHIP_MAP = {
    # Maps various edge types to a canonical one for founding events
    ("Date", "Organization", "CREATED"): "FOUNDED_ON",
    ("Date", "Organization", "FOUNDED_ON"): "FOUNDED_ON",
    ("Date", "Organization", "ESTABLISHED_ON"): "FOUNDED_ON",
    ("Date", "Organization", "STARTED_ON"): "FOUNDED_ON",

    # Organization acquisition events
    ("Date", "Organization", "ACQUIRED"): "ACQUIRED_ON",
    ("Date", "Organization", "PURCHASED"): "ACQUIRED_ON",
    ("Organization", "Organization", "ACQUIRED"): "ACQUIRED",
    ("Organization", "Organization", "PURCHASED"): "ACQUIRED",

    # Leadership and employment
    ("Person", "Organization", "FOUNDED"): "FOUNDER_OF",
    ("Person", "Organization", "STARTED"): "FOUNDER_OF",
    ("Person", "Organization", "CREATOR_OF"): "FOUNDER_OF",
    ("Person", "Organization", "WORKS_FOR"): "EMPLOYED_BY",
    ("Person", "Organization", "CEO_OF"): "CEO_OF",

    # Location
    ("Organization", "Location", "HEADQUARTERED_IN"): "LOCATED_IN",
    ("Organization", "Location", "BASED_IN"): "LOCATED_IN",
    ("Person", "Location", "LIVES_IN"): "RESIDES_IN",

    # Product launches
    ("Date", "Product", "LAUNCHED"): "LAUNCHED_ON",
    ("Date", "Product", "RELEASED"): "RELEASED_ON",
    ("Date", "Product", "INTRODUCED"): "RELEASED_ON",

    # Events
    ("Event", "Date", "HAPPENED_ON"): "OCCURRED_ON",
    ("Product", "Technology", "USES"): "USES_TECHNOLOGY",
}


def normalize_edge_type(source_type: str, target_type: str, edge_type: str) -> str:
    """Normalize an edge type using semantic mapping."""
    if not source_type or not target_type:
        return edge_type
    return SEMANTIC_RELATIONSHIP_MAP.get((source_type, target_type, edge_type), edge_type)


def determine_relationship_direction(relationship_type: str, source_type: str, target_type: str) -> bool:
    """
    Dynamically determine if a relationship direction should be reversed
    based on semantic meaning and entity types
    
    Returns:
        bool: True if relationship should be reversed, False otherwise
    """
    # Dictionary of relationship types and their expected directions
    # Format: "RELATIONSHIP_TYPE": ("FROM_TYPE", "TO_TYPE")
    relationship_semantics = {
        "FOUNDED_BY": ("Organization", "Person"),
        "HAS_ROLE": ("Organization", "Person"),
        "EMPLOYS": ("Organization", "Person"),
        "WORKS_FOR": ("Person", "Organization"),
        "FOUNDED": ("Person", "Organization"),
        "HAPPENED_ON": ("Event", "Date"),
        "CREATED_ON": ("Product", "Date"),
        "LOCATED_IN": ("Organization", "Location"),
        "HEADQUARTERED_IN": ("Organization", "Location")
    }
    
    # If we have semantics for this relationship type
    if relationship_type in relationship_semantics and source_type and target_type:
        expected_source, expected_target = relationship_semantics[relationship_type]
        
        # If the current direction doesn't match expected semantics, reverse it
        if source_type == expected_target and target_type == expected_source:
            logger.info(f"Reversing relationship: {source_type}--{relationship_type}-->{target_type}")
            return True
    
    return False


class CustomGraphTransformer:
    """Custom graph transformer for extracting knowledge graphs from text."""
    
    def __init__(self, llm, allowed_nodes: Optional[List[str]] = None, 
                 allowed_relationships: Optional[List[str]] = None):
        self.llm = llm
        self.allowed_nodes = allowed_nodes or ENTITY_TYPES
        self.allowed_relationships = allowed_relationships or RELATION_TYPES
        logger.info("Initialized CustomGraphTransformer")
    
    def _create_extraction_prompt(self, text: str) -> str:
        """Create a security-grade structured prompt for knowledge graph extraction."""
        return f'''Extract a SECURITY-GRADE knowledge graph from the following text.

## CRITICAL SCHEMA RULES:

### 1. CONNECTION AS A NODE (NOT JUST AN EDGE)
When describing network connections, create a Connection node:
- BAD:  IP_A --CONNECTED_TO--> IP_B
- GOOD: IP_A --SOURCE_OF--> Connection_1 --TARGET_OF--> IP_B
        Connection_1 --USED_PORT--> Port_22
        Connection_1 --USED_PROTOCOL--> SSH

### 2. ATTACK CHAINS MUST BE EXPLICIT
Use LEADS_TO, FOLLOWED_BY, RESULTS_IN to show causality:
- CredentialCompromise --LEADS_TO--> LateralMovement
- LateralMovement --LEADS_TO--> Exfiltration

### 3. CONFIDENCE AND EVIDENCE
For security findings, include confidence and source in properties:
- "properties": {{"confidence": 0.85, "source": "text_inference", "severity": "high"}}

### 4. ENTITY TYPE SELECTION
Network entities (telemetry):
- InternalIP, ExternalIP, Port, Protocol, Device, Connection, Session

Security events:
- Attack, Threat, Vulnerability, Indicator, Evidence, AttackChain

Attack stages (MITRE aligned):
- InitialAccess, CredentialAccess, LateralMovement, Exfiltration, CommandAndControl

### 5. RELATIONSHIP TYPES FOR SECURITY

Attack chain (use these for kill chain):
- LEADS_TO: A enables or causes B
- FOLLOWED_BY: A happened before B  
- RESULTS_IN: A caused B
- INDICATES: A is evidence of B

Connection-centric:
- SOURCE_OF: IP/Device originated Connection
- TARGET_OF: IP/Device is destination of Connection
- INITIATED: Person/Process started Connection
- USED_PORT: Connection used this port
- USED_PROTOCOL: Connection used this protocol
- OCCURRED_AT: Event/Connection happened at timestamp

## ENTITY TYPES AVAILABLE:
{', '.join(self.allowed_nodes)}

## RELATIONSHIP TYPES AVAILABLE:
{', '.join(self.allowed_relationships)}

## TEXT TO ANALYZE:
{text}

## REQUIRED OUTPUT FORMAT:
Return ONLY a valid JSON object:
{{
  "nodes": [
    {{ 
      "id": "conn_1", 
      "type": "Connection", 
      "label": "SSH Connection to DB Server",
      "properties": {{"timestamp": "2025-01-12T10:30:00Z", "bytes_transferred": 150000000}}
    }},
    {{ 
      "id": "threat_1", 
      "type": "LateralMovement", 
      "label": "SSH-based Lateral Movement",
      "properties": {{"confidence": 0.85, "source": "text_inference", "severity": "high"}}
    }}
  ],
  "relationships": [
    {{ "source": "ip_internal", "target": "conn_1", "type": "SOURCE_OF" }},
    {{ "source": "conn_1", "target": "ip_external", "type": "TARGET_OF" }},
    {{ "source": "threat_credential", "target": "threat_lateral", "type": "LEADS_TO" }}
  ]
}}
'''
    
    def _invoke_llm(self, prompt: str) -> str:
        """Invoke the LLM with error handling for different interfaces."""
        try:
            # Try modern LangChain interface first
            if hasattr(self.llm, "invoke"):
                result = self.llm.invoke(prompt)
                return str(result) if not isinstance(result, str) else result
            
            # Try message-based interface
            elif hasattr(self.llm, "predict_messages"):
                from langchain.schema import HumanMessage
                result = self.llm.predict_messages([HumanMessage(content=prompt)])
                return result.content if hasattr(result, 'content') else str(result)
            
            # Fallback to direct call
            else:
                result = self.llm(prompt)
                return str(result) if not isinstance(result, str) else result
                
        except Exception as e:
            logger.error(f"Error invoking LLM: {str(e)}")
            raise
    
    def _extract_json_from_response(self, content: str) -> Dict[str, Any]:
        """Extract JSON from LLM response with multiple fallback strategies."""
        # Strategy 1: Look for JSON in code blocks
        json_patterns = [
            r'```json\s*([\s\S]*?)\s*```',
            r'```\s*([\s\S]*?)\s*```',
            r'({[\s\S]*})'
        ]
        
        for pattern in json_patterns:
            match = re.search(pattern, content)
            if match:
                json_str = match.group(1)
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    continue
        
        # Strategy 2: Find JSON-like structure in the text
        try:
            json_start = content.find('{')
            json_end = content.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = content[json_start:json_end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        logger.warning("Failed to extract JSON from LLM response")
        return {"nodes": [], "relationships": []}
    
    def transform(self, text: str) -> Dict[str, Any]:
        """Extract knowledge graph from text using LLM."""
        if not text.strip():
            return {"nodes": [], "relationships": []}
        
        try:
            prompt = self._create_extraction_prompt(text)
            content = self._invoke_llm(prompt)
            logger.info(f"LLM response length: {len(content)} characters")
            
            result = self._extract_json_from_response(content)
            logger.info(f"Extracted JSON result: {result}")
            
            # Validate the structure
            if not isinstance(result, dict):
                logger.warning("LLM response is not a dictionary")
                return {"nodes": [], "relationships": []}
            
            nodes = result.get("nodes", [])
            relationships = result.get("relationships", [])
            
            logger.info(f"Extracted {len(nodes)} nodes and {len(relationships)} relationships")
            return {"nodes": nodes, "relationships": relationships}
            
        except Exception as e:
            logger.error(f"Error in transform method: {str(e)}")
            return {"nodes": [], "relationships": []}


def get_graph_transformer() -> CustomGraphTransformer:
    """Factory function to create and return a graph transformer instance."""
    try:
        llm = get_llm()
        return CustomGraphTransformer(
            llm=llm,
            allowed_nodes=ENTITY_TYPES,
            allowed_relationships=RELATION_TYPES
        )
    except Exception as e:
        logger.error(f"Error creating graph transformer: {str(e)}")
        raise


def validate_graph_data(graph_data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and clean graph data structure with security-grade properties."""
    validated_data = {
        "nodes": [],
        "edges": [],
        "graph_type": "semantic"  # Mark as semantic (vs telemetry from network logs)
    }
    
    nodes = graph_data.get("nodes", [])
    relationships = graph_data.get("relationships", graph_data.get("edges", []))
    
    # Security entity types that should have confidence/source
    SECURITY_TYPES = {
        "Threat", "Attack", "AttackChain", "Vulnerability", "Indicator", 
        "Evidence", "InitialAccess", "CredentialAccess", "LateralMovement",
        "Exfiltration", "CommandAndControl", "Persistence", "PrivilegeEscalation",
        "Collection", "Execution"
    }
    
    # Validate nodes - ALWAYS generate unique UUIDs to avoid conflicts
    node_ids = set()
    old_to_new_id_map = {}  # Map old IDs to new UUIDs for relationships
    
    for node in nodes:
        if not isinstance(node, dict):
            continue
        
        old_id = node.get("id", "")
        # ALWAYS generate a new unique UUID for each node
        new_id = str(uuid.uuid4())
        
        # Map old ID to new ID for relationship resolution
        if old_id:
            old_to_new_id_map[str(old_id)] = new_id
            
        node_ids.add(new_id)
        
        # Get node type and properties
        node_type = node.get("type", "Entity")
        properties = node.get("properties", {})
        
        # Add default security properties for security entity types
        if node_type in SECURITY_TYPES:
            if "confidence" not in properties:
                properties["confidence"] = 0.7  # Default confidence for text inference
            if "source" not in properties:
                properties["source"] = "text_inference"
            if "severity" not in properties and node_type in ["Attack", "Exfiltration", "CommandAndControl"]:
                properties["severity"] = "high"
        
        # Add entity_class to distinguish telemetry vs semantic
        if node_type in ["InternalIP", "ExternalIP", "Port", "Protocol", "Connection", "Session"]:
            properties["entity_class"] = "telemetry"
        elif node_type in SECURITY_TYPES:
            properties["entity_class"] = "security"
        else:
            properties["entity_class"] = "semantic"
        
        validated_data["nodes"].append({
            "data": {
                "id": new_id,
                "label": node.get("label", f"Entity {len(validated_data['nodes']) + 1}"),
                "type": node_type,
                "properties": properties
            }
        })
    
    # Validate relationships - use the ID mapping
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
            
        old_source_id = str(rel.get("source", ""))
        old_target_id = str(rel.get("target", ""))
        
        # Map old IDs to new UUIDs
        source_id = old_to_new_id_map.get(old_source_id)
        target_id = old_to_new_id_map.get(old_target_id)
        
        # Only add relationship if both source and target exist
        if source_id and target_id:
            rel_type = rel.get("type", "RELATED_TO")
            
            # Add edge properties for security relationships
            edge_properties = {}
            if rel_type in ["LEADS_TO", "FOLLOWED_BY", "RESULTS_IN"]:
                edge_properties["edge_class"] = "attack_chain"
            elif rel_type in ["SOURCE_OF", "TARGET_OF", "USED_PORT", "USED_PROTOCOL"]:
                edge_properties["edge_class"] = "connection"
            
            validated_data["edges"].append({
                "data": {
                    "id": f"e_{uuid.uuid4().hex[:8]}",
                    "source": source_id,
                    "target": target_id,
                    "label": rel_type,
                    "properties": edge_properties
                }
            })
    
    return validated_data


def extract_knowledge_graph(text: str) -> Dict[str, Any]:
    """
    Extract a knowledge graph from the given text.
    
    Args:
        text: The text to extract a knowledge graph from
        
    Returns:
        A dictionary containing nodes and edges of the knowledge graph
    """
    if not text or not text.strip():
        logger.warning("Empty text provided for knowledge graph extraction")
        return {"graph_id": str(uuid.uuid4()), "nodes": [], "edges": []}
    
    # Truncate very long texts to avoid token limits
    if len(text) > 10000:
        text = text[:10000] + "..."
        logger.info("Truncated text to 10000 characters")
    
    try:
        logger.info("Starting knowledge graph extraction")
        
        transformer = get_graph_transformer()
        raw_graph = transformer.transform(text)
        logger.info(f"Raw graph from transformer: nodes={len(raw_graph.get('nodes', []))}, relationships={len(raw_graph.get('relationships', []))}")
        
        # Validate and clean the extracted graph
        processed_graph = validate_graph_data(raw_graph)
        
        # Apply semantic normalization and relationship direction correction
        processed_nodes = processed_graph["nodes"]
        processed_edges = []
        
        # Create a lookup map for node types
        node_type_map = {}
        for node in processed_nodes:
            node_data = node.get("data", {})
            node_type_map[node_data.get("id")] = node_data.get("type")
        
        # Process edges with normalization and direction correction
        for edge in processed_graph["edges"]:
            edge_data = edge.get("data", {})
            source_id = edge_data.get("source")
            target_id = edge_data.get("target")
            edge_type = edge_data.get("label")
            
            source_type = node_type_map.get(source_id)
            target_type = node_type_map.get(target_id)
            
            # Apply semantic normalization
            normalized_edge_type = normalize_edge_type(source_type, target_type, edge_type)
            
            # Check if relationship direction should be reversed
            if determine_relationship_direction(normalized_edge_type, source_type, target_type):
                # Swap source and target
                source_id, target_id = target_id, source_id
                logger.info(f"Reversed relationship: {normalized_edge_type}")
            
            processed_edges.append({
                "data": {
                    "id": edge_data.get("id"),
                    "source": source_id,
                    "target": target_id,
                    "label": normalized_edge_type
                }
            })
        
        result = {
            "graph_id": str(uuid.uuid4()),
            "nodes": processed_nodes,
            "edges": processed_edges
        }
        
        logger.info(f"Successfully extracted graph with {len(result['nodes'])} nodes and {len(result['edges'])} edges")
        return result
        
    except Exception as e:
        logger.exception(f"Error extracting knowledge graph: {e}")
        # Return a minimal graph if extraction fails
        return {
            "graph_id": str(uuid.uuid4()),
            "nodes": [],
            "edges": []
        }


def chunk_text(text: str, chunk_size: int = 4000, overlap: int = 200) -> List[str]:
    """
    Split text into overlapping chunks of specified size.
    
    Args:
        text: Text to split
        chunk_size: Maximum size of each chunk
        overlap: Number of characters to overlap between chunks
        
    Returns:
        List of text chunks
    """
    if len(text) <= chunk_size:
        return [text]
    
    chunks = []
    start = 0
    
    while start < len(text):
        end = start + chunk_size
        
        # If this is not the last chunk, try to break at a sentence or word boundary
        if end < len(text):
            # Look for sentence boundary
            sentence_break = text.rfind('.', start, end)
            if sentence_break > start + chunk_size // 2:
                end = sentence_break + 1
            else:
                # Look for word boundary
                word_break = text.rfind(' ', start, end)
                if word_break > start + chunk_size // 2:
                    end = word_break
        
        chunks.append(text[start:end])
        start = max(start + 1, end - overlap)  # Ensure progress
    
    return chunks


def merge_knowledge_graphs(graphs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge multiple knowledge graphs into a single graph.
    
    Args:
        graphs: List of knowledge graphs to merge
        
    Returns:
        Merged knowledge graph
    """
    merged_nodes = []
    merged_edges = []
    node_id_map = {}  # Map original IDs to new unique IDs
    seen_nodes = set()  # Track seen node labels to avoid duplicates
    
    for graph in graphs:
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        
        # Process nodes
        for node in nodes:
            node_data = node.get("data", {})
            original_id = node_data.get("id")
            label = node_data.get("label", "")
            node_type = node_data.get("type", "")
            
            # Create a unique identifier for deduplication
            node_key = f"{label.lower()}_{node_type.lower()}"
            
            if node_key not in seen_nodes:
                new_id = str(uuid.uuid4())
                node_id_map[original_id] = new_id
                seen_nodes.add(node_key)
                
                merged_nodes.append({
                    "data": {
                        "id": new_id,
                        "label": label,
                        "type": node_type,
                        "properties": node_data.get("properties", {})
                    }
                })
            else:
                # Find existing node ID
                for existing_node in merged_nodes:
                    existing_data = existing_node.get("data", {})
                    existing_key = f"{existing_data.get('label', '').lower()}_{existing_data.get('type', '').lower()}"
                    if existing_key == node_key:
                        node_id_map[original_id] = existing_data.get("id")
                        break
        
        # Process edges
        for edge in edges:
            edge_data = edge.get("data", {})
            original_source = edge_data.get("source")
            original_target = edge_data.get("target")
            
            # Map to new node IDs
            new_source = node_id_map.get(original_source)
            new_target = node_id_map.get(original_target)
            
            if new_source and new_target:
                merged_edges.append({
                    "data": {
                        "id": f"e_{uuid.uuid4().hex[:8]}",
                        "source": new_source,
                        "target": new_target,
                        "label": edge_data.get("label", "RELATED_TO")
                    }
                })
    
    return {
        "graph_id": str(uuid.uuid4()),
        "nodes": merged_nodes,
        "edges": merged_edges
    }