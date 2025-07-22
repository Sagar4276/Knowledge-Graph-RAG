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
ENTITY_TYPES = [
    "Person", 
    "Organization", 
    "Location", 
    "Concept", 
    "Event", 
    "Product", 
    "Date",
    "Document",
    "Technology"
]

RELATION_TYPES = [
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
    "ACQUIRED"
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
        """Create a structured prompt for knowledge graph extraction."""
        return f"""
Extract a knowledge graph from the following text. Follow these guidelines:

ENTITY TYPES: {', '.join(self.allowed_nodes)}
RELATIONSHIP TYPES: {', '.join(self.allowed_relationships)}

Instructions:
1. Identify all entities and classify them into the provided types
2. Extract relationships between entities using the provided relationship types
3. Use meaningful, descriptive labels for entities
4. Ensure relationships make logical sense

Text to analyze:
{text}

Return ONLY a valid JSON object with this exact structure:
{{
  "nodes": [
    {{ "id": "unique_id_1", "type": "EntityType", "label": "Entity Name" }},
    {{ "id": "unique_id_2", "type": "EntityType", "label": "Entity Name" }}
  ],
  "relationships": [
    {{ "source": "unique_id_1", "target": "unique_id_2", "type": "RELATIONSHIP_TYPE" }}
  ]
}}
"""
    
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
    """Validate and clean graph data structure."""
    validated_data = {
        "nodes": [],
        "edges": []
    }
    
    nodes = graph_data.get("nodes", [])
    relationships = graph_data.get("relationships", graph_data.get("edges", []))
    
    # Validate nodes
    node_ids = set()
    for node in nodes:
        if not isinstance(node, dict):
            continue
            
        node_id = node.get("id")
        if not node_id:
            node_id = str(uuid.uuid4())
            
        # Avoid duplicate node IDs
        if node_id in node_ids:
            node_id = f"{node_id}_{uuid.uuid4().hex[:8]}"
            
        node_ids.add(node_id)
        
        validated_data["nodes"].append({
            "data": {
                "id": node_id,
                "label": node.get("label", f"Entity {len(validated_data['nodes']) + 1}"),
                "type": node.get("type", "Entity"),
                "properties": node.get("properties", {})
            }
        })
    
    # Validate relationships
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
            
        source_id = rel.get("source")
        target_id = rel.get("target")
        
        # Only add relationship if both source and target exist
        if source_id in node_ids and target_id in node_ids:
            rel_type = rel.get("type", "RELATED_TO")
            
            validated_data["edges"].append({
                "data": {
                    "id": f"e_{uuid.uuid4().hex[:8]}",
                    "source": source_id,
                    "target": target_id,
                    "label": rel_type
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
        
        # Create transformer and extract graph
        transformer = get_graph_transformer()
        raw_graph = transformer.transform(text)
        
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