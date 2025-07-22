from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class NodeData(BaseModel):
    id: str
    label: str
    type: str
    properties: Dict[str, Any] = {}

class EdgeData(BaseModel):
    id: str
    source: str
    target: str
    label: str

class Node(BaseModel):
    data: NodeData

class Edge(BaseModel):
    data: EdgeData

class GraphResponse(BaseModel):
    """Response model for graph retrieval"""
    graph_id: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]

class NodeFilter(BaseModel):
    """Filter options for a graph"""
    node_types: Optional[List[str]] = None
    edge_types: Optional[List[str]] = None
    search_term: Optional[str] = None