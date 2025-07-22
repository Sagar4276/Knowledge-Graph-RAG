from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class TextInput(BaseModel):
    """Model for text input"""
    text: str
    
class URLInput(BaseModel):
    """Model for URL input"""
    url: str

class ProcessResponse(BaseModel):
    """Response model for document processing"""
    graph_id: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]