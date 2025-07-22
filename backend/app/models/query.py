from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class QueryInput(BaseModel):
    """Input model for graph queries"""
    query: str
    graph_id: Optional[str] = None

class QueryResponse(BaseModel):
    """Response model for graph queries"""
    answer: str
    paths: List[str]
    context_used: str