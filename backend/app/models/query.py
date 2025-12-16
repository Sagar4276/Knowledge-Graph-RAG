from pydantic import BaseModel
from typing import List, Dict, Any, Optional


class QueryInput(BaseModel):
    """Input model for graph queries"""
    query: str
    graph_id: Optional[str] = None


class QueryResponse(BaseModel):
    """Response model for graph queries with grounding information"""
    answer: str
    paths: List[str] = []
    context_used: Optional[str] = None
    # New grounding fields
    intent: Optional[str] = None
    entities_extracted: Optional[Dict[str, Any]] = None
    query_results_count: Optional[int] = None
    cypher_template_used: Optional[str] = None
    grounding_context: Optional[str] = None