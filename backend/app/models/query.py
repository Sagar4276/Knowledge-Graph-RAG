from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class QueryInput(BaseModel):
    """Input model for graph queries"""
    query: str
    graph_id: Optional[str] = None


class QueryResponse(BaseModel):
    """Response model for graph queries with grounding information"""
    answer: str
    paths: List[str] = Field(default_factory=list)
    context_used: Optional[str] = None
    # Grounding fields
    intent: Optional[str] = None
    entities_extracted: Optional[Dict[str, Any]] = None
    query_results_count: Optional[int] = None
    cypher_template_used: Optional[str] = None
    grounding_context: Optional[str] = None
    # Validation hardening fields
    confidence_score: Optional[float] = None  # Intent classification confidence (0-1)
    validation_warnings: List[str] = Field(default_factory=list)  # Entity/result warnings
    entities_validated: Optional[Dict[str, bool]] = None  # Which entities exist in graph
    # Performance metrics
    execution_time_ms: Optional[int] = None  # Query execution time in milliseconds