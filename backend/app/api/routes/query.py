from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from app.models.query import QueryInput, QueryResponse
from app.services.cypher_query_service import query_with_grounding
from app.services.neo4j_service import Neo4jService
from app.api.dependencies import get_neo4j_service
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/query", response_model=QueryResponse)
async def query_graph(
    query_input: QueryInput,
    neo4j_service: Neo4jService = Depends(get_neo4j_service)
):
    """
    Query the knowledge graph using Cypher-grounded RAG.
    
    This endpoint uses template-constrained Cypher queries:
    1. LLM classifies query intent + extracts entities
    2. Intent maps to safe Cypher template
    3. Results ground the LLM's answer (no hallucination)
    """
    try:
        # Check if graph_id provided
        if not query_input.graph_id:
            raise HTTPException(
                status_code=400,
                detail="graph_id is required for queries"
            )
        
        # Check if graph exists
        graph = neo4j_service.get_graph(query_input.graph_id)
        if not graph:
            raise HTTPException(
                status_code=404, 
                detail=f"Graph with ID {query_input.graph_id} not found"
            )
        
        logger.info(f"Processing grounded query: '{query_input.query}' for graph {query_input.graph_id}")
        
        # Process query with grounding
        result = query_with_grounding(
            question=query_input.query,
            neo4j_service=neo4j_service,
            graph_id=query_input.graph_id
        )
        
        logger.info(f"Query result - Intent: {result.get('intent')}, Results: {result.get('query_results_count')}")
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error in query endpoint: {e}")
        raise HTTPException(status_code=500, detail=f"Error querying graph: {str(e)}")