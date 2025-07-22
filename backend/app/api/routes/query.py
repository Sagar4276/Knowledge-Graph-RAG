from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from app.models.query import QueryInput, QueryResponse
from app.services.rag_service import query_knowledge_graph
from app.services.neo4j_service import Neo4jService
from app.api.dependencies import get_neo4j_service

router = APIRouter()

@router.post("/query", response_model=QueryResponse)
async def query_graph(
    query_input: QueryInput,
    neo4j_service: Neo4jService = Depends(get_neo4j_service)
):
    """Query the knowledge graph using RAG"""
    try:
        # Check if graph exists
        if query_input.graph_id:
            graph = neo4j_service.get_graph(query_input.graph_id)
            if not graph:
                raise HTTPException(
                    status_code=404, 
                    detail=f"Graph with ID {query_input.graph_id} not found"
                )
        
        # Process query
        result = query_knowledge_graph(
            query=query_input.query,
            graph_id=query_input.graph_id,
            neo4j_service=neo4j_service
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying graph: {str(e)}")