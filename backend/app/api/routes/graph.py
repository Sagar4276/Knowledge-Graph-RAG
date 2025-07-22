from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from app.models.graph import GraphResponse, NodeFilter
from app.services.neo4j_service import Neo4jService
from app.api.dependencies import get_neo4j_service

router = APIRouter()

@router.get("/graphs/{graph_id}", response_model=GraphResponse)
async def get_graph(
    graph_id: str,
    neo4j_service: Neo4jService = Depends(get_neo4j_service)
):
    """Get a specific knowledge graph by ID"""
    try:
        kg = neo4j_service.get_graph(graph_id)
        if not kg:
            raise HTTPException(status_code=404, detail=f"Graph with ID {graph_id} not found")
        
        return {
            "graph_id": graph_id,
            "nodes": kg["nodes"],
            "edges": kg["edges"]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving graph: {str(e)}")

@router.get("/graphs", response_model=List[str])
async def list_graphs(
    neo4j_service: Neo4jService = Depends(get_neo4j_service)
):
    """List all available knowledge graphs"""
    try:
        graph_ids = neo4j_service.list_graphs()
        return graph_ids
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing graphs: {str(e)}")

@router.post("/graphs/{graph_id}/filter", response_model=GraphResponse)
async def filter_graph(
    graph_id: str,
    filter_options: NodeFilter,
    neo4j_service: Neo4jService = Depends(get_neo4j_service)
):
    """Filter nodes and edges in a graph based on criteria"""
    try:
        kg = neo4j_service.filter_graph(
            graph_id=graph_id,
            node_types=filter_options.node_types,
            edge_types=filter_options.edge_types,
            search_term=filter_options.search_term
        )
        
        if not kg:
            raise HTTPException(status_code=404, detail=f"Graph with ID {graph_id} not found")
        
        return {
            "graph_id": graph_id,
            "nodes": kg["nodes"],
            "edges": kg["edges"]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error filtering graph: {str(e)}")