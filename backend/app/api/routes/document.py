from fastapi import APIRouter, File, UploadFile, Depends, HTTPException
from typing import Optional
from app.models.document import TextInput, URLInput, ProcessResponse
from app.services.document_processor import process_document, process_text, process_url
from app.services.graph_extractor import extract_knowledge_graph
from app.services.neo4j_service import Neo4jService
from app.api.dependencies import get_neo4j_service

router = APIRouter()

@router.post("/process/document", response_model=ProcessResponse)
async def upload_document(
    file: UploadFile = File(...),
    neo4j_service: Neo4jService = Depends(get_neo4j_service)
):
    """Upload and process a document to extract knowledge graph"""
    try:
        content = await file.read()
        text = process_document(content, file.filename)
        kg = extract_knowledge_graph(text)
        graph_id = neo4j_service.store_graph(kg)
        
        return {
            "graph_id": graph_id,
            "nodes": kg["nodes"],
            "edges": kg["edges"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing document: {str(e)}")

@router.post("/process/text", response_model=ProcessResponse)
async def process_text_input(
    text_input: TextInput,
    neo4j_service: Neo4jService = Depends(get_neo4j_service)
):
    """Process raw text to extract knowledge graph"""
    try:
        kg = extract_knowledge_graph(text_input.text)
        graph_id = neo4j_service.store_graph(kg)
        
        return {
            "graph_id": graph_id,
            "nodes": kg["nodes"],
            "edges": kg["edges"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing text: {str(e)}")

@router.post("/process/url", response_model=ProcessResponse)
async def process_url_input(
    url_input: URLInput,
    neo4j_service: Neo4jService = Depends(get_neo4j_service)
):
    """Process content from a URL to extract knowledge graph"""
    try:
        text = process_url(url_input.url)
        kg = extract_knowledge_graph(text)
        graph_id = neo4j_service.store_graph(kg)
        
        return {
            "graph_id": graph_id,
            "nodes": kg["nodes"],
            "edges": kg["edges"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing URL: {str(e)}")