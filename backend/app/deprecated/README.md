# Deprecated Code

This folder contains deprecated code that was moved from the main application.

## Why Deprecated

These files implemented **document/text processing endpoints** that:
- Used LLM to **synthesize** knowledge graphs from text/documents
- Caused confusion because users thought they were **querying** network data
- Are NOT needed for the Network Security use case

## Files Moved

| Original Location | New Location | Purpose |
|-------------------|--------------|---------|
| `api/routes/document.py` | `document_routes.py` | Endpoints: `/api/process/text`, `/api/process/document`, `/api/process/url` |
| `services/document_processor.py` | `document_processor.py` | Document text extraction (PDF, TXT, etc.) |
| `services/graph_extractor.py` | `graph_extractor.py` | LLM-based knowledge graph extraction from text |
| `models/document.py` | `document_models.py` | Pydantic models for document endpoints |

## Removed Endpoints

- `POST /api/process/text` - Extracted KG from raw text
- `POST /api/process/document` - Extracted KG from uploaded documents
- `POST /api/process/url` - Extracted KG from web pages

## Use Instead

For network security queries, use:
- `POST /api/network/query` - Grounded RAG queries against actual network data
- `POST /api/network/upload-csv` - Ingest network traffic data

## Date Deprecated

2025-12-24
