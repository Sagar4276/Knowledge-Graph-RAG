from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import document, graph, query, network
from app.config import settings
from app.services.neo4j_service import Neo4jService
import logging
import os
from app.utils.logging_utils import setup_logging

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="Network Security Graph RAG API",
    description="API for network security analysis with knowledge graphs and RAG",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Neo4j service
neo4j_service = Neo4jService(
    uri=settings.neo4j_uri,
    user=settings.neo4j_user,
    password=settings.neo4j_password
)

# Include routers
app.include_router(document.router, prefix=settings.api_prefix, tags=["Document Processing"])
app.include_router(graph.router, prefix=settings.api_prefix, tags=["Graph Operations"])
app.include_router(query.router, prefix=settings.api_prefix, tags=["RAG Queries"])
app.include_router(network.router, prefix=settings.api_prefix, tags=["Network Security"])

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    logger.debug("Health check endpoint called")
    return {"status": "healthy", "version": "2.0.0"}

@app.on_event("startup")
async def startup_event():
    """Startup event handler - auto-processes CSV files in sample_data"""
    logger.info("Starting Network Security Graph RAG API")
    
    # Auto-process CSV files if enabled
    enable_auto = os.environ.get("ENABLE_AUTO_PROCESS", "true").lower() == "true"
    
    if enable_auto:
        try:
            from app.services.auto_processor import scan_and_process_csv_files
            
            sample_data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_data")
            
            if os.path.exists(sample_data_dir):
                logger.info(f"Scanning {sample_data_dir} for CSV files...")
                results = scan_and_process_csv_files(sample_data_dir, neo4j_service)
                
                if results:
                    for result in results:
                        if result.get("status") == "success":
                            logger.info(
                                f"Auto-processed {result.get('filename')}: "
                                f"Graph ID = {result.get('graph_id')}, "
                                f"Connections = {result.get('processing_summary', {}).get('valid_connections', 0)}"
                            )
                        else:
                            logger.warning(f"Failed to process {result.get('filename')}: {result.get('error')}")
                else:
                    logger.info("No new CSV files to process")
            else:
                logger.debug(f"Sample data directory not found: {sample_data_dir}")
                
        except Exception as e:
            logger.error(f"Error in auto-processing: {e}")
    else:
        logger.info("Auto-processing disabled (set ENABLE_AUTO_PROCESS=true to enable)")

@app.on_event("shutdown")
def shutdown_event():
    """Shutdown event handler"""
    logger.info("Shutting down Knowledge Graph RAG API")
    neo4j_service.close()