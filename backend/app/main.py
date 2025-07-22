from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import document, graph, query
from app.config import settings
from app.services.neo4j_service import Neo4jService
import logging
from app.utils.logging_utils import setup_logging

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="Knowledge Graph RAG Dashboard API",
    description="API for extracting and visualizing knowledge graphs from documents",
    version="1.0.0",
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

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    logger.debug("Health check endpoint called")
    return {"status": "healthy", "version": "1.0.0"}

@app.on_event("startup")
async def startup_event():
    """Startup event handler"""
    logger.info("Starting Knowledge Graph RAG API")

@app.on_event("shutdown")
def shutdown_event():
    """Shutdown event handler"""
    logger.info("Shutting down Knowledge Graph RAG API")
    neo4j_service.close()