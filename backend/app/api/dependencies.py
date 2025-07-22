from fastapi import Depends
from app.services.neo4j_service import Neo4jService
import os

# Singleton instance of Neo4jService
_neo4j_service = None

def get_neo4j_service() -> Neo4jService:
    """Get or create a Neo4j service instance"""
    global _neo4j_service
    if _neo4j_service is None:
        _neo4j_service = Neo4jService(
            uri=os.environ.get("NEO4J_URI", "bolt://neo4j:7687"),
            user=os.environ.get("NEO4J_USER", "neo4j"),
            password=os.environ.get("NEO4J_PASSWORD", "password")
        )
    return _neo4j_service