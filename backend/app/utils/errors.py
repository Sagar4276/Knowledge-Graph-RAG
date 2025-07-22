from fastapi import HTTPException, status
from typing import Optional, Dict, Any

class BaseAPIException(HTTPException):
    """Base class for API exceptions"""
    def __init__(
        self,
        status_code: int,
        detail: str,
        headers: Optional[Dict[str, Any]] = None
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)

class DocumentProcessingError(BaseAPIException):
    """Exception raised when document processing fails"""
    def __init__(self, detail: str = "Error processing document"):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail
        )

class GraphExtractionError(BaseAPIException):
    """Exception raised when graph extraction fails"""
    def __init__(self, detail: str = "Error extracting knowledge graph"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )

class DatabaseError(BaseAPIException):
    """Exception raised when database operations fail"""
    def __init__(self, detail: str = "Database operation failed"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )

class ResourceNotFoundError(BaseAPIException):
    """Exception raised when a requested resource is not found"""
    def __init__(self, resource_type: str, resource_id: str):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource_type} with ID {resource_id} not found"
        )

class LLMError(BaseAPIException):
    """Exception raised when LLM operations fail"""
    def __init__(self, detail: str = "LLM operation failed"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )

class ValidationError(BaseAPIException):
    """Exception raised for input validation errors"""
    def __init__(self, detail: str = "Invalid input data"):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail
        )

# Helper functions for common error responses
def handle_document_error(e: Exception) -> DocumentProcessingError:
    """Handle document processing errors"""
    return DocumentProcessingError(f"Error processing document: {str(e)}")

def handle_graph_error(e: Exception) -> GraphExtractionError:
    """Handle graph extraction errors"""
    return GraphExtractionError(f"Error extracting knowledge graph: {str(e)}")

def handle_db_error(e: Exception) -> DatabaseError:
    """Handle database errors"""
    return DatabaseError(f"Database error: {str(e)}")

def handle_llm_error(e: Exception) -> LLMError:
    """Handle LLM errors"""
    return LLMError(f"LLM error: {str(e)}")