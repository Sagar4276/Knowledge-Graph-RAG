import os
import requests
from typing import Optional
import tempfile
from bs4 import BeautifulSoup

# Import document processing libraries conditionally
# to handle cases where they might not be installed
try:
    import PyPDF2
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

try:
    import docx2txt
    DOCX_SUPPORT = True
except ImportError:
    DOCX_SUPPORT = False

def process_document(content: bytes, filename: str) -> str:
    """
    Process a document file and extract its text content
    
    Args:
        content: Binary content of the document
        filename: Name of the uploaded file
        
    Returns:
        Extracted text content
    """
    _, ext = os.path.splitext(filename.lower())
    
    if ext == '.pdf':
        if not PDF_SUPPORT:
            raise ImportError("PyPDF2 is required for PDF processing")
        return _process_pdf(content)
    elif ext == '.docx':
        if not DOCX_SUPPORT:
            raise ImportError("docx2txt is required for DOCX processing")
        return _process_docx(content)
    elif ext == '.doc':
        # Basic support for old .doc files
        return _process_doc(content)
    elif ext == '.txt':
        return content.decode('utf-8', errors='replace')
    else:
        raise ValueError(f"Unsupported file format: {ext}")

def process_text(text: str) -> str:
    """
    Process raw text input
    
    Args:
        text: Raw text input
        
    Returns:
        Processed text
    """
    # In a more complex implementation, this could include:
    # - Text normalization
    # - Named entity pre-processing
    # - Summarization for very large texts
    return text.strip()

class URLFetchError(Exception):
    """Custom exception for URL fetch failures with proper HTTP status code semantics."""
    def __init__(self, message: str, error_type: str, url: str, status_code: int = 504, suggestion: str = None):
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.url = url
        self.status_code = status_code
        self.suggestion = suggestion or "Try pasting the text directly instead."
    
    def to_dict(self):
        return {
            "error": self.error_type,
            "message": self.message,
            "url": self.url,
            "suggestion": self.suggestion
        }


# URL class timeouts and strategies
URL_STRATEGIES = {
    "gov": {"timeout": (10, 60), "retries": 3},  # Government sites are slow
    "wiki": {"timeout": (5, 30), "retries": 2},  # Wikipedia can be slow
    "default": {"timeout": (5, 20), "retries": 2},  # Normal sites
}


def _get_url_strategy(url: str) -> dict:
    """Get the appropriate fetching strategy for a URL."""
    url_lower = url.lower()
    if ".gov" in url_lower or "cisa.gov" in url_lower or "nist.gov" in url_lower:
        return URL_STRATEGIES["gov"]
    elif "wikipedia.org" in url_lower:
        return URL_STRATEGIES["wiki"]
    return URL_STRATEGIES["default"]


def process_url(url: str) -> str:
    """
    Fetch and process content from a URL with robust error handling.
    
    Features:
    - Proper User-Agent to avoid bot blocks
    - Retries with exponential backoff
    - URL-class based timeout handling
    - Proper error classification (504/502/403/422)
    
    Args:
        url: URL to fetch content from
        
    Returns:
        Extracted text content
        
    Raises:
        URLFetchError: With proper error type and status code
    """
    import time
    
    # Professional User-Agent (required for many gov sites)
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityGraphBot/1.0; +https://github.com/security-graph-rag)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    
    strategy = _get_url_strategy(url)
    timeout = strategy["timeout"]
    max_retries = strategy["retries"]
    
    last_error = None
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            
            content_type = response.headers.get('Content-Type', '').lower()
            
            if 'text/html' in content_type:
                return _extract_text_from_html(response.text)
            elif 'application/pdf' in content_type:
                if not PDF_SUPPORT:
                    raise URLFetchError(
                        message="PDF processing is not available",
                        error_type="PDF_NOT_SUPPORTED",
                        url=url,
                        status_code=415,
                        suggestion="Install PyPDF2 or upload the PDF directly via /process/document"
                    )
                return _process_pdf(response.content)
            elif 'text/plain' in content_type:
                return response.text
            else:
                raise URLFetchError(
                    message=f"Unsupported content type: {content_type}",
                    error_type="UNSUPPORTED_CONTENT_TYPE",
                    url=url,
                    status_code=415,
                    suggestion="Only HTML, PDF, and plain text are supported"
                )
                
        except requests.exceptions.Timeout as e:
            last_error = e
            if attempt < max_retries - 1:
                # Exponential backoff
                time.sleep(2 ** attempt)
                continue
            raise URLFetchError(
                message=f"URL did not respond within {timeout[1]} seconds after {max_retries} attempts",
                error_type="URL_FETCH_TIMEOUT",
                url=url,
                status_code=504,
                suggestion="This site is slow or blocks automated requests. Try pasting the text manually."
            )
            
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response else 500
            if status == 403:
                raise URLFetchError(
                    message="Access forbidden - site blocks automated requests",
                    error_type="ACCESS_FORBIDDEN",
                    url=url,
                    status_code=403,
                    suggestion="This site blocks bots. Copy the text manually and use /process/text instead."
                )
            elif status == 404:
                raise URLFetchError(
                    message="Page not found",
                    error_type="PAGE_NOT_FOUND",
                    url=url,
                    status_code=404,
                    suggestion="Check the URL is correct"
                )
            else:
                raise URLFetchError(
                    message=f"HTTP error {status}",
                    error_type="HTTP_ERROR",
                    url=url,
                    status_code=502
                )
                
        except requests.exceptions.ConnectionError:
            raise URLFetchError(
                message="Could not connect to the server",
                error_type="CONNECTION_FAILED",
                url=url,
                status_code=502,
                suggestion="Check the URL is accessible and try again"
            )
            
        except requests.exceptions.RequestException as e:
            raise URLFetchError(
                message=str(e),
                error_type="FETCH_ERROR",
                url=url,
                status_code=502
            )

def _process_pdf(content: bytes) -> str:
    """Extract text from PDF content"""
    if not PDF_SUPPORT:
        raise ImportError("PyPDF2 is required for PDF processing")
    
    # Save content to a temporary file
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
        temp_file.write(content)
        temp_path = temp_file.name
    
    try:
        # Extract text from PDF
        with open(temp_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            text = ""
            for page_num in range(len(reader.pages)):
                page = reader.pages[page_num]
                text += page.extract_text() + "\n\n"
        return text
    finally:
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)

def _process_docx(content: bytes) -> str:
    """Extract text from DOCX content"""
    if not DOCX_SUPPORT:
        raise ImportError("docx2txt is required for DOCX processing")
    
    # Save content to a temporary file
    with tempfile.NamedTemporaryFile(suffix='.docx', delete=False) as temp_file:
        temp_file.write(content)
        temp_path = temp_file.name
    
    try:
        # Extract text from DOCX
        text = docx2txt.process(temp_path)
        return text
    finally:
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)

def _process_doc(content: bytes) -> str:
    """Basic text extraction from DOC content"""
    # This is a simplified version that doesn't actually parse DOC format
    # For production use, consider using a library like python-docx2txt or antiword
    
    # Try to extract readable text
    text = content.decode('latin-1', errors='ignore')
    
    # Remove binary garbage as much as possible
    text = ''.join(c for c in text if c.isprintable() or c in '\n\r\t')
    
    return text

def _extract_text_from_html(html_content: str) -> str:
    """Extract meaningful text content from HTML"""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Remove script and style elements
    for script in soup(["script", "style"]):
        script.extract()
    
    # Extract text
    text = soup.get_text(separator='\n')
    
    # Remove excessive newlines
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    text = '\n'.join(lines)
    
    return text