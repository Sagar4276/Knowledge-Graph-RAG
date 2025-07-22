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

def process_url(url: str) -> str:
    """
    Fetch and process content from a URL
    
    Args:
        url: URL to fetch content from
        
    Returns:
        Extracted text content
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise exception for HTTP errors
        
        content_type = response.headers.get('Content-Type', '').lower()
        
        if 'text/html' in content_type:
            return _extract_text_from_html(response.text)
        elif 'application/pdf' in content_type:
            if not PDF_SUPPORT:
                raise ImportError("PyPDF2 is required for PDF processing")
            return _process_pdf(response.content)
        elif 'text/plain' in content_type:
            return response.text
        else:
            raise ValueError(f"Unsupported content type: {content_type}")
    except requests.RequestException as e:
        raise ValueError(f"Error fetching URL: {str(e)}")

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