import re
from typing import List, Dict, Any, Optional
import html
import unicodedata
import logging

logger = logging.getLogger(__name__)

def clean_text(text: str) -> str:
    """
    Clean and normalize text
    
    Args:
        text: Input text string
        
    Returns:
        Cleaned text
    """
    if not text:
        return ""
    
    # Decode HTML entities
    text = html.unescape(text)
    
    # Normalize unicode characters
    text = unicodedata.normalize('NFKC', text)
    
    # Replace multiple whitespace with a single space
    text = re.sub(r'\s+', ' ', text)
    
    # Remove control characters
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    
    return text.strip()

def split_into_sentences(text: str) -> List[str]:
    """
    Split text into sentences
    
    Args:
        text: Input text string
        
    Returns:
        List of sentences
    """
    # Basic sentence splitting (can be improved with NLP libraries)
    sentences = re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|\!)\s', text)
    return [s.strip() for s in sentences if s.strip()]

def extract_keywords(text: str, min_length: int = 3, max_keywords: int = 10) -> List[str]:
    """
    Extract potential keywords from text
    
    Args:
        text: Input text string
        min_length: Minimum word length to consider
        max_keywords: Maximum number of keywords to return
        
    Returns:
        List of keywords
    """
    # This is a simple implementation - could be improved with NLP libraries
    # Remove common punctuation
    text = re.sub(r'[^\w\s]', ' ', text.lower())
    
    # Get word frequencies
    words = text.split()
    word_freq = {}
    
    for word in words:
        if len(word) >= min_length:
            if word in word_freq:
                word_freq[word] += 1
            else:
                word_freq[word] = 1
    
    # Sort by frequency and return top keywords
    sorted_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)
    return [word for word, _ in sorted_words[:max_keywords]]

def truncate_text(text: str, max_length: int = 10000, add_ellipsis: bool = True) -> str:
    """
    Truncate text to a maximum length
    
    Args:
        text: Input text string
        max_length: Maximum length of the output text
        add_ellipsis: Whether to add an ellipsis to truncated text
        
    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
        
    truncated = text[:max_length]
    
    # Try to truncate at sentence boundary
    last_sentence_end = max([
        truncated.rfind('.'), 
        truncated.rfind('!'), 
        truncated.rfind('?')
    ])
    
    if last_sentence_end > 0.8 * max_length:
        truncated = truncated[:last_sentence_end + 1]
        
    if add_ellipsis:
        truncated += "..."
        
    return truncated

def chunk_text(text: str, chunk_size: int = 4000, overlap: int = 100) -> List[str]:
    """
    Split text into overlapping chunks of specified size
    
    Args:
        text: Input text string
        chunk_size: Maximum size of each chunk
        overlap: Number of characters to overlap between chunks
        
    Returns:
        List of text chunks
    """
    if len(text) <= chunk_size:
        return [text]
        
    chunks = []
    start = 0
    
    while start < len(text):
        end = start + chunk_size
        
        if end >= len(text):
            chunks.append(text[start:])
            break
            
        # Try to find a good breaking point
        break_point = text.rfind('. ', start + chunk_size - overlap, end)
        
        if break_point == -1:
            break_point = text.rfind(' ', start + chunk_size - overlap, end)
            
        if break_point == -1:
            break_point = end
        else:
            break_point += 1  # Include the space after the period
            
        chunks.append(text[start:break_point])
        start = break_point - overlap  # Start with overlap
        
    return chunks

def detect_language(text: str) -> Optional[str]:
    """
    Detect the language of a text
    Simple implementation based on common words
    
    Args:
        text: Input text string
        
    Returns:
        ISO language code or None if unknown
    """
    # This is a very basic implementation
    # For production use, consider using a library like langdetect
    
    text = text.lower()
    
    # Simple language detection based on common words
    english_markers = ['the', 'and', 'that', 'have', 'for', 'not', 'with']
    spanish_markers = ['el', 'la', 'que', 'de', 'en', 'y', 'es', 'por']
    french_markers = ['le', 'la', 'les', 'de', 'en', 'et', 'est', 'pour']
    german_markers = ['der', 'die', 'das', 'und', 'ist', 'für', 'nicht']
    
    # Count occurrences
    en_count = sum(1 for word in text.split() if word in english_markers)
    es_count = sum(1 for word in text.split() if word in spanish_markers)
    fr_count = sum(1 for word in text.split() if word in french_markers)
    de_count = sum(1 for word in text.split() if word in german_markers)
    
    counts = {
        'en': en_count,
        'es': es_count,
        'fr': fr_count,
        'de': de_count
    }
    
    # Find language with highest count
    max_lang = max(counts.items(), key=lambda x: x[1])
    
    # If no significant markers found, return None
    if max_lang[1] < 2:
        return None
        
    return max_lang[0]

def remove_boilerplate(text: str) -> str:
    """
    Attempt to remove common boilerplate text
    
    Args:
        text: Input text string
        
    Returns:
        Cleaned text
    """
    # Remove common headers/footers
    patterns = [
        r'(?i)terms\s+and\s+conditions.*',
        r'(?i)privacy\s+policy.*',
        r'(?i)all\s+rights\s+reserved.*',
        r'(?i)copyright\s+\d{4}.*',
        r'(?i)confidential.*',
        r'(?i)page\s+\d+\s+of\s+\d+',
    ]
    
    for pattern in patterns:
        text = re.sub(pattern, '', text)
    
    return text.strip()