import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GroqLLM:
    """Groq API client using httpx for fast async HTTP requests."""
    
    def __init__(self):
        self.api_key = os.environ.get("GROQ_API_KEY", "")
        self.model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        
        if not self.api_key:
            raise ValueError("GROQ_API_KEY environment variable is required")
    
    def __call__(self, prompt: str, **kwargs) -> str:
        return self.invoke(prompt, **kwargs)
    
    def invoke(self, prompt: str, **kwargs) -> str:
        """Synchronous invocation using httpx."""
        try:
            import httpx
        except ImportError:
            # Fallback to requests if httpx not available
            return self._invoke_with_requests(prompt, **kwargs)
        
        logger.info(f"[LLM] Using Groq {self.model}")
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": kwargs.get("temperature", 0.2),
            "max_tokens": kwargs.get("max_tokens", 4096)
        }
        
        try:
            with httpx.Client(timeout=90.0) as client:
                response = client.post(self.base_url, headers=headers, json=data)
                response.raise_for_status()
                return response.json()["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as e:
            logger.error(f"[LLM] Groq API HTTP error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"[LLM] Groq API error: {str(e)}")
            raise
    
    def _invoke_with_requests(self, prompt: str, **kwargs) -> str:
        """Fallback using requests library."""
        import requests
        
        logger.info(f"[LLM] Using Groq {self.model} (requests fallback)")
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": kwargs.get("temperature", 0.2),
            "max_tokens": kwargs.get("max_tokens", 4096)
        }
        
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=90)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except requests.exceptions.HTTPError as e:
            logger.error(f"[LLM] Groq API HTTP error: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"[LLM] Groq API error: {str(e)}")
            raise
    
    async def ainvoke(self, prompt: str, **kwargs) -> str:
        """Async invocation for better performance."""
        import httpx
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": kwargs.get("temperature", 0.2),
            "max_tokens": kwargs.get("max_tokens", 4096)
        }
        
        async with httpx.AsyncClient(timeout=90.0) as client:
            response = await client.post(self.base_url, headers=headers, json=data)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]


class OllamaLLM:
    """Ollama local LLM client (fallback for offline use)."""
    
    def __init__(self):
        self.base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = os.environ.get("OLLAMA_MODEL", "llama3")
    
    def __call__(self, prompt: str, **kwargs) -> str:
        return self.invoke(prompt, **kwargs)
    
    def invoke(self, prompt: str, **kwargs) -> str:
        """Invoke Ollama API."""
        import requests
        
        logger.info(f"[LLM] Using Ollama {self.model} at {self.base_url}")
        
        data = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": kwargs.get("temperature", 0.2),
                "num_predict": kwargs.get("max_tokens", 4096)
            }
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=data,
                timeout=120
            )
            response.raise_for_status()
            return response.json()["response"]
        except Exception as e:
            logger.error(f"[LLM] Ollama error: {str(e)}")
            raise


def get_llm():
    """
    Factory function to get the configured LLM instance.
    
    Priority order:
    1. Groq (default - fast online inference)
    2. Ollama (fallback - local inference)
    
    Returns:
        LLM instance with invoke() method
    """
    provider = os.environ.get("LLM_PROVIDER", "groq").lower()
    
    logger.info(f"[LLM] Provider requested: {provider}")
    
    # 1. Groq API (primary - fast online inference)
    if provider == "groq":
        groq_api_key = os.environ.get("GROQ_API_KEY", "")
        if groq_api_key:
            try:
                llm = GroqLLM()
                logger.info(f"[LLM] Initialized Groq with model: {llm.model}")
                return llm
            except Exception as e:
                logger.error(f"[LLM] Failed to initialize Groq: {e}")
                if provider == "groq":
                    raise  # Re-raise if Groq was explicitly requested
        else:
            error_msg = (
                "GROQ_API_KEY is not set. Please set your Groq API key:\n"
                "  1. Get a free API key from https://console.groq.com\n"
                "  2. Set GROQ_API_KEY environment variable or add to .env file"
            )
            logger.error(f"[LLM] {error_msg}")
            raise ValueError(error_msg)
    
    # 2. Ollama (fallback - local inference)
    if provider == "ollama":
        try:
            llm = OllamaLLM()
            logger.info(f"[LLM] Initialized Ollama with model: {llm.model}")
            return llm
        except Exception as e:
            logger.error(f"[LLM] Failed to initialize Ollama: {e}")
            raise
    
    # 3. Unknown provider
    raise ValueError(
        f"Unknown LLM provider: {provider}. "
        f"Supported providers: groq, ollama"
    )