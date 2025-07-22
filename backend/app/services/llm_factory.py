import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_llm():
    provider = os.environ.get("LLM_PROVIDER", "ollama").lower()
    model_name = os.environ.get("OLLAMA_MODEL", "llama3")

    logger.info(f"[LLM] Provider requested: {provider}")

    # 1. Groq API (OpenAI-compatible endpoint)
    if provider == "groq" and os.environ.get("GROQ_API_KEY"):
        try:
            import httpx  # Modern replacement for requests
            import asyncio
            from typing import Any, Dict

            class GroqLLM:
                def __init__(self):
                    self.api_key = os.environ["GROQ_API_KEY"]
                    self.model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
                    self.base_url = "https://api.groq.com/openai/v1/chat/completions"
                
                def __call__(self, prompt: str, **kwargs) -> str:
                    logger.info(f"[LLM] Using Groq {self.model} (ONLINE MODE)")
                    print(f"[LLM] Groq {self.model} loaded (ONLINE MODE)")
                    
                    headers = {"Authorization": f"Bearer {self.api_key}"}
                    data = {
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": kwargs.get("temperature", 0.2),
                        "max_tokens": kwargs.get("max_tokens", 2048)
                    }
                    
                    try:
                        with httpx.Client() as client:
                            response = client.post(self.base_url, headers=headers, json=data, timeout=60.0)
                            response.raise_for_status()
                            return response.json()["choices"][0]["message"]["content"]
                    except Exception as e:
                        logger.error(f"[LLM] Groq API error: {str(e)}")
                        raise
                
                def invoke(self, prompt: str, **kwargs) -> str:
                    return self(prompt, **kwargs)
                
                async def ainvoke(self, prompt: str, **kwargs) -> str:
                    """Async version for better performance"""
                    headers = {"Authorization": f"Bearer {self.api_key}"}
                    data = {
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": kwargs.get("temperature", 0.2),
                        "max_tokens": kwargs.get("max_tokens", 2048)
                    }
                    
                    async with httpx.AsyncClient() as client:
                        response = await client.post(self.base_url, headers=headers, json=data, timeout=60.0)
                        response.raise_for_status()
                        return response.json()["choices"][0]["message"]["content"]
            
            logger.info(f"[LLM] Groq {os.environ.get('GROQ_MODEL', 'llama-3.3-70b-versatile')} loaded (ONLINE MODE)")
            print(f"[LLM] Groq {os.environ.get('GROQ_MODEL', 'llama-3.3-70b-versatile')} loaded (ONLINE MODE)")
            return GroqLLM()
            
        except ImportError:
            logger.warning("[LLM] httpx package not installed. Falling back to requests.")
            try:
                import requests
                
                class GroqLLMFallback:
                    def __init__(self):
                        self.api_key = os.environ["GROQ_API_KEY"]
                        self.model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
                    
                    def __call__(self, prompt: str, **kwargs) -> str:
                        logger.info(f"[LLM] Using Groq {self.model} (ONLINE MODE - Fallback)")
                        print(f"[LLM] Groq {self.model} loaded (ONLINE MODE - Fallback)")
                        
                        endpoint = "https://api.groq.com/openai/v1/chat/completions"
                        headers = {"Authorization": f"Bearer {self.api_key}"}
                        data = {
                            "model": self.model,
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": kwargs.get("temperature", 0.2),
                            "max_tokens": kwargs.get("max_tokens", 2048)
                        }
                        
                        try:
                            resp = requests.post(endpoint, headers=headers, json=data, timeout=60)
                            resp.raise_for_status()
                            return resp.json()["choices"][0]["message"]["content"]
                        except Exception as e:
                            logger.error(f"[LLM] Groq API error: {str(e)}")
                            raise
                    
                    def invoke(self, prompt: str, **kwargs) -> str:
                        return self(prompt, **kwargs)
                
                return GroqLLMFallback()
                
            except ImportError:
                logger.warning("[LLM] Neither httpx nor requests package installed.")

    # 2. Default: Ollama (local) with modern imports
    try:
        # Try the newest LangChain Ollama import first
        try:
            from langchain_ollama import OllamaLLM
            logger.info("[LLM] Using langchain-ollama (newest)")
        except ImportError:
            try:
                from langchain_community.llms import Ollama as OllamaLLM
                logger.info("[LLM] Using langchain-community (fallback)")
            except ImportError:
                # Last resort - old import style
                from langchain.llms import Ollama as OllamaLLM
                logger.warning("[LLM] Using legacy langchain import")
        
        base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        
        # Create Ollama instance with modern parameters
        ollama_params = {
            "model": model_name,
            "base_url": base_url,
            "temperature": 0.1,
            "num_ctx": 4096,  # Increased context window
            "num_predict": 1024,  # Increased prediction tokens
            "repeat_penalty": 1.1,
            "top_k": 40,
            "top_p": 0.9,
            "timeout": 120,  # 2 minutes timeout
        }
        
        # Remove parameters that might not be supported in newer versions
        try:
            llm = OllamaLLM(**ollama_params)
        except TypeError as e:
            # If some parameters are not supported, try with basic parameters
            logger.warning(f"[LLM] Some Ollama parameters not supported: {e}")
            basic_params = {
                "model": model_name,
                "base_url": base_url,
                "temperature": 0.1
            }
            llm = OllamaLLM(**basic_params)
        
        logger.info(f"[LLM] Using Ollama (OFFLINE MODE) with model: {model_name} at {base_url}")
        print(f"[LLM] Ollama loaded (OFFLINE MODE) with model: {model_name} at {base_url}")
        
        return llm
        
    except ImportError as e:
        logger.error(f"[LLM] Could not import Ollama LLM: {str(e)}")
        
        # Try OpenAI as final fallback if API key is available
        if os.environ.get("OPENAI_API_KEY"):
            try:
                from openai import OpenAI
                
                class OpenAILLM:
                    def __init__(self):
                        self.client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
                        self.model = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo")
                    
                    def __call__(self, prompt: str, **kwargs) -> str:
                        logger.info(f"[LLM] Using OpenAI {self.model} (ONLINE MODE - Fallback)")
                        
                        response = self.client.chat.completions.create(
                            model=self.model,
                            messages=[{"role": "user", "content": prompt}],
                            temperature=kwargs.get("temperature", 0.2),
                            max_tokens=kwargs.get("max_tokens", 1024)
                        )
                        return response.choices[0].message.content
                    
                    def invoke(self, prompt: str, **kwargs) -> str:
                        return self(prompt, **kwargs)
                
                logger.info("[LLM] OpenAI loaded as final fallback")
                return OpenAILLM()
                
            except ImportError:
                logger.warning("[LLM] OpenAI package not available")
        
        raise ImportError(
            "Could not import any LLM. Please install one of:\n"
            "- langchain-ollama (recommended for Ollama)\n"
            "- langchain-community (fallback for Ollama)\n"
            "- httpx (for Groq with better performance)\n"
            "- requests (for Groq fallback)\n"
            "- openai (for OpenAI fallback)\n"
            "Or set up appropriate API keys (GROQ_API_KEY, OPENAI_API_KEY)"
        )