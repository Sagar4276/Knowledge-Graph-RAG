import os
from pydantic_settings import BaseSettings
from typing import List
from dotenv import load_dotenv
from pydantic import Field

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    """Application settings"""

    # API settings
    api_prefix: str = "/api"
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    cors_origins: List[str] = Field(default=["*"])
    api_timeout: int = Field(default=120, env="API_TIMEOUT")

    # Neo4j settings
    neo4j_uri: str = Field(default="bolt://neo4j:7687", env="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", env="NEO4J_USER")
    neo4j_password: str = Field(default="password", env="NEO4J_PASSWORD")

    # LLM settings
    llm_provider: str = Field(default="ollama", env="LLM_PROVIDER")  # "ollama", "groq", or "gemini"
    # Only keep Ollama and Groq (and optionally Gemini/Google)
    ollama_base_url: str = Field(default="http://localhost:11434", env="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="llama3", env="OLLAMA_MODEL")

    groq_api_key: str = Field(default="", env="GROQ_API_KEY")
    groq_model: str = Field(default="mixtral-8x7b-32768", env="GROQ_MODEL")

    # Gemini/Google
    google_api_key: str = Field(default="", env="GOOGLE_API_KEY")
    gemini_model: str = Field(default="gemini-pro", env="GEMINI_MODEL")

    # Removed OpenAI and Anthropic keys/settings

    # Document processing settings
    max_file_size_mb: int = Field(default=10)
    supported_file_types: List[str] = Field(
        default=[".pdf", ".docx", ".doc", ".txt"]
    )

    # Graph extraction settings
    max_text_length: int = Field(default=10000)

    class Config:
        env_file = ".env"
        case_sensitive = False

# Create settings instance
settings = Settings()

# Additional configuration constants
VERSION = "1.0.0"
PROJECT_NAME = "Knowledge Graph RAG Dashboard"