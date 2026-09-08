import os
import tempfile
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # App
    PROJECT_NAME: str = "LineSec 2+ Core"
    VERSION: str = "2.0.0"
    API_PREFIX: str = "/api"
    DEV_MODE: bool = Field(default=True, description="Enables local permissive development mode")

    # Database
    DATABASE_URL: str = Field(
        default="sqlite:///./linesec.db",
        description="PostgreSQL or SQLite database connection URL"
    )

    # Security & CORS
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000"],
        description="Allowed CORS origin domains"
    )
    API_SECRET_KEY: str = Field(
        default="linesec-dev-secret-key-change-in-production",
        description="Secret key for JWT/API key authentication"
    )

    # AI Integration
    GEMINI_API_KEY: str = Field(default="", description="Google Gemini API key")
    OLLAMA_BASE_URL: str = Field(default="http://localhost:11434", description="Ollama API base URL")

    # GitHub Remediation
    GITHUB_TOKEN: str = Field(default="", description="GitHub personal access token")
    TARGET_REPO: str = Field(default="", description="Target GitHub repository (Owner/Repo)")

    # Workspace
    WORKSPACE_ROOT: str = Field(
        default_factory=lambda: os.path.join(tempfile.gettempdir(), "linesec_workspaces"),
        description="Isolated local directory for repository operations and tests"
    )

settings = Settings()
