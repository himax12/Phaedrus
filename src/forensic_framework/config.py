"""
Configuration management using Pydantic Settings.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="FORENSIC_",
        case_sensitive=False,
    )

    # Application
    app_name: str = "Forensic Framework"
    debug: bool = False
    log_level: str = "INFO"

    # Database
    database_url: str = "sqlite+aiosqlite:///./forensic.db"

    # Ollama Configuration
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    ollama_timeout: int = 120

    # Drain3 Configuration (research-backed values)
    drain_depth: int = 4  # Fixed-depth parse tree
    drain_sim_th: float = 0.4  # Similarity threshold
    drain_max_children: int = 100
    drain_max_clusters: int = 1024

    # Merkle Tree / Logchain
    evidence_block_interval_seconds: int = 60  # 1-minute blocks
    hash_algorithm: Literal["sha256", "sha512"] = "sha256"

    # Storage paths
    data_dir: Path = Path("./data")
    reports_dir: Path = Path("./reports")
    drain_state_file: Path = Path("./data/drain_state.bin")

    # API Security
    sql_readonly_mode: bool = True
    sql_blocked_keywords: list[str] = [
        "DROP",
        "TRUNCATE",
        "DELETE",
        "INSERT",
        "UPDATE",
        "GRANT",
        "REVOKE",
        "ALTER",
        "CREATE",
        "EXEC",
    ]

    def model_post_init(self, __context) -> None:
        """Ensure directories exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
