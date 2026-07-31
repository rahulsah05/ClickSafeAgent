from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ClickSafe API"
    app_env: Literal["development", "test", "production"] = "development"
    app_version: str = "0.1.0"
    log_level: str = "INFO"
    api_v1_prefix: str = "/api/v1"

    database_url: str = "sqlite+aiosqlite:///./clicksafe.db"
    sql_echo: bool = False

    openai_api_key: str = ""
    openai_model: str = "gpt-5.6"
    openai_reasoning_effort: Literal["minimal", "low", "medium", "high"] = "medium"

    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""

    playwright_headless: bool = True
    browser_timeout_ms: int = Field(default=15_000, ge=1_000, le=120_000)
    max_redirects: int = Field(default=10, ge=0, le=20)
    max_html_bytes: int = Field(default=1_000_000, ge=10_000, le=5_000_000)
    screenshot_dir: str = "data/screenshots"
    html_dir: str = "data/html"

    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
