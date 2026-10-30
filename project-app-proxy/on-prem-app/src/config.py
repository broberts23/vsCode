"""Central configuration for the on-prem FastAPI app."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    local_debug: bool = Field(
        default=True,
        description="When True, skip all authentication (local development only).",
    )
    tenant_id: str = Field(
        default="",
        description="Microsoft Entra tenant ID used to validate token issuer and JWKS.",
    )
    api_audience: str = Field(
        default="",
        description="Expected access-token audience (app client ID or Application ID URI).",
    )
    required_api_role: str = Field(
        default="Api.Read",
        description="App role claim required for /api routes when auth is enabled.",
    )
    host: str = "0.0.0.0"
    port: int = 8000


@lru_cache
def get_settings() -> Settings:
    return Settings()
