"""Application configuration from environment variables."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Well-known Cosmos DB emulator master key (local development only).
COSMOS_EMULATOR_KEY = (
    "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw=="
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    cosmos_endpoint: str = Field(default="https://localhost:8081/")
    cosmos_key: str = Field(default=COSMOS_EMULATOR_KEY)
    cosmos_database: str = Field(default="identitydb")
    cosmos_container: str = Field(default="identities")
    use_cosmos_emulator: bool = Field(default=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
