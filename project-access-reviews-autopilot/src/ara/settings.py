from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root: src/ara/settings.py → parents[2]
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ENV_FILE = _PROJECT_ROOT / ".env"

# Published well-known keys for the Linux Docker emulator (not Azure secrets).
_OBSOLETE_COSMOS_EMULATOR_KEY = (
    "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2Dxhs2jLeIqFDt4v4Mh9Cz6Q8MwZAIJwQPwSUfFlAKEQ=="
)
_COSMOS_EMULATOR_KEY = (
    "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw=="
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE) if _ENV_FILE.is_file() else ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    ara_environment: str = "local"
    ara_auth_bypass: bool = False

    cosmos_endpoint: str = ""
    cosmos_key: str = ""  # local emulator only; never set in Azure
    cosmos_database: str = "ara"
    cosmos_container: str = "correlations"

    service_bus_fully_qualified_namespace: str = ""
    service_bus_connection_string: str = ""  # emulator only
    service_bus_topic: str = "review-work"
    service_bus_subscription_notify: str = "slack-notify"
    service_bus_subscription_apply: str = "apply-decision"

    key_vault_uri: str = ""
    slack_bot_token: str = ""
    slack_signing_secret: str = ""
    slack_app_token: str = ""
    slack_channel_id: str = ""
    slack_socket_mode: bool = False

    entra_tenant_id: str = ""
    entra_api_client_id: str = ""
    entra_spa_client_id: str = ""
    entra_api_audience: str = "api://access-reviews-autopilot"
    entra_required_scope: str = "access_as_user"

    fixtures_dir: str = "config/simulated-events"
    api_base_url: str = "http://localhost:8080"
    applicationinsights_connection_string: str = ""

    @field_validator("cosmos_key")
    @classmethod
    def _upgrade_obsolete_emulator_key(cls, value: str) -> str:
        if value == _OBSOLETE_COSMOS_EMULATOR_KEY:
            return _COSMOS_EMULATOR_KEY
        return value

    @property
    def fixtures_path(self) -> Path:
        return Path(self.fixtures_dir)

    @property
    def use_cosmos_emulator(self) -> bool:
        return bool(self.cosmos_key)

    @property
    def use_service_bus_emulator(self) -> bool:
        return bool(self.service_bus_connection_string)


@lru_cache
def get_settings() -> Settings:
    return Settings()
