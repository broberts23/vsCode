"""Application configuration from environment variables."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Well-known Cosmos DB emulator master key (local development only).
COSMOS_EMULATOR_KEY = (
    "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw=="
)

ROLE_ADMIN = "role.admin"
ROLE_SERVICE = "role.service"
ALLOWED_API_ROLES = frozenset({ROLE_ADMIN, ROLE_SERVICE})
DELEGATED_SCOPE_NAME = "access_as_user"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    cosmos_endpoint: str = Field(default="https://localhost:8081/")
    cosmos_key: str = Field(default=COSMOS_EMULATOR_KEY)
    cosmos_database: str = Field(default="identitydb")
    cosmos_container: str = Field(default="identities")
    use_cosmos_emulator: bool = Field(default=True)

    tenant_id: str = Field(default="")
    api_client_id: str = Field(default="")
    openapi_client_id: str = Field(default="")

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @property
    def issuer(self) -> str:
        # v2 only — requires app manifest accessTokenAcceptedVersion = 2
        return f"{self.authority}/v2.0"

    @property
    def jwks_uri(self) -> str:
        return f"{self.authority}/discovery/v2.0/keys"

    @property
    def authorize_url(self) -> str:
        return f"{self.authority}/oauth2/v2.0/authorize"

    @property
    def token_url(self) -> str:
        return f"{self.authority}/oauth2/v2.0/token"

    @property
    def app_id_uri(self) -> str:
        return f"api://{self.api_client_id}"

    @property
    def access_as_user_scope(self) -> str:
        return f"{self.app_id_uri}/{DELEGATED_SCOPE_NAME}"

    @property
    def audience_values(self) -> list[str]:
        return [self.api_client_id, self.app_id_uri]

    def require_entra(self) -> None:
        missing = [
            name
            for name, value in (
                ("TENANT_ID", self.tenant_id),
                ("API_CLIENT_ID", self.api_client_id),
                ("OPENAPI_CLIENT_ID", self.openapi_client_id),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(
                "Entra settings incomplete; set " + ", ".join(missing) + " in the environment"
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
