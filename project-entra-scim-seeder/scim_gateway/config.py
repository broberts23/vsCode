"""Azure Key Vault / Environment integration via azure-identity."""

import logging
import os

from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


def _fetch_keyvault_secret(vault_url: str, secret_name: str) -> str | None:
    """Attempt to read a secret from Azure Key Vault using DefaultAzureCredential.

    Returns None if the SDK is unavailable or the read fails (local dev).
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault_url, credential=credential)
        return client.get_secret(secret_name).value
    except Exception:
        logger.debug("Key Vault secret fetch skipped (local dev or SDK unavailable)")
        return None


class Settings(BaseSettings):
    """Runtime configuration for the SCIM Gateway."""

    scim_bearer_token: str = "local-dev-token"

    model_config = {"env_prefix": "SCIM_", "env_file": ".env", "extra": "ignore"}


def get_settings() -> Settings:
    """Build Settings, attempting Key Vault first, falling back to env vars.

    In Azure (ACA with Managed Identity), the bearer token is read from
    Key Vault. Locally, it falls back to the SCIM_BEARER_TOKEN env var.
    """
    vault_url = os.environ.get("KEY_VAULT_URL")
    secret_name = os.environ.get("SCIM_BEARER_TOKEN_SECRET_NAME", "scim-bearer-token")

    if vault_url:
        token = _fetch_keyvault_secret(vault_url, secret_name)
        if token:
            logger.info("Loaded SCIM bearer token from Key Vault")
            return Settings(scim_bearer_token=token)

    logger.info("Using environment-based SCIM bearer token")
    return Settings()
