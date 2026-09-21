"""Resolve Slack signing secret from Key Vault (Azure) or env (local)."""

from __future__ import annotations

import logging

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from ara.settings import Settings

logger = logging.getLogger(__name__)


def resolve_slack_signing_secret(settings: Settings) -> str:
    if settings.slack_signing_secret:
        return settings.slack_signing_secret
    if not settings.key_vault_uri:
        return ""
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=settings.key_vault_uri, credential=credential)
    secret = client.get_secret("slack-signing-secret")
    return secret.value or ""


def resolve_slack_bot_token(settings: Settings) -> str:
    if settings.slack_bot_token:
        return settings.slack_bot_token
    if not settings.key_vault_uri:
        return ""
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=settings.key_vault_uri, credential=credential)
    secret = client.get_secret("slack-bot-token")
    return secret.value or ""
