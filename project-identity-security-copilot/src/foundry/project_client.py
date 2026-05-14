"""Helpers for working with the Azure AI Foundry project client.

PowerShell bridge:
- This file is similar to a small module that centralizes SDK client creation.
- `@contextmanager` lets one function manage setup and cleanup, similar to using `try/finally` around a shared resource.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential

from src.config import AppConfig


@contextmanager
def open_project_client(settings: AppConfig) -> Iterator[AIProjectClient]:
    """Open an authenticated Foundry project client.

    PowerShell bridge:
    - Think of this like creating a disposable SDK client and guaranteeing cleanup after use.
    """

    with DefaultAzureCredential() as credential, AIProjectClient(
        endpoint=settings.azure_ai_project_endpoint,
        credential=credential,
    ) as project_client:
        yield project_client


def list_deployment_names(settings: AppConfig) -> list[str]:
    """Return the deployment names visible from the Foundry project."""

    with open_project_client(settings) as project_client:
        return [deployment.name for deployment in project_client.deployments.list()]
