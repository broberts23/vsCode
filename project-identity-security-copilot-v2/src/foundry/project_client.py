"""Helpers for working with the Azure AI Foundry project client.

PowerShell bridge:
- This file is similar to a small module that centralizes SDK client creation.
- `@contextmanager` lets one function manage setup and cleanup, similar to using
    `try/finally` around a shared resource.
- Keeping the client creation here avoids repeating the same endpoint and credential
    wiring in every feature module.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from azure.identity import DefaultAzureCredential

from src.config import AppConfig


@contextmanager
def open_project_client(settings: AppConfig) -> Iterator[Any]:
    """Open an authenticated Foundry project client.

    PowerShell bridge:
        - Think of this like creating a disposable SDK client and guaranteeing cleanup
            after use.
        - The `with` statement is the Python equivalent of wrapping object lifetime in a
            `try/finally` block.
    """

    # DefaultAzureCredential tries the current developer identity first and then other
    # supported sources, which keeps local and hosted execution paths aligned.
    from azure.ai.projects import AIProjectClient

    with DefaultAzureCredential() as credential, AIProjectClient(
        endpoint=settings.azure_ai_project_endpoint,
        credential=credential,
    ) as project_client:
        yield project_client


def list_deployment_names(settings: AppConfig) -> list[str]:
    """Return the deployment names visible from the Foundry project.

    PowerShell bridge:
    - This is like querying a service for a collection of items and projecting just
        the property you care about.
    """

    with open_project_client(settings) as project_client:
        # The list comprehension keeps the data flow direct: ask the service, then
        # pull back only the deployment name field.
        return [deployment.name for deployment in project_client.deployments.list()]
