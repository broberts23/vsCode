"""Azure AI Foundry project client helpers.

Adapted from `project-identity-security-copilot-v2`. Provides authenticated
access to the Foundry project and the model deployment.

Note: deepseek-v4-flash does NOT support tool calling, so this module is
used for single-turn completions only. The code scanning and wiki publishing
are handled in Python, not via model tool calls.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from azure.identity import DefaultAzureCredential

from src.config import AppConfig


@contextmanager
def open_project_client(settings: AppConfig) -> Iterator[Any]:
    """Open an authenticated Foundry project client."""
    from azure.ai.projects import AIProjectClient

    with DefaultAzureCredential() as credential, AIProjectClient(
        endpoint=settings.azure_ai_project_endpoint,
        credential=credential,
    ) as project_client:
        yield project_client


def list_deployment_names(settings: AppConfig) -> list[str]:
    """Return the deployment names visible from the Foundry project."""
    with open_project_client(settings) as project_client:
        return [deployment.name for deployment in project_client.deployments.list()]


def complete_with_foundry(
    system_prompt: str,
    user_input: str,
    settings: AppConfig,
) -> str:
    """Send a single-turn completion to the Foundry model deployment.

    Because deepseek-v4-flash does not support tool calling, this is a
    simple prompt→response flow. All tool-like operations (code scanning,
    REST API calls) are handled in Python before/after this call.
    """
    deployments = set(list_deployment_names(settings))
    if settings.azure_ai_chat_deployment not in deployments:
        raise RuntimeError(
            f'Configured deployment {settings.azure_ai_chat_deployment} '
            f'was not found in the Foundry project. Available: {sorted(deployments)}'
        )

    with open_project_client(settings) as project_client, \
            project_client.get_openai_client() as openai_client:
        response = openai_client.responses.create(
            model=settings.azure_ai_chat_deployment,
            instructions=system_prompt,
            input=user_input,
        )
        return response.output_text or 'No response text was returned by the model.'
