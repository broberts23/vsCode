"""Configuration helpers for the Identity Security Copilot.

PowerShell bridge:
- Think of this file like a strongly typed wrapper around environment variables.
- A `dataclass` is similar to defining a simple class that mainly stores values.
- `classmethod` is like a helper you call on the class itself rather than on an instance.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(slots=True)
class AppConfig:
    """Application settings loaded from environment variables."""

    azure_ai_project_endpoint: str
    azure_ai_chat_deployment: str
    azure_ai_summary_deployment: str
    azure_search_endpoint: str
    azure_search_index_name: str
    knowledge_root: Path

    @classmethod
    def from_env(cls) -> 'AppConfig':
        """Create settings from environment variables.

        PowerShell bridge:
        - This is similar to reading required variables from `$env:` and returning one config object.
        - We fail fast for required settings so mistakes show up early.
        """

        chat_deployment = _get_required_env('AZURE_AI_CHAT_DEPLOYMENT')
        summary_deployment = os.environ.get('AZURE_AI_SUMMARY_DEPLOYMENT', chat_deployment)
        knowledge_root = Path(os.environ.get('KNOWLEDGE_ROOT', './knowledge')).resolve()

        return cls(
            azure_ai_project_endpoint=_get_required_env('AZURE_AI_PROJECT_ENDPOINT'),
            azure_ai_chat_deployment=chat_deployment,
            azure_ai_summary_deployment=summary_deployment,
            azure_search_endpoint=_get_required_env('AZURE_SEARCH_ENDPOINT'),
            azure_search_index_name=os.environ.get('AZURE_SEARCH_INDEX_NAME', 'identity-security-knowledge'),
            knowledge_root=knowledge_root,
        )


def _get_required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f'{name} is required.')
    return value
