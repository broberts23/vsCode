"""Configuration helpers for the Identity Security Copilot.

PowerShell bridge:
- Think of this file like a strongly typed wrapper around environment variables.
- A `dataclass` is similar to defining a simple class that mainly stores values.
- `classmethod` is like a helper you call on the class itself rather than on an
    instance.
- Centralizing config in one place is similar to building a single `$script:` config
    object instead of scattering environment access across the whole script.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(slots=True)
class AppConfig:
    """Application settings loaded from environment variables.

    PowerShell bridge:
    - This dataclass acts like a compact settings object with fixed properties.
    - Each field corresponds to one runtime value the copilot needs in order to run.
    """

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
        - Keeping this logic in a class method makes startup code look like a single
            `New-Object` style construction step rather than a pile of individual reads.
        """

        # Optional values are resolved first so we can reuse them in the returned object.
        chat_deployment = _get_required_env('AZURE_AI_CHAT_DEPLOYMENT')
        summary_deployment = os.environ.get(
            'AZURE_AI_SUMMARY_DEPLOYMENT', chat_deployment)
        knowledge_root = Path(os.environ.get(
            'KNOWLEDGE_ROOT', './knowledge')).resolve()

        # The constructor call is the Python equivalent of returning a custom object
        # with named properties already populated.
        return cls(
            azure_ai_project_endpoint=_get_required_env(
                'AZURE_AI_PROJECT_ENDPOINT'),
            azure_ai_chat_deployment=chat_deployment,
            azure_ai_summary_deployment=summary_deployment,
            azure_search_endpoint=_get_required_env('AZURE_SEARCH_ENDPOINT'),
            azure_search_index_name=os.environ.get(
                'AZURE_SEARCH_INDEX_NAME', 'identity-security-knowledge'),
            knowledge_root=knowledge_root,
        )


def _get_required_env(name: str) -> str:
    """Read a required environment variable and raise a clear error if it is missing.

    PowerShell bridge:
    - This is like a helper that throws immediately when `$env:NAME` is empty.
    - It keeps the rest of the code simpler because callers do not need to repeat the
      same validation logic everywhere.
    """

    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f'{name} is required.')
    return value
