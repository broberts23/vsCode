"""Configuration helpers for the Documentation Copilot.

Adapted from the `project-identity-security-copilot-v2` AppConfig contract.
Centralizes all runtime settings loaded from environment variables.
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
    azure_devops_org_url: str
    azure_devops_project: str
    azure_devops_wiki_id: str
    target_repo_root: Path

    @classmethod
    def from_env(cls) -> AppConfig:
        chat_deployment = os.environ.get(
            'AZURE_AI_CHAT_DEPLOYMENT', 'deepseek-v4-flash')
        target_repo_root = Path(os.environ.get(
            'TARGET_REPO_ROOT', '.')).resolve()

        return cls(
            azure_ai_project_endpoint=_get_required_env(
                'AZURE_AI_PROJECT_ENDPOINT'),
            azure_ai_chat_deployment=chat_deployment,
            azure_devops_org_url=_get_required_env('AZURE_DEVOPS_ORG_URL'),
            azure_devops_project=_get_required_env('AZURE_DEVOPS_PROJECT'),
            azure_devops_wiki_id=os.environ.get(
                'AZURE_DEVOPS_WIKI_ID', 'myproject.wiki'),
            target_repo_root=target_repo_root,
        )


def _get_required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f'{name} is required.')
    return value
