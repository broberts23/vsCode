"""Shared Azure AI Search client helpers.

PowerShell bridge:
- These helpers are the Python equivalent of wrapper functions that return ready-to-use
    SDK clients.
- Centralizing this code keeps endpoint wiring and credential creation consistent
    across indexing and query operations.
"""

from __future__ import annotations

from azure.identity import DefaultAzureCredential
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient

from src.config import AppConfig


def create_index_client(settings: AppConfig) -> SearchIndexClient:
    """Create the management client used for index creation and updates.

    PowerShell bridge:
    - This is like returning an SDK object from a helper so multiple commands can reuse
      the same creation logic.
    """

    return SearchIndexClient(
        endpoint=settings.azure_search_endpoint,
        credential=DefaultAzureCredential(),
    )


def create_search_client(settings: AppConfig) -> SearchClient:
    """Create the query client used for retrieval-time search operations.

    PowerShell bridge:
    - This is the read-side counterpart to `create_index_client`.
    - Keeping the read and write clients separate mirrors the different roles they play
      in the workflow.
    """

    return SearchClient(
        endpoint=settings.azure_search_endpoint,
        index_name=settings.azure_search_index_name,
        credential=DefaultAzureCredential(),
    )
