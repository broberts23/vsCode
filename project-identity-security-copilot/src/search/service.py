"""Shared Azure AI Search client helpers.

PowerShell bridge:
- These helpers are the Python equivalent of wrapper functions that return ready-to-use SDK clients.
"""

from __future__ import annotations

from azure.identity import DefaultAzureCredential
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient

from src.config import AppConfig


def create_index_client(settings: AppConfig) -> SearchIndexClient:
    return SearchIndexClient(
        endpoint=settings.azure_search_endpoint,
        credential=DefaultAzureCredential(),
    )


def create_search_client(settings: AppConfig) -> SearchClient:
    return SearchClient(
        endpoint=settings.azure_search_endpoint,
        index_name=settings.azure_search_index_name,
        credential=DefaultAzureCredential(),
    )
