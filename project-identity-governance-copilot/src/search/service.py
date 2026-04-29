"""Centralize Azure AI Search connection details.

PowerShell bridge:
- These helpers play the same role as reusable wrapper functions around SDK client construction.
- `DefaultAzureCredential` is a credential chain object, not the token itself.
"""

from __future__ import annotations

import os

from azure.identity import DefaultAzureCredential
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient


def get_search_endpoint() -> str:
    # `RuntimeError` here is just a fast, explicit failure when required configuration is missing.
    endpoint = os.environ.get("AZURE_SEARCH_ENDPOINT")
    if not endpoint:
        raise RuntimeError("AZURE_SEARCH_ENDPOINT is required.")
    return endpoint


def get_index_name() -> str:
    return os.environ.get("AZURE_SEARCH_INDEX_NAME", "identity-governance-documents")


def get_credential() -> DefaultAzureCredential:
    # The same credential builder is reused by both the index-management and query clients.
    return DefaultAzureCredential()


def create_index_client() -> SearchIndexClient:
    return SearchIndexClient(endpoint=get_search_endpoint(), credential=get_credential())


def create_search_client() -> SearchClient:
    return SearchClient(
        endpoint=get_search_endpoint(),
        index_name=get_index_name(),
        credential=get_credential(),
    )