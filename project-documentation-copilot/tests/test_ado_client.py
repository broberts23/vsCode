"""Tests for the Azure DevOps wiki REST API client.

Uses mock HTTP responses to validate client behaviour without network access.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def test_get_page_returns_none_for_404() -> None:
    with patch('src.ado.auth.get_auth_header', return_value={'Authorization': 'Basic dGVzdA=='}):
        with patch('requests.Session.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response

            from src.ado.client import AdoWikiClient
            client = AdoWikiClient(
                'https://dev.azure.com/myorg', 'myproject', 'mywiki')
            result = client.get_page('API-Reference/test')

            assert result is None


def test_create_or_update_page_returns_created() -> None:
    with patch('src.ado.auth.get_auth_header', return_value={'Authorization': 'Basic dGVzdA=='}):
        with patch('requests.Session.put') as mock_put:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.headers = {'ETag': '"abc123"'}
            mock_put.return_value = mock_response

            from src.ado.client import AdoWikiClient, WikiPage
            client = AdoWikiClient(
                'https://dev.azure.com/myorg', 'myproject', 'mywiki')
            result = client.create_or_update_page(
                WikiPage(path='API-Reference/test', content='# Test'))

            assert result.status == 'created'
            assert result.version == '"abc123"'


def test_create_or_update_page_handles_error() -> None:
    import requests as req

    with patch('src.ado.auth.get_auth_header', return_value={'Authorization': 'Basic dGVzdA=='}):
        with patch('requests.Session.put') as mock_put:
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.raise_for_status.side_effect = req.HTTPError(
                'Unauthorized', response=mock_response)
            mock_put.return_value = mock_response

            from src.ado.client import AdoWikiClient, WikiPage
            client = AdoWikiClient(
                'https://dev.azure.com/myorg', 'myproject', 'mywiki')
            result = client.create_or_update_page(
                WikiPage(path='API-Reference/test', content='# Test'))

            assert result.status == 'error'
            assert result.error_message is not None
