"""Azure DevOps REST API client.

Provides a typed HTTP client for the Azure DevOps Wiki REST API.
Handles page CRUD operations, version tracking (ETag), and error normalisation.

API reference: https://learn.microsoft.com/en-us/rest/api/azure/devops/wiki/pages
"""

from __future__ import annotations

from dataclasses import dataclass
import logging

import requests

from src.ado.auth import get_auth_header

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class WikiPage:
    path: str
    content: str
    version: str | None = None


@dataclass(slots=True)
class WikiPageResult:
    path: str
    status: str       # 'created', 'updated', 'unchanged', 'error'
    version: str | None
    error_message: str | None = None


class AdoWikiClient:
    """Client for Azure DevOps Wiki Pages REST API (v7.1)."""

    def __init__(self, org_url: str, project: str, wiki_id: str) -> None:
        org_url = org_url.rstrip('/')
        self._base_url = (
            f'{org_url}/{project}/_apis/wiki/wikis/{wiki_id}/pages'
        )
        self._session = requests.Session()
        self._session.headers.update(get_auth_header())
        self._session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        })

    def get_page(self, path: str) -> WikiPage | None:
        """Retrieve a wiki page by its path."""
        url = f'{self._base_url}?path={path}&api-version=7.1&includeContent=true'
        response = self._session.get(url)
        if response.status_code == 404:
            return None
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            logger.error('Wiki API error for %s: %s', path, exc)
            return None
        data = response.json()
        return WikiPage(
            path=path,
            content=data.get('content', ''),
            version=response.headers.get('ETag'),
        )

    def create_or_update_page(self, page: WikiPage) -> WikiPageResult:
        """Create or update a wiki page.

        If `page.version` is set, the request includes an If-Match header
        for safe concurrent editing. Otherwise, a new page is created.
        """
        path_encoded = page.path.lstrip('/')
        url = f'{self._base_url}?path={path_encoded}&api-version=7.1'
        body = {'content': page.content}
        headers: dict[str, str] = {}

        if page.version:
            headers['If-Match'] = page.version
            logger.info('Updating page: %s (version %s)', path_encoded, page.version)
        else:
            logger.info('Creating page: %s', path_encoded)

        try:
            response = self._session.put(url, json=body, headers=headers)
            response.raise_for_status()
            new_version = response.headers.get('ETag')
            is_new = response.status_code == 201
            return WikiPageResult(
                path=path_encoded,
                status='created' if is_new else 'updated',
                version=new_version,
            )
        except requests.HTTPError as exc:
            try:
                detail = exc.response.json()
                logger.error('Wiki API error for %s: %s | body: %s', path_encoded, exc, detail)
            except Exception:
                logger.error('Wiki API error for %s: %s', path_encoded, exc)
            return WikiPageResult(
                path=path_encoded,
                status='error',
                version=None,
                error_message=str(exc),
            )

    def delete_page(self, path: str) -> bool:
        """Delete a wiki page by path."""
        path_encoded = path.lstrip('/')
        url = f'{self._base_url}?path={path_encoded}&api-version=7.1'
        response = self._session.delete(url)
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
            return True
        except requests.HTTPError as exc:
            logger.error('Wiki API error deleting %s: %s', path_encoded, exc)
            return False

    def list_pages(self, recursion_level: str = 'full') -> list[dict[str, object]]:
        """List all pages in the wiki."""
        url = (
            f'{self._base_url}?api-version=7.1'
            f'&recursionLevel={recursion_level}&includeContent=false'
        )
        try:
            response = self._session.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get('subPages', []) if isinstance(data, dict) else []
        except requests.HTTPError as exc:
            logger.error('Wiki API error listing pages: %s', exc)
            return []
