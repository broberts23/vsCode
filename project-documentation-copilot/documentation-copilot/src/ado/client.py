"""Azure DevOps REST API client.

Provides a typed HTTP client for the Azure DevOps Wiki REST API.
Handles page CRUD operations, version tracking (ETag), and error normalisation.

API reference: https://learn.microsoft.com/en-us/rest/api/azure/devops/wiki/pages
"""

from __future__ import annotations

from dataclasses import dataclass
import logging

import requests

from src.ado.auth import (
    ManagedIdentityAuth,
    build_session_auth,
    get_auth_header,
    get_bearer_token,
)

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
        # Allow one redirect. The ADO API returns 302 → sign-in page on auth
        # failure, and we need to follow it once to detect that the final
        # response is HTML (the sign-in page itself). Set to 0 would raise
        # TooManyRedirects before we can inspect the response body.
        self._session.max_redirects = 1

        # Three-tier auth: service principal via Key Vault (production),
        # managed identity direct (fallback), or PAT Basic auth (local dev).
        # The service principal path is preferred when Key Vault is
        # configured because the platform-assigned managed identity is
        # not reliably recognized by Azure DevOps (VS403283).
        auth_handler, auth_description = build_session_auth()
        logger.info('Using %s for Azure DevOps auth', auth_description)
        self._session.auth = auth_handler

        self._session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        })

    @staticmethod
    def _is_html_response(response: requests.Response) -> bool:
        """Return True if the response body is HTML rather than JSON.

        The ADO API returns the sign-in page HTML (Content-Type: text/html)
        when authentication fails or the request URL is wrong. Treating this
        as a successful JSON response silently reports success while
        creating nothing.
        """
        content_type = response.headers.get('Content-Type', '')
        return 'text/html' in content_type.lower()

    def get_page(self, path: str) -> WikiPage | None:
        """Retrieve a wiki page by its path."""
        url = f'{self._base_url}?path={path}&api-version=7.1&includeContent=true'
        try:
            response = self._session.get(url)
        except requests.exceptions.TooManyRedirects as exc:
            logger.error(
                'Too many redirects checking %s | '
                'identity may lack ADO access — verify the agent identity '
                '(managed identity or service principal) is added as a user '
                'in Azure DevOps with Wiki Read & Write permissions',
                path,
            )
            return None
        if self._is_html_response(response):
            logger.error(
                'Wiki API returned HTML (auth failure) for %s | '
                'status: %s | the agent identity may not be added as a user '
                'in Azure DevOps, or lacks Wiki Read & Write permissions',
                path, response.status_code,
            )
            return None
        if response.status_code == 404:
            return None
        if self._is_html_response(response):
            logger.error(
                'Wiki API returned HTML (auth failure) for %s | '
                'status: %s | the agent managed identity may not be added '
                'as a user in Azure DevOps, or lacks Wiki Read & Write permissions',
                path, response.status_code,
            )
            return None
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            logger.error('Wiki API error for %s: %s | body: %s', path, exc, response.text[:500])
            return None
        try:
            data = response.json()
        except (ValueError, requests.exceptions.JSONDecodeError) as exc:
            logger.error('Wiki API returned non-JSON for %s: %s | body: %s', path, exc, response.text[:500])
            return None
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
        except requests.exceptions.TooManyRedirects:
            logger.error(
                'Too many redirects creating/updating %s | '
                'identity may lack ADO access — verify the agent identity '
                '(managed identity or service principal) is added as a user '
                'in Azure DevOps with Wiki Read & Write permissions',
                path_encoded,
            )
            return WikiPageResult(
                path=path_encoded,
                status='error',
                version=None,
                error_message='Auth failure: too many redirects (identity may lack ADO access)',
            )

        if self._is_html_response(response):
            logger.error(
                'Wiki API returned HTML (auth failure) for PUT %s | '
                'status: %s | the agent identity may not be added as a user '
                'in Azure DevOps, or lacks Wiki Read & Write permissions',
                path_encoded, response.status_code,
            )
            return WikiPageResult(
                path=path_encoded,
                status='error',
                version=None,
                error_message='Auth failure: received HTML sign-in page instead of API response',
            )

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            logger.error('Wiki API error for %s: %s | body: %s', path_encoded, exc, response.text[:500])
            return WikiPageResult(
                path=path_encoded,
                status='error',
                version=None,
                error_message=str(exc),
            )

        new_version = response.headers.get('ETag')
        is_new = response.status_code == 201
        return WikiPageResult(
            path=path_encoded,
            status='created' if is_new else 'updated',
            version=new_version,
        )

    def delete_page(self, path: str) -> bool:
        """Delete a wiki page by path."""
        path_encoded = path.lstrip('/')
        url = f'{self._base_url}?path={path_encoded}&api-version=7.1'
        response = self._session.delete(url)
        if response.status_code == 404:
            return False
        if self._is_html_response(response):
            logger.error(
                'Wiki API returned HTML (auth failure) for DELETE %s | '
                'check the agent identity is added as a user in Azure DevOps',
                path_encoded,
            )
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
            if self._is_html_response(response):
                logger.error(
                    'Wiki API returned HTML (auth failure) for list_pages | '
                    'check the agent identity is added as a user in Azure DevOps',
                )
                return []
            response.raise_for_status()
            data = response.json()
            return data.get('subPages', []) if isinstance(data, dict) else []
        except requests.HTTPError as exc:
            logger.error('Wiki API error listing pages: %s', exc)
            return []
