"""Wiki service orchestration.

Coordinates the full documentation lifecycle:
1. Scan repository for code changes
2. Generate wiki markdown content via the Foundry LLM
3. Publish to Azure DevOps Wiki via the ADO client
"""

from __future__ import annotations

import logging

from src.ado.client import AdoWikiClient, WikiPage
from src.config import AppConfig
from src.scanner.python_parser import ModuleInfo
from src.scanner.repo_walker import scan_target, walk_repository

logger = logging.getLogger(__name__)


def update_wiki_for_target(
    target_name: str,
    settings: AppConfig,
) -> list[str]:
    """Scan, generate, and publish wiki documentation for a specific target.

    Returns a list of wiki page paths that were created or updated.
    """
    modules = walk_repository(settings.target_repo_root)
    matching = scan_target(target_name, modules)
    if not matching:
        logger.warning('No code found matching target: %s', target_name)
        return []

    return _publish_modules(matching, target_name, settings)


def update_wiki_for_target_from_data(
    target_name: str,
    modules: list[ModuleInfo],
    settings: AppConfig,
) -> list[str]:
    """Generate and publish wiki documentation from pre-scanned module data.

    The caller (e.g. a local CLI) has already scanned the repository and
    extracted module metadata. This function skips the scan step and goes
    directly to generation + publishing.

    Returns a list of wiki page paths that were created or updated.
    """
    matching = scan_target(target_name, modules)
    if not matching:
        logger.warning('No code found matching target: %s', target_name)
        return []

    return _publish_modules(matching, target_name, settings)


def _publish_modules(
    modules: list[ModuleInfo],
    target_name: str,
    settings: AppConfig,
) -> list[str]:
    """Core publish logic: generate content and push to ADO Wiki."""
    from src.wiki.generator import generate_wiki_content

    client = AdoWikiClient(
        org_url=settings.azure_devops_org_url,
        project=settings.azure_devops_project,
        wiki_id=settings.azure_devops_wiki_id,
    )

    published: list[str] = []
    for mod in modules:
        content = generate_wiki_content(mod, settings)
        path = _build_wiki_page_path(mod, target_name)

        _ensure_ancestor_pages(client, path)

        existing = client.get_page(path)
        page = WikiPage(
            path=path,
            content=content,
            version=existing.version if existing else None,
        )
        result = client.create_or_update_page(page)
        if result.status in ('created', 'updated'):
            published.append(result.path)
            logger.info('Published wiki page: %s (%s)', result.path, result.status)
        else:
            logger.error(
                'Failed to publish %s: %s', result.path, result.error_message)

    return published


def _ensure_ancestor_pages(client: AdoWikiClient, leaf_path: str) -> None:
    """Create any missing ancestor pages in the wiki hierarchy.

    Azure DevOps Wiki requires all ancestor pages to exist before a child
    page can be created (returns WikiAncestorPageNotFoundException otherwise).
    Walks the path from the root down to the leaf's parent and creates any
    missing pages with minimal index content.
    """
    parts = leaf_path.strip('/').split('/')
    for i in range(1, len(parts)):
        ancestor_path = '/' + '/'.join(parts[:i])
        try:
            existing = client.get_page(ancestor_path)
        except Exception as exc:
            logger.error('Unexpected error checking ancestor %s: %s', ancestor_path, exc)
            continue
        if existing is not None:
            continue
        title = parts[i - 1]
        content = (
            f'# {title}\n\n'
            f'Index page for `{ancestor_path}`. '
            'Module pages appear below this folder.\n'
        )
        result = client.create_or_update_page(
            WikiPage(path=ancestor_path, content=content))
        if result.status in ('created', 'updated'):
            logger.info('Created ancestor page: %s', result.path)
        else:
            logger.error(
                'Failed to create ancestor %s: %s',
                result.path, result.error_message,
            )


def _build_wiki_page_path(module_info: 'ModuleInfo', target_name: str) -> str:
    """Build the wiki page path for a given module and target."""
    file_stem = module_info.file_path.replace('\\', '/').split('/')[-1].replace('.py', '')
    return f'/API-Reference/{target_name}/{file_stem}'
