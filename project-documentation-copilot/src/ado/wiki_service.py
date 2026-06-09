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
from src.scanner.repo_walker import scan_target, walk_repository

logger = logging.getLogger(__name__)


def update_wiki_for_target(
    target_name: str,
    settings: AppConfig,
) -> list[str]:
    """Scan, generate, and publish wiki documentation for a specific target.

    Returns a list of wiki page paths that were created or updated.
    """
    from src.wiki.generator import generate_wiki_content

    modules = walk_repository(settings.target_repo_root)
    matching = scan_target(target_name, modules)
    if not matching:
        logger.warning('No code found matching target: %s', target_name)
        return []

    client = AdoWikiClient(
        org_url=settings.azure_devops_org_url,
        project=settings.azure_devops_project,
        wiki_id=settings.azure_devops_wiki_id,
    )

    published: list[str] = []
    for mod in matching:
        content = generate_wiki_content(mod, settings)
        path = _build_wiki_page_path(mod, target_name)
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


def _build_wiki_page_path(module_info: 'ModuleInfo', target_name: str) -> str:
    """Build the wiki page path for a given module and target."""
    file_stem = module_info.file_path.replace('\\', '/').split('/')[-1].replace('.py', '')
    return f'API-Reference/{target_name}/{file_stem}'
