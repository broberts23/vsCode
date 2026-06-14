"""CLI entry point for the Documentation Copilot.

Routes user prompts to the appropriate documentation action:
- "update the wiki for ABC function" → scan, generate, publish updated wiki
- "create a new wiki for XYZ function" → scan, generate, publish new wiki
- "scan and report" → scan only, print findings without publishing

Adapted from the `project-identity-security-copilot-v2` argpattern.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import AppConfig
from src.security.masking import mask_answer
from src.workflow.provenance import new_correlation_id, record_event

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
)
logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Documentation Copilot — generate Azure DevOps wiki entries from code.')
    parser.add_argument(
        '--prompt',
        required=True,
        help='Natural-language instruction (e.g. "update the wiki for ABC function").',
    )
    parser.add_argument(
        '--target',
        help='Specific function or class name to document.',
    )
    parser.add_argument(
        '--mode',
        choices=('auto', 'scan-only', 'publish'),
        default='auto',
        help='Execution mode: auto (scan+publish), scan-only, or force publish.',
    )
    args = parser.parse_args()

    settings = AppConfig.from_env()
    correlation_id = new_correlation_id()

    record_event('request_received', correlation_id, prompt=args.prompt, mode=args.mode)

    target_name = args.target or _extract_target_from_prompt(args.prompt)

    if not target_name:
        logger.warning('No target function/class could be inferred from prompt.')
        print(
            'Could not determine a target function or class from your prompt. '
            'Use --target to specify one explicitly.'
        )
        sys.exit(1)

    logger.info('Target: %s | Mode: %s', target_name, args.mode)

    if args.mode == 'scan-only':
        _handle_scan_only(target_name, settings, correlation_id)
        return

    _handle_publish(target_name, settings, correlation_id)


def _extract_target_from_prompt(prompt: str) -> str | None:
    """Heuristically extract a function or class name from the user prompt.

    Looks for patterns like:
    - "update the wiki for ABC function"
    - "create a new wiki for XYZ function"
    - "document the MyClass class"
    - "find the walk_repository function"
    - "function MyParser needs documentation"
    """
    import re

    patterns = [
        r'(?:wiki\s+for|document(?:\s+the)?|update(?:\s+the)?\s+wiki\s+for|create(?:\s+a)?(?:\s+new)?\s+wiki\s+for)\s+(\w+)',
        r'(?:function|class)\s+(\w+)',
        r'(\w+)\s+(?:function|class)',
    ]

    for pattern in patterns:
        match = re.search(pattern, prompt, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def _handle_scan_only(target_name: str, settings: AppConfig, correlation_id: str) -> None:
    """Scan the repository and print findings without publishing."""
    from src.scanner.repo_walker import scan_target, walk_repository

    record_event('scan_started', correlation_id, target=target_name)
    modules = walk_repository(settings.target_repo_root)
    matching = scan_target(target_name, modules)
    record_event(
        'scan_completed', correlation_id,
        total_modules=len(modules), matching_modules=len(matching),
    )

    if not matching:
        print(f'No code found matching target: {target_name}')
        return

    for mod in matching:
        print(f'\n--- {mod.file_path} ---')
        for func in mod.functions:
            print(f'  def {func.name}(...) -> {func.return_type or "None"}')
        for cls in mod.classes:
            print(f'  class {cls.name}')
            for method in cls.methods:
                print(f'    def {method.name}(...) -> {method.return_type or "None"}')

    print(f'\nFound {len(matching)} matching module(s).')


def _handle_publish(target_name: str, settings: AppConfig, correlation_id: str) -> None:
    """Scan, generate, and publish wiki documentation."""
    from src.ado.wiki_service import update_wiki_for_target

    record_event('publish_started', correlation_id, target=target_name)
    published = update_wiki_for_target(target_name, settings)
    record_event(
        'publish_completed', correlation_id,
        pages_published=len(published),
    )

    if published:
        output = '\n'.join(
            f'  - {settings.azure_devops_org_url}/{settings.azure_devops_project}/_wiki/wikis/{settings.azure_devops_wiki_id}?pagePath={p}'
            for p in published
        )
        print(mask_answer(
            f'Published {len(published)} wiki page(s):\n{output}'
        ))
    else:
        print(f'No wiki pages were published for target: {target_name}')


if __name__ == '__main__':
    main()
