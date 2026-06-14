r"""Documentation Copilot — Local CLI.

Scans a local Python repository, packages the code metadata, and delegates
wiki generation + ADO publishing to the Foundry Hosted Agent via ``azd ai agent
invoke``. The scan data is base64-encoded into the prompt, and the agent detects
the ``__SCAN__:`` marker, deserialises the payload, and proceeds with wiki
generation using the service principal auth already wired inside Foundry.

Usage:
    python wikicopilot.py "update the wiki for walk_repository function"
    python wikicopilot.py --target AdoWikiClient --mode publish
    python wikicopilot.py --repo C:\git\myproject "document parse_config"

No PAT, Key Vault, or LLM credentials are needed locally. The Foundry agent
handles everything beyond the local file-system scan.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
AGENT_DIR = PROJECT_ROOT / 'documentation-copilot'
sys.path.insert(0, str(AGENT_DIR))

from src.ado.module_serializer import module_info_to_dict
from src.app import _extract_target_from_prompt
from src.scanner.repo_walker import scan_target, walk_repository

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
)
logger = logging.getLogger('wikicopilot')


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description='Scan local Python code and publish wiki docs via Foundry.',
    )
    parser.add_argument(
        'prompt', nargs='?',
        help='Natural-language instruction (e.g. "update the wiki for MyFunction").',
    )
    parser.add_argument(
        '--target', '-t',
        help='Function or class name (overrides prompt extraction).',
    )
    parser.add_argument(
        '--mode', '-m',
        choices=('auto', 'scan-only', 'publish'),
        default='auto',
    )
    parser.add_argument(
        '--repo', '-r',
        default='.',
        help='Repository root to scan (default: current directory).',
    )
    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='Output raw JSON response.',
    )
    args = parser.parse_args()

    prompt = args.prompt or ''
    target_name = args.target or _extract_target_from_prompt(prompt)

    if not target_name:
        logger.error(
            'Could not determine target. Use --target to specify one explicitly.'
        )
        sys.exit(1)

    repo_root = Path(args.repo).resolve()
    logger.info('Target: %s  |  Repo: %s  |  Mode: %s', target_name, repo_root, args.mode)
    _run_pipeline(target_name, repo_root, args.mode, args.json)


def _run_pipeline(
    target_name: str,
    repo_root: Path,
    mode: str,
    raw_json: bool,
) -> None:
    logger.info('Scanning %s ...', repo_root)
    modules = walk_repository(repo_root)
    logger.info('Discovered %d module(s)', len(modules))

    matching = scan_target(target_name, modules)
    if not matching:
        logger.warning('No code found matching target: %s', target_name)
        return

    logger.info(
        'Found %d matching module(s) for "%s":',
        len(matching), target_name,
    )
    for mod in matching:
        names = ', '.join(
            [f'def {f.name}' for f in mod.functions]
            + [f'class {c.name}' for c in mod.classes]
        )
        logger.info('  %s → %s', mod.file_path, names)

    if mode == 'scan-only':
        _print_scan_only(matching, target_name)
        return

    scan_data = [module_info_to_dict(m) for m in matching]

    _invoke_agent(target_name, scan_data, mode, raw_json)


def _invoke_agent(
    target_name: str,
    scan_data: list[dict[str, object]],
    mode: str,
    raw_json: bool,
) -> None:
    payload = json.dumps({
        'target': target_name,
        'scan_data': scan_data,
        'mode': mode,
    })
    encoded = base64.b64encode(payload.encode('utf-8')).decode('ascii')
    prompt = f'__SCAN__:{encoded}'

    logger.info(
        'Invoking Foundry agent (%d module(s), %d bytes scan data) ...',
        len(scan_data), len(payload),
    )

    result = subprocess.run(
        ['azd', 'ai', 'agent', 'invoke', prompt],
        capture_output=True,
        text=True,
        cwd=str(AGENT_DIR),
        timeout=600,
    )

    if result.returncode != 0:
        logger.error('azd ai agent invoke failed (rc=%d): %s',
                     result.returncode, result.stderr[:500])
        return

    stdout = result.stdout.strip()
    if raw_json:
        print(stdout)
        return

    _print_agent_response(stdout, target_name)


def _print_agent_response(stdout: str, target_name: str) -> None:
    """Parse and pretty-print the agent's JSON response."""
    try:
        response = json.loads(stdout)
    except json.JSONDecodeError:
        print(stdout)
        return

    status = response.get('status', 'unknown')
    pages = response.get('pages', [])

    if status == 'success' and pages:
        print(f'\nPublished {len(pages)} wiki page(s) for "{target_name}":')
        for p in pages:
            print(f'  - {p}')
    elif status == 'no_target_found':
        print(f'\nNo pages published for "{target_name}". The code was scanned but '
              f'no matching modules were found on the agent side.')
    else:
        msg = response.get('message', 'Unknown error')
        print(f'\nAgent error: {msg}')


def _print_scan_only(matching: list, target_name: str) -> None:
    for mod in matching:
        print(f'\n--- {mod.file_path} ---')
        for func in mod.functions:
            print(f'  def {func.name}(...) -> {func.return_type or "None"}')
        for cls in mod.classes:
            print(f'  class {cls.name}')
            for method in cls.methods:
                print(f'    def {method.name}(...) -> {method.return_type or "None"}')
    print(f'\nFound {len(matching)} matching module(s) for "{target_name}".')


if __name__ == '__main__':
    main()