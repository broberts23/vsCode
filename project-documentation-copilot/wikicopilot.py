r"""Documentation Copilot — Local CLI.

Scans a local Python repository, serialises the code metadata, and invokes
the Foundry Hosted Agent via the ``azure-ai-projects`` Python SDK
(``AIProjectClient`` → ``get_openai_client(agent_name=...)`` →
``responses.create()``).  No ``azd`` subprocess, no command-line length
limits, no manual token management — the SDK uses ``DefaultAzureCredential``
to acquire tokens from the existing Azure CLI session.

Usage:
    python wikicopilot.py "update the wiki for walk_repository function"
    python wikicopilot.py --target AdoWikiClient --mode publish
    python wikicopilot.py --repo C:\git\myproject "document parse_config"

No PAT, Key Vault, or LLM credentials are needed locally.  The Foundry agent
handles wiki generation + ADO publishing with its service‑principal auth
chain (Key Vault → SP Bearer token).
"""

from __future__ import annotations
import json
import logging
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
AGENT_DIR = PROJECT_ROOT / 'documentation-copilot'
sys.path.insert(0, str(AGENT_DIR))

from src.scanner.repo_walker import scan_target, walk_repository
from src.app import _extract_target_from_prompt
from src.ado.module_serializer import module_info_to_dict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
)
logger = logging.getLogger('wikicopilot')


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description='Scan local Python code and publish wiki docs via Foundry.',
    )
    parser.add_argument(
        'prompt', nargs='?',
        help='Natural-language instruction.',
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
        '--project-endpoint',
        help='Foundry project endpoint.  Defaults to $AZURE_AI_PROJECT_ENDPOINT.',
    )
    parser.add_argument(
        '--agent-name',
        default='documentation-copilot',
        help='Foundry agent name (default: documentation-copilot).',
    )
    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='Output raw agent response JSON.',
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
    logger.info('Target: %s  |  Repo: %s  |  Mode: %s',
                target_name, repo_root, args.mode)
    _run_pipeline(
        target_name, repo_root, args.mode, args.json,
        args.project_endpoint, args.agent_name,
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def _run_pipeline(
    target_name: str,
    repo_root: Path,
    mode: str,
    raw_json: bool,
    project_endpoint_override: str | None,
    agent_name: str,
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

    _invoke_agent(target_name, matching, mode, raw_json,
                  project_endpoint_override, agent_name)


# ---------------------------------------------------------------------------
# Agent invocation (azure-ai-projects SDK)
# ---------------------------------------------------------------------------

def _invoke_agent(
    target_name: str,
    matching: list,          # list[ModuleInfo]
    mode: str,
    raw_json: bool,
    project_endpoint_override: str | None,
    agent_name: str,
) -> None:
    from azure.identity import DefaultAzureCredential
    from azure.ai.projects import AIProjectClient

    scan_data = [module_info_to_dict(m) for m in matching]

    # Resolve project endpoint from override, env, or default
    project_endpoint = (
        project_endpoint_override
        or os.environ.get('AZURE_AI_PROJECT_ENDPOINT')
        or 'https://cog-doccopilot-dev01.services.ai.azure.com/api/projects/doccopilot'
    )

    logger.info(
        'Connecting to Foundry agent "%s" at %s  |  %d module(s)  |  %d bytes',
        agent_name, project_endpoint, len(scan_data),
        len(json.dumps(scan_data)),
    )

    credential = DefaultAzureCredential()
    project = AIProjectClient(
        endpoint=project_endpoint, credential=credential, allow_preview=True)
    openai_client = project.get_openai_client(agent_name=agent_name)

    # Send with extra_body to pass our custom fields alongside standard fields
    response = openai_client.responses.create(
        input=f'update the wiki for {target_name}',
        stream=False,
        extra_body={
            'mode': mode,
            'scan_data': scan_data,
        },
    )

    output = response.output_text or ''
    if raw_json:
        print(output)
        return

    _print_agent_response(output, target_name)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_agent_response(output: str, target_name: str) -> None:
    try:
        response = json.loads(output)
    except json.JSONDecodeError:
        print(output)
        return

    status = response.get('status', 'unknown')
    pages = response.get('pages', [])

    if status == 'success' and pages:
        print(f'\nPublished {len(pages)} wiki page(s) for "{target_name}":')
        for p in pages:
            print(f'  - {p}')
    elif status == 'no_target_found':
        print(f'\nNo pages published for "{target_name}". '
              f'The code was scanned but no matching modules were found on the agent side.')
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
                print(
                    f'    def {method.name}(...) -> {method.return_type or "None"}')
    print(f'\nFound {len(matching)} matching module(s) for "{target_name}".')


if __name__ == '__main__':
    main()
