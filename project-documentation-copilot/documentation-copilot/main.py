"""Documentation Copilot — Foundry Hosted Agent entry point.

Starts a local HTTP server on http://localhost:8088/ that accepts
documentation generation requests. When deployed to Foundry Agent Service,
the hosting runtime provides the same interface.

Usage (local development):
    python main.py

Then send requests:
    curl -X POST http://localhost:8088/responses -H "Content-Type: application/json" -d '{"input": "update the wiki for MyFunction", "stream": false}'
"""

from __future__ import annotations
from src.workflow.provenance import new_correlation_id, record_event
from src.app import _extract_target_from_prompt, _handle_publish, _handle_scan_only
from src.config import AppConfig

import json
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
)
logger = logging.getLogger(__name__)


def handle_request(input_text: str, mode: str = 'auto', scan_data: list[dict[str, object]] | None = None) -> str:
    """Process a documentation request and return the result.

    Two operation modes:
    1. **Local scan (legacy):** When ``scan_data`` is ``None``, the agent scans
       its own file system at ``TARGET_REPO_ROOT``, generates wiki content,
       and publishes to ADO Wiki.
    2. **Remote scan (preferred):** When ``scan_data`` is provided (from a
       local CLI), the agent deserializes the pre-scanned module metadata,
       skips local scanning, and goes directly to generation + publishing.

    Also detects ``__SCAN__:`` marker in input_text for azd ai agent invoke
    compatibility (scan data is base64-encoded in the prompt text).

    This is the core handler invoked by both the local dev server and the
    Foundry Hosted Agent runtime.
    """
    import base64

    # Detect inline scan data marker (base64-encoded, for azd ai agent invoke compat)
    if input_text.startswith('__SCAN__:'):
        try:
            payload_raw = input_text[len('__SCAN__:'):]
            payload_bytes = base64.b64decode(payload_raw)
            payload = json.loads(payload_bytes)
            target_name = payload.get('target', '')
            scan_data = payload.get('scan_data')
            mode = payload.get('mode', mode)
            input_text = f'update the wiki for {target_name}'
        except Exception as exc:
            logger.warning('Failed to parse __SCAN__ payload: %s', exc)

    correlation_id = new_correlation_id()
    record_event('agent_request_received', correlation_id,
                 input=input_text, mode=mode,
                 scan_data_provided=scan_data is not None)

    settings = AppConfig.from_env()
    target_name = _extract_target_from_prompt(input_text)

    if not target_name:
        return json.dumps({
            'status': 'error',
            'message': 'Could not determine target function/class from prompt. Specify the function or class name explicitly.',
            'correlation_id': correlation_id,
        })

    logger.info('Agent handling target: %s (mode: %s, remote_scan: %s)',
                target_name, mode, scan_data is not None)

    if scan_data is not None:
        return _handle_remote_scan(target_name, scan_data, mode, settings, correlation_id)

    if mode == 'scan-only':
        import io
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        try:
            _handle_scan_only(target_name, settings, correlation_id)
            result = buffer.getvalue()
        finally:
            sys.stdout = old_stdout
        return json.dumps({
            'status': 'success',
            'target': target_name,
            'mode': 'scan-only',
            'output': result,
            'correlation_id': correlation_id,
        })

    from src.ado.wiki_service import update_wiki_for_target
    record_event('agent_publish_started', correlation_id, target=target_name)
    published = update_wiki_for_target(target_name, settings)
    record_event('agent_publish_completed', correlation_id, pages=published)

    return json.dumps({
        'status': 'success' if published else 'no_target_found',
        'target': target_name,
        'mode': mode,
        'pages_published': len(published),
        'pages': published,
        'correlation_id': correlation_id,
    })


def _handle_remote_scan(
    target_name: str,
    scan_data: list[dict[str, object]],
    mode: str,
    settings: AppConfig,
    correlation_id: str,
) -> str:
    """Handle a request where the caller already scanned the repo locally."""
    from src.ado.module_serializer import dict_to_module_info
    from src.scanner.python_parser import ModuleInfo

    modules = [dict_to_module_info(d) for d in scan_data]
    logger.info('Deserialized %d module(s) from remote scan data', len(modules))

    if mode == 'scan-only':
        output_lines: list[str] = []
        for mod in modules:
            output_lines.append(f'\n--- {mod.file_path} ---')
            for func in mod.functions:
                output_lines.append(f'  def {func.name}(...) -> {func.return_type or "None"}')
            for cls in mod.classes:
                output_lines.append(f'  class {cls.name}')
                for method in cls.methods:
                    output_lines.append(f'    def {method.name}(...) -> {method.return_type or "None"}')
        output_lines.append(f'\nFound {len(modules)} matching module(s).')
        return json.dumps({
            'status': 'success',
            'target': target_name,
            'mode': 'scan-only',
            'output': '\n'.join(output_lines),
            'correlation_id': correlation_id,
        })

    from src.ado.wiki_service import update_wiki_for_target_from_data
    record_event('agent_publish_started', correlation_id, target=target_name)
    published = update_wiki_for_target_from_data(target_name, modules, settings)
    record_event('agent_publish_completed', correlation_id, pages=published)

    return json.dumps({
        'status': 'success' if published else 'no_target_found',
        'target': target_name,
        'mode': mode,
        'pages_published': len(published),
        'pages': published,
        'correlation_id': correlation_id,
    })


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', '8088'))

    from http.server import HTTPServer, BaseHTTPRequestHandler

    class AgentHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid JSON"}')
                return

            input_text = data.get('input', '')
            mode = data.get('mode', 'auto')
            scan_data: list[dict[str, object]] | None = data.get('scan_data')
            result = handle_request(input_text, mode, scan_data)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(result.encode('utf-8'))

        def do_GET(self) -> None:
            if self.path in ('/health', '/readiness'):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "healthy"}')
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            logger.info('%s - %s', self.client_address[0], format % args)

    server = HTTPServer(('0.0.0.0', port), AgentHandler)
    logger.info('Documentation Copilot agent listening on port %d', port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info('Agent shutting down.')
        server.server_close()
