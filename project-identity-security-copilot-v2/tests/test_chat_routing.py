"""Tests for request routing and deterministic chat helpers.

PowerShell bridge:
- These tests are closer to validating helper logic in a small module than to running
  a full end-to-end cloud integration.
- We keep them narrow so they can fail fast when the copilot routing contract changes.
"""

from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.rag.chat import build_copilot_plan, extract_function_calls, format_citations


def test_build_copilot_plan_routes_summary_requests() -> None:
    """Verify that summary prompts use the summary path."""

    plan = build_copilot_plan('Summarize Conditional Access guidance for reviewers.')

    assert plan.operation == 'summarize'
    assert plan.use_tools is False


def test_build_copilot_plan_routes_questions_to_grounded_chat() -> None:
    """Verify that normal questions stay on the grounded answer path."""

    plan = build_copilot_plan('Which workload identities need stronger controls?')

    assert plan.operation == 'answer'
    assert plan.use_tools is True


def test_extract_function_calls_filters_non_tool_outputs() -> None:
    """Verify that only tool calls are normalized from a response payload."""

    class FakeOutputItem:
        def __init__(self, item_type: str, name: str = '', arguments: str = '{}', call_id: str = '') -> None:
            self.type = item_type
            self.name = name
            self.arguments = arguments
            self.call_id = call_id

    class FakeResponse:
        output = [
            FakeOutputItem('reasoning'),
            FakeOutputItem('function_call', 'search_identity_knowledge', '{"query":"Conditional Access"}', 'call-001'),
        ]

    calls = extract_function_calls(FakeResponse())

    assert calls == [
        {
            'name': 'search_identity_knowledge',
            'arguments': '{"query":"Conditional Access"}',
            'call_id': 'call-001',
        }
    ]


def test_format_citations_removes_duplicate_document_ids() -> None:
    """Verify that the deterministic citation block stays de-duplicated."""

    citations = format_citations(
        [
            {'id': 'doc-1', 'title': 'Conditional Access', 'file_path': 'knowledge/conditional-access.md'},
            {'id': 'doc-1', 'title': 'Conditional Access', 'file_path': 'knowledge/conditional-access.md'},
            {'id': 'doc-2', 'title': 'Workload identities', 'file_path': 'knowledge/workload-identities.md'},
        ]
    )

    assert citations.splitlines() == [
        '- doc-1 | Conditional Access | knowledge/conditional-access.md',
        '- doc-2 | Workload identities | knowledge/workload-identities.md',
    ]