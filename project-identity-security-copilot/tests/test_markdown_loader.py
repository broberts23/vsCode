"""Tests for the local markdown ingestion path.

PowerShell bridge:
- These tests are similar to lightweight Pester checks for a parsing helper.
"""

from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.content.markdown_loader import build_search_documents, load_markdown_sections


def test_markdown_sections_load_from_repo_knowledge() -> None:
    knowledge_root = PROJECT_ROOT / 'knowledge'
    sections = load_markdown_sections(knowledge_root)

    assert sections
    assert any('Conditional Access' in section.title for section in sections)


def test_build_search_documents_creates_stable_ids() -> None:
    knowledge_root = PROJECT_ROOT / 'knowledge'
    documents = build_search_documents(knowledge_root)

    assert documents
    assert all(document.id for document in documents)
    assert all(document.source_type == 'markdown' for document in documents)
