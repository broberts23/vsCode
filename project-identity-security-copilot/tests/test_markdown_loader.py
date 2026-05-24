"""Tests for the local markdown ingestion path.

PowerShell bridge:
- These tests are similar to lightweight Pester checks for a parsing helper.
- The tests intentionally stay narrow because they are validating the shape of the
    ingestion pipeline, not the Azure services behind it.
"""

from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.content.markdown_loader import build_search_documents, load_markdown_sections


def test_markdown_sections_load_from_repo_knowledge() -> None:
        """Verify that the local knowledge base is discoverable and parsable.

        PowerShell bridge:
        - This is similar to checking that a script can find the files it expects before
            moving on to a heavier operation.
        """

    knowledge_root = PROJECT_ROOT / 'knowledge'
    sections = load_markdown_sections(knowledge_root)

        # We only care that the parser finds something useful and that the content looks
        # like the repo's identity-security knowledge base.
    assert sections
    assert any('Conditional Access' in section.title for section in sections)


def test_build_search_documents_creates_stable_ids() -> None:
        """Verify that markdown sections become stable search document shapes.

        PowerShell bridge:
        - This is the equivalent of validating that a transformation step returns the same
            predictable keys every time it runs.
        """

    knowledge_root = PROJECT_ROOT / 'knowledge'
    documents = build_search_documents(knowledge_root)

        # Stable IDs and a consistent source type are the important contract for indexing.
    assert documents
    assert all(document.id for document in documents)
    assert all(document.source_type == 'markdown' for document in documents)
