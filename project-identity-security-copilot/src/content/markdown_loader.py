"""Load markdown knowledge files and turn them into search documents.

PowerShell bridge:
- This module is doing the same job as a parser plus object reshaping script.
- Each markdown section becomes one document, similar to turning one file into many pipeline objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(slots=True)
class SearchDocument:
    """Search-ready document shape for Azure AI Search."""

    id: str
    source_type: str
    title: str
    content: str
    file_path: str
    heading: str
    tags: str

    def as_dict(self) -> dict[str, str]:
        """Convert the typed object into a plain dictionary for SDK upload."""

        return {
            'id': self.id,
            'source_type': self.source_type,
            'title': self.title,
            'content': self.content,
            'file_path': self.file_path,
            'heading': self.heading,
            'tags': self.tags,
        }


@dataclass(slots=True)
class MarkdownSection:
    """In-memory representation of one markdown section."""

    title: str
    content: str
    file_path: Path
    heading: str


def load_markdown_sections(knowledge_root: Path) -> list[MarkdownSection]:
    """Read all markdown files under the knowledge folder and split them by heading."""

    sections: list[MarkdownSection] = []
    for file_path in sorted(knowledge_root.rglob('*.md')):
        sections.extend(_split_file_into_sections(file_path))
    return sections


def build_search_documents(knowledge_root: Path) -> list[SearchDocument]:
    """Create Azure AI Search documents from markdown sections."""

    documents: list[SearchDocument] = []
    for section in load_markdown_sections(knowledge_root):
        document_id = _make_document_id(section.file_path, section.heading)
        tags = _build_tags(section.file_path, section.heading)
        documents.append(
            SearchDocument(
                id=document_id,
                source_type='markdown',
                title=section.title,
                content=section.content,
                file_path=section.file_path.as_posix(),
                heading=section.heading,
                tags=tags,
            )
        )

    return documents


def _split_file_into_sections(file_path: Path) -> list[MarkdownSection]:
    text = file_path.read_text(encoding='utf-8')
    lines = text.splitlines()

    sections: list[MarkdownSection] = []
    current_heading = file_path.stem.replace('-', ' ')
    current_lines: list[str] = []

    for line in lines:
        if line.startswith('#'):
            _append_section(sections, file_path, current_heading, current_lines)
            current_heading = line.lstrip('#').strip() or current_heading
            current_lines = []
            continue

        current_lines.append(line)

    _append_section(sections, file_path, current_heading, current_lines)
    return sections


def _append_section(
    sections: list[MarkdownSection],
    file_path: Path,
    heading: str,
    current_lines: list[str],
) -> None:
    cleaned_content = '\n'.join(line.strip() for line in current_lines if line.strip()).strip()
    if not cleaned_content:
        return

    sections.append(
        MarkdownSection(
            title=f'{file_path.stem.replace('-', ' ').title()}: {heading}',
            content=cleaned_content,
            file_path=file_path,
            heading=heading,
        )
    )


def _make_document_id(file_path: Path, heading: str) -> str:
    base_name = file_path.stem.lower().replace(' ', '-')
    heading_slug = re.sub(r'[^a-z0-9]+', '-', heading.lower()).strip('-')
    return f'{base_name}::{heading_slug or "section"}'


def _build_tags(file_path: Path, heading: str) -> str:
    parts = [file_path.stem.replace('-', ' '), heading]
    return ', '.join(part for part in parts if part)
