"""Load markdown knowledge files and turn them into search documents.

PowerShell bridge:
- This module is doing the same job as a parser plus object reshaping script.
- Each markdown section becomes one document, similar to turning one file into many
    pipeline objects.
- The code deliberately keeps the transformation steps small so the data flow is easy
    to follow from file system input to search-ready output.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(slots=True)
class SearchDocument:
        """Search-ready document shape for Azure AI Search.

        PowerShell bridge:
        - Think of this like a custom object with a fixed property set that is ready to
            be sent to another command or service.
        - The dataclass keeps the document shape explicit and predictable.
        """

    id: str
    source_type: str
    title: str
    content: str
    file_path: str
    heading: str
    tags: str

    def as_dict(self) -> dict[str, str]:
                """Convert the typed object into a plain dictionary for SDK upload.

                PowerShell bridge:
                - This is like converting a custom class instance into a hashtable before
                    passing it into an SDK command.
                - Azure SDK upload methods generally expect simple dictionary-like payloads.
                """

                # Keep the shape narrow so the Search index and the upload payload stay aligned.
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
        """In-memory representation of one markdown section.

        PowerShell bridge:
        - This is a staging object that represents one section before it is flattened into
            a search document.
        """

    title: str
    content: str
    file_path: Path
    heading: str


def load_markdown_sections(knowledge_root: Path) -> list[MarkdownSection]:
    """Read all markdown files under the knowledge folder and split them by heading.

    PowerShell bridge:
    - This is similar to recursively reading files and returning a list of parsed
      objects instead of raw text.
    """

    sections: list[MarkdownSection] = []
    for file_path in sorted(knowledge_root.rglob('*.md')):
        # Each file can produce multiple sections, so we extend the list instead of
        # appending a single item.
        sections.extend(_split_file_into_sections(file_path))
    return sections


def build_search_documents(knowledge_root: Path) -> list[SearchDocument]:
        """Create Azure AI Search documents from markdown sections.

        PowerShell bridge:
        - This is like taking parsed objects and projecting them into the exact object
            shape expected by the next command in the pipeline.
        """

    documents: list[SearchDocument] = []
    for section in load_markdown_sections(knowledge_root):
                # The document ID is deterministic so re-ingestion produces stable records.
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
        """Split a markdown file into one section object per heading block.

        PowerShell bridge:
        - This is the parser step. It reads text line by line and turns it into a more
            structured representation.
        - We treat headings as boundaries, which is simple and easy to reason about.
        """

    text = file_path.read_text(encoding='utf-8')
    lines = text.splitlines()

    sections: list[MarkdownSection] = []
    current_heading = file_path.stem.replace('-', ' ')
    current_lines: list[str] = []

    for line in lines:
        if line.startswith('#'):
                        # Flush the previous section before starting a new heading block.
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
    """Append one parsed section if it contains usable content.

    PowerShell bridge:
    - This is the same pattern as checking whether a pipeline object is worth keeping
      before adding it to the output collection.
    """

    cleaned_content = '\n'.join(line.strip() for line in current_lines if line.strip()).strip()
    if not cleaned_content:
        return

    # The title combines file context and heading context so search results remain readable.
    sections.append(
        MarkdownSection(
            title=f'{file_path.stem.replace('-', ' ').title()}: {heading}',
            content=cleaned_content,
            file_path=file_path,
            heading=heading,
        )
    )


def _make_document_id(file_path: Path, heading: str) -> str:
    """Build a stable document ID from the file and heading names.

    PowerShell bridge:
    - This is similar to creating a repeatable key by combining normalized strings.
    - Stable IDs make reindexing safe because the same source section maps to the same
      destination document.
    """

    base_name = file_path.stem.lower().replace(' ', '-')
    heading_slug = re.sub(r'[^a-z0-9]+', '-', heading.lower()).strip('-')
    return f'{base_name}::{heading_slug or "section"}'


def _build_tags(file_path: Path, heading: str) -> str:
    """Build a compact tag string for filter and display scenarios.

    PowerShell bridge:
    - This is like joining a few metadata fields into one friendly label for later use.
    """

    parts = [file_path.stem.replace('-', ' '), heading]
    return ', '.join(part for part in parts if part)
