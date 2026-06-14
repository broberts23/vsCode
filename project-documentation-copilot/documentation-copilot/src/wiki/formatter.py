"""Wiki markdown formatter.

Produces Azure DevOps Wiki-compatible markdown from typed wiki content models.
Handles section structure, table formatting, and Mermaid diagram embedding.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class WikiSection:
    heading: str
    body: str


@dataclass(slots=True)
class WikiEntry:
    title: str
    sections: list[WikiSection]


def format_wiki_markdown(entry: WikiEntry) -> str:
    """Convert a WikiEntry into Azure DevOps Wiki markdown."""
    lines: list[str] = [f'# {entry.title}', '']
    for section in entry.sections:
        lines.append(f'## {section.heading}')
        lines.append('')
        lines.append(section.body)
        lines.append('')
    return '\n'.join(lines)


def format_input_output_table(
    params: list[tuple[str, str | None, str | None]],
) -> str:
    """Format a parameter table for Azure DevOps Wiki.

    Each tuple is (name, type_annotation, description).
    """
    if not params:
        return '_No parameters._'

    lines: list[str] = [
        '| Parameter | Type | Description |',
        '| --- | --- | --- |',
    ]
    for name, type_anno, desc in params:
        lines.append(f'| `{name}` | `{type_anno or "Any"}` | {desc or "—"} |')
    return '\n'.join(lines)


def format_dependency_list(
    internal: list[str],
    external: list[str],
) -> str:
    """Format dependency sections for a wiki page."""
    sections: list[str] = []

    if internal:
        items = '\n'.join(f'- `{d}`' for d in internal)
        sections.append(f'**Internal Dependencies:**\n\n{items}')

    if external:
        items = '\n'.join(f'- `{d}`' for d in external)
        sections.append(f'**External Dependencies:**\n\n{items}')

    if not sections:
        return '_No dependencies detected._'

    return '\n\n'.join(sections)
