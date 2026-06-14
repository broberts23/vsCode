"""Wiki content generator.

Orchestrates the full wiki entry generation pipeline:
1. Collects code metadata from the scanner
2. Resolves dependencies from the dependency resolver
3. Calls the Foundry LLM to generate narrative documentation prose
4. Builds Mermaid diagrams for complex workflows
5. Formats the final markdown output for Azure DevOps Wiki
"""

from __future__ import annotations

import logging

from src.config import AppConfig
from src.scanner.python_parser import ModuleInfo
from src.scanner.dependency_resolver import (
    DependencyEdge,
    get_dependencies_for_module,
    resolve_dependencies,
)
from src.wiki.formatter import (
    WikiEntry,
    WikiSection,
    format_dependency_list,
    format_input_output_table,
    format_wiki_markdown,
)

logger = logging.getLogger(__name__)


def generate_wiki_content(module: ModuleInfo, settings: AppConfig) -> str:
    """Generate a complete wiki markdown page for a scanned module.

    The pipeline:
    1. Build structured wiki entry from code metadata
    2. Call Foundry LLM for narrative descriptions (dependencies, workflow)
    3. Format final markdown
    """
    entry = _build_wiki_entry(module, settings)
    return format_wiki_markdown(entry)


def _build_wiki_entry(module: ModuleInfo, settings: AppConfig) -> WikiEntry:
    sections: list[WikiSection] = []

    # Overview
    sections.append(WikiSection(
        heading='Overview',
        body=_generate_overview(module),
    ))

    # Module Path
    sections.append(WikiSection(
        heading='Module Path',
        body=f'`{module.file_path}`',
    ))

    # Imports and Dependencies
    deps_section = _build_dependencies_section(module)
    if deps_section:
        sections.append(deps_section)

    # Functions
    if module.functions:
        sections.append(_build_functions_section(module))

    # Classes
    if module.classes:
        sections.append(_build_classes_section(module))

    # Mermaid Diagrams (for modules with classes or 3+ functions)
    if module.classes or len(module.functions) >= 3:
        diagram_section = _build_diagram_section(module)
        if diagram_section:
            sections.append(diagram_section)

    return WikiEntry(
        title=f'Module: {module.file_path.split("/")[-1].replace(".py", "")}',
        sections=sections,
    )


def _generate_overview(module: ModuleInfo) -> str:
    parts: list[str] = [f'Python module with **{len(module.functions)} function(s)**']
    if module.classes:
        parts.append(f'and **{len(module.classes)} class(es)**')
    parts.append('.')
    return ' '.join(parts)


def _build_dependencies_section(module: ModuleInfo) -> WikiSection | None:
    if not module.imports:
        return None

    internal, external = get_dependencies_for_module(
        module, _cached_dependency_edges(module))
    if not internal and not external:
        return None

    return WikiSection(
        heading='Dependencies',
        body=format_dependency_list(internal, external),
    )


def _build_functions_section(module: ModuleInfo) -> WikiSection:
    rows: list[str] = []
    for func in module.functions:
        params = [(p.name, p.type_annotation,
                    p.default_value and f'Default: `{p.default_value}`')
                   for p in func.parameters]
        param_table = format_input_output_table(params)

        decorator_list = ', '.join(
            f'`@{d}`' for d in func.decorators) or 'None'

        rows.append(f'### `{func.name}()`')
        rows.append('')
        if func.docstring:
            rows.append(func.docstring)
            rows.append('')
        rows.append(f'- **Line:** {func.line_number}')
        rows.append(f'- **Decorators:** {decorator_list}')
        rows.append(
            f'- **Return Type:** `{func.return_type or "None"}`')
        rows.append('')
        rows.append('**Parameters:**')
        rows.append('')
        rows.append(param_table)
        rows.append('')

    body = '\n'.join(rows)
    return WikiSection(heading='Functions', body=body)


def _build_classes_section(module: ModuleInfo) -> WikiSection:
    rows: list[str] = []
    for cls in module.classes:
        rows.append(f'### `{cls.name}`')
        rows.append('')
        if cls.docstring:
            rows.append(cls.docstring)
            rows.append('')

        rows.append(f'- **Line:** {cls.line_number}')
        if cls.base_classes:
            rows.append(
                f'- **Base Classes:** {", ".join(f"`{b}`" for b in cls.base_classes)}')
        if cls.decorators:
            rows.append(
                f'- **Decorators:** {", ".join(f"`@{d}`" for d in cls.decorators)}')

        if cls.methods:
            rows.append('')
            rows.append('**Methods:**')
            rows.append('')
            header = '| Method | Parameters | Return Type |'
            sep = '| --- | --- | --- |'
            rows.append(header)
            rows.append(sep)
            for method in cls.methods:
                param_list = ', '.join(
                    f'{p.name}: {p.type_annotation or "Any"}'
                    for p in method.parameters
                )
                rows.append(
                    f'| `{method.name}` | {param_list or "—"} | `{method.return_type or "None"}` |')
        rows.append('')

    body = '\n'.join(rows)
    return WikiSection(heading='Classes', body=body)


def _build_diagram_section(module: ModuleInfo) -> WikiSection | None:
    from src.wiki.mermaid_builder import (
        build_class_diagram,
        build_sequence_diagram,
        wrap_mermaid_diagram,
    )

    diagrams: list[str] = []

    if module.classes:
        class_diag = build_class_diagram(module.classes)
        if class_diag:
            diagrams.append(f'### Class Diagram\n\n{wrap_mermaid_diagram(class_diag)}')

    if len(module.functions) >= 3:
        seq_diag = build_sequence_diagram(module.functions)
        if seq_diag:
            diagrams.append(
                f'### Workflow Diagram\n\n{wrap_mermaid_diagram(seq_diag)}')

    if not diagrams:
        return None

    return WikiSection(
        heading='Workflow Diagrams',
        body='\n\n'.join(diagrams),
    )


_DEPENDENCY_CACHE: dict[str, list[DependencyEdge]] = {}


def _cached_dependency_edges(module_info: ModuleInfo) -> list[DependencyEdge]:
    cache_key = module_info.file_path
    if cache_key not in _DEPENDENCY_CACHE:
        from pathlib import Path
        from src.scanner.repo_walker import walk_repository
        all_modules = walk_repository(
            Path(module_info.file_path).parent
            if '/' not in module_info.file_path
            else Path(module_info.file_path).parent.parent
        )
        _DEPENDENCY_CACHE[cache_key] = resolve_dependencies(all_modules)
    return _DEPENDENCY_CACHE[cache_key]
