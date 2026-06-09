"""Tests for wiki markdown formatting."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.wiki.formatter import (
    WikiEntry,
    WikiSection,
    format_dependency_list,
    format_input_output_table,
    format_wiki_markdown,
)


def test_format_wiki_markdown_renders_sections() -> None:
    entry = WikiEntry(
        title='Test Module',
        sections=[
            WikiSection('Overview', 'This is a test module.'),
            WikiSection('Functions', '### `foo()`.'),
        ],
    )

    result = format_wiki_markdown(entry)

    assert result.startswith('# Test Module')
    assert '## Overview' in result
    assert '## Functions' in result
    assert 'This is a test module.' in result
    assert '### `foo()`' in result


def test_format_input_output_table_with_params() -> None:
    result = format_input_output_table([
        ('name', 'str', 'The name parameter.'),
        ('count', 'int', None),
    ])

    assert '| Parameter | Type | Description |' in result
    assert '| `name` | `str` | The name parameter. |' in result
    assert '| `count` | `int` | — |' in result


def test_format_input_output_table_empty() -> None:
    result = format_input_output_table([])

    assert '_No parameters._' in result


def test_format_dependency_list_both_types() -> None:
    result = format_dependency_list(
        internal=['src.config', 'src.models'],
        external=['requests', 'numpy'],
    )

    assert '**Internal Dependencies:**' in result
    assert '- `src.config`' in result
    assert '- `src.models`' in result
    assert '**External Dependencies:**' in result
    assert '- `requests`' in result
    assert '- `numpy`' in result


def test_format_dependency_list_empty() -> None:
    result = format_dependency_list([], [])

    assert '_No dependencies detected._' in result
