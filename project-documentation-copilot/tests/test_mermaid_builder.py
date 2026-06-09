"""Tests for the Mermaid diagram builder."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.wiki.mermaid_builder import (
    build_class_diagram,
    build_sequence_diagram,
    wrap_mermaid_diagram,
)
from src.scanner.python_parser import ClassInfo, FunctionInfo, ParamInfo


def _make_class(name: str, methods: list[FunctionInfo], bases: list[str] | None = None) -> ClassInfo:
    return ClassInfo(
        name=name,
        file_path='test_module.py',
        line_number=1,
        docstring=None,
        decorators=[],
        base_classes=bases or [],
        methods=methods,
    )


def _make_func(name: str, decorators: list[str] | None = None) -> FunctionInfo:
    return FunctionInfo(
        name=name,
        file_path='test_module.py',
        line_number=1,
        docstring=None,
        decorators=decorators or [],
        parameters=[],
    )


def test_build_class_diagram_includes_class_and_methods() -> None:
    cls = _make_class('AuthService', [
        _make_func('login'),
        _make_func('logout'),
    ])

    result = build_class_diagram([cls])

    assert 'classDiagram' in result
    assert 'class AuthService' in result
    assert '+login' in result
    assert '+logout' in result


def test_build_class_diagram_includes_inheritance() -> None:
    cls = _make_class('ChildService', [
        _make_func('process'),
    ], bases=['BaseService'])

    result = build_class_diagram([cls])

    assert 'BaseService <|-- ChildService' in result


def test_build_sequence_diagram_assigns_participants() -> None:
    funcs = [
        _make_func('authenticate', ['@router']),
        _make_func('validate_input'),
        _make_func('process_request'),
    ]

    result = build_sequence_diagram(funcs)

    assert 'sequenceDiagram' in result
    assert 'participant' in result
    assert 'authenticate' in result
    assert 'validate_input' in result
    assert 'process_request' in result


def test_wrap_mermaid_diagram_adds_fence() -> None:
    result = wrap_mermaid_diagram('graph TD\n    A --> B')

    assert result.startswith('::: mermaid')
    assert 'graph TD' in result
    assert result.strip().endswith(':::')


def test_wrap_mermaid_diagram_empty_string() -> None:
    result = wrap_mermaid_diagram('')

    assert result == ''
