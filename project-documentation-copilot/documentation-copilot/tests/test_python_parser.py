"""Tests for the Python AST-based code parser."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.scanner.python_parser import parse_python_file


def test_parse_function_with_type_annotations(tmp_path: Path) -> None:
    source = '''"""Test module."""
from typing import Optional

def calculate_total(items: list[int], tax_rate: float = 0.1) -> float:
    """Calculate the total price including tax."""
    return sum(items) * (1 + tax_rate)
'''
    py_file = tmp_path / 'test_mod.py'
    py_file.write_text(source, encoding='utf-8')

    module = parse_python_file(py_file)

    assert len(module.functions) == 1
    func = module.functions[0]
    assert func.name == 'calculate_total'
    assert func.docstring == 'Calculate the total price including tax.'
    assert func.line_number > 0
    assert len(func.parameters) == 2
    assert func.parameters[0].name == 'items'
    assert func.parameters[0].type_annotation == 'list[int]'
    assert func.parameters[1].name == 'tax_rate'
    assert func.parameters[1].default_value == '0.1'
    assert func.return_type == 'float'


def test_parse_class_with_methods(tmp_path: Path) -> None:
    source = '''"""Service module."""

class DataService:
    """Handles data operations."""

    def __init__(self, config: dict) -> None:
        self.config = config

    def fetch(self, key: str) -> str | None:
        """Fetch a value by key."""
        return self.config.get(key)
'''
    py_file = tmp_path / 'service.py'
    py_file.write_text(source, encoding='utf-8')

    module = parse_python_file(py_file)

    assert len(module.classes) == 1
    cls = module.classes[0]
    assert cls.name == 'DataService'
    assert cls.docstring == 'Handles data operations.'
    assert len(cls.methods) == 2
    method_names = {m.name for m in cls.methods}
    assert method_names == {'__init__', 'fetch'}


def test_parse_extracts_imports(tmp_path: Path) -> None:
    source = '''import os
from pathlib import Path
from typing import Optional, Any
'''
    py_file = tmp_path / 'imports.py'
    py_file.write_text(source, encoding='utf-8')

    module = parse_python_file(py_file)

    assert 'os' in module.imports
    assert 'pathlib.Path' in module.imports
    assert 'typing.Optional' in module.imports
    assert 'typing.Any' in module.imports


def test_parse_skips_syntax_errors(tmp_path: Path) -> None:
    py_file = tmp_path / 'broken.py'
    py_file.write_text('def broken(:\n    pass\n', encoding='utf-8')

    try:
        parse_python_file(py_file)
        assert False, 'Should have raised SyntaxError'
    except SyntaxError:
        pass
