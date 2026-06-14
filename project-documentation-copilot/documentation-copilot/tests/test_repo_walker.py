"""Tests for repository walking and file discovery."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.scanner.repo_walker import scan_target, walk_repository
from src.scanner.python_parser import ModuleInfo, FunctionInfo


def test_walk_repository_discovers_python_files(tmp_path: Path) -> None:
    (tmp_path / 'module_a.py').write_text(
        'def hello(): return "world"\n', encoding='utf-8')
    (tmp_path / 'module_b.py').write_text(
        'def goodbye(): return "farewell"\n', encoding='utf-8')
    (tmp_path / '__init__.py').write_text('', encoding='utf-8')
    (tmp_path / 'README.md').write_text('# Readme', encoding='utf-8')

    modules = walk_repository(tmp_path)

    python_files = {Path(m.file_path).name
                    for m in modules if Path(m.file_path).name != '__init__.py'}
    assert python_files == {'module_a.py', 'module_b.py'}


def test_walk_repository_excludes_venv(tmp_path: Path) -> None:
    (tmp_path / 'app.py').write_text('x = 1\n', encoding='utf-8')
    venv_dir = tmp_path / '.venv'
    venv_dir.mkdir()
    (venv_dir / 'ignored.py').write_text('y = 2\n', encoding='utf-8')

    modules = walk_repository(tmp_path)

    file_names = {Path(m.file_path).name for m in modules}
    assert 'app.py' in file_names
    assert 'ignored.py' not in file_names


def test_scan_target_finds_matching_function() -> None:
    modules = [
        ModuleInfo(
            file_path='src/config.py',
            functions=[FunctionInfo(
                name='load_config', file_path='src/config.py', line_number=1,
                docstring=None, decorators=[], parameters=[], return_type='dict',
            )],
            classes=[],
            imports=[],
        ),
        ModuleInfo(
            file_path='src/utils.py',
            functions=[FunctionInfo(
                name='helper', file_path='src/utils.py', line_number=1,
                docstring=None, decorators=[], parameters=[], return_type=None,
            )],
            classes=[],
            imports=[],
        ),
    ]

    matching = scan_target('load_config', modules)
    assert len(matching) == 1
    assert matching[0].file_path == 'src/config.py'

    matching = scan_target('nonexistent', modules)
    assert len(matching) == 0
