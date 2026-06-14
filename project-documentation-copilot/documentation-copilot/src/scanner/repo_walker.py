"""Repository traversal for code discovery.

Walks a directory tree and discovers all Python source files, then delegates
to `python_parser` for per-file analysis. Produces an aggregated module catalog
that the wiki generator consumes.
"""

from __future__ import annotations

from pathlib import Path

from src.scanner.python_parser import ModuleInfo, parse_python_file


def walk_repository(root: Path, *, exclude_patterns: set[str] | None = None) -> list[ModuleInfo]:
    """Discover and parse all Python files under the given root directory.

    Args:
        root: The root directory to walk.
        exclude_patterns: Directory names to skip (default: venv, .git, __pycache__, etc.).

    Returns:
        A list of ModuleInfo objects, one per discovered Python file.
    """
    if exclude_patterns is None:
        exclude_patterns = {
            '.git', '.venv', 'venv', '__pycache__', '.pytest_cache',
            'node_modules', '.tox', 'build', 'dist', '.eggs',
        }

    modules: list[ModuleInfo] = []
    for py_file in sorted(root.rglob('*.py')):
        if _is_excluded(py_file, root, exclude_patterns):
            continue
        try:
            modules.append(parse_python_file(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue

    return modules


def _is_excluded(path: Path, root: Path, exclude_patterns: set[str]) -> bool:
    relative = path.relative_to(root)
    for part in relative.parts:
        if part in exclude_patterns:
            return True
    return False


def scan_target(target_name: str | None, modules: list[ModuleInfo]) -> list[ModuleInfo]:
    """Filter modules to those containing a specific function or class name.

    Args:
        target_name: The function or class name to search for (case-sensitive).
        modules: The full module catalog from `walk_repository`.

    Returns:
        Modules that contain the named function or class.
    """
    if not target_name:
        return []

    matching: list[ModuleInfo] = []
    for mod in modules:
        func_names = {f.name for f in mod.functions}
        class_names = {c.name for c in mod.classes}
        if target_name in func_names or target_name in class_names:
            matching.append(mod)

    return matching
