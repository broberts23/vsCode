"""Dependency resolution for scanned code.

Analyzes imports across modules to build a dependency graph. This feeds the
"dependencies" section of generated wiki entries.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.scanner.python_parser import ModuleInfo


@dataclass(slots=True)
class DependencyEdge:
    source_file: str
    target_module: str
    is_internal: bool


def resolve_dependencies(modules: list[ModuleInfo]) -> list[DependencyEdge]:
    """Build a dependency graph from module imports.

    An import is considered 'internal' if the target module prefix matches
    the project namespace inferred from the scanned modules. External imports
    are third-party or stdlib packages.
    """
    internal_prefixes = _infer_internal_prefixes(modules)
    edges: list[DependencyEdge] = []

    for mod in modules:
        for imp in mod.imports:
            top_level = imp.split('.')[0]
            is_internal = top_level in internal_prefixes or any(
                imp.startswith(p) for p in internal_prefixes
            )
            edges.append(DependencyEdge(
                source_file=mod.file_path,
                target_module=imp,
                is_internal=is_internal,
            ))

    return edges


def _infer_internal_prefixes(modules: list[ModuleInfo]) -> set[str]:
    """Heuristically identify project-internal package prefixes."""
    prefixes: set[str] = set()
    for mod in modules:
        for imp in mod.imports:
            top = imp.split('.')[0]
            if any(
                m.file_path.replace('\\', '/').find(f'/{top}/') != -1
                for m in modules
            ):
                prefixes.add(top)
    return prefixes


def get_dependencies_for_module(
    module: ModuleInfo,
    edges: list[DependencyEdge],
) -> tuple[list[str], list[str]]:
    """Return (internal_deps, external_deps) for a single module."""
    internal: list[str] = []
    external: list[str] = []
    seen: set[str] = set()

    for edge in edges:
        if edge.source_file != module.file_path:
            continue
        if edge.target_module in seen:
            continue
        seen.add(edge.target_module)
        if edge.is_internal:
            internal.append(edge.target_module)
        else:
            external.append(edge.target_module)

    return sorted(internal), sorted(external)
