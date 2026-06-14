"""Serialization helpers for ModuleInfo / FunctionInfo / ClassInfo.

Provides lossless JSON round-trip for code scan data, enabling the local
CLI to scan a repository, serialize the results, and send them to the
Foundry agent for wiki generation and ADO publishing.
"""

from __future__ import annotations

from src.scanner.python_parser import (
    ClassInfo,
    FunctionInfo,
    ModuleInfo,
    ParamInfo,
)


def module_info_to_dict(mod: ModuleInfo) -> dict[str, object]:
    """Serialize a ModuleInfo tree to a JSON-serializable dict."""
    return {
        'file_path': mod.file_path,
        'functions': [_function_to_dict(f) for f in mod.functions],
        'classes': [_class_to_dict(c) for c in mod.classes],
        'imports': list(mod.imports),
    }


def dict_to_module_info(d: dict[str, object]) -> ModuleInfo:
    """Deserialize a dict back into a ModuleInfo tree."""
    return ModuleInfo(
        file_path=str(d['file_path']),
        functions=[_dict_to_function(f) for f in d.get('functions', [])],  # type: ignore[arg-type]
        classes=[_dict_to_class(c) for c in d.get('classes', [])],  # type: ignore[arg-type]
        imports=[str(i) for i in d.get('imports', [])],  # type: ignore[arg-type]
    )


def _function_to_dict(f: FunctionInfo) -> dict[str, object]:
    return {
        'name': f.name,
        'file_path': f.file_path,
        'line_number': f.line_number,
        'docstring': f.docstring,
        'decorators': list(f.decorators),
        'parameters': [
            {
                'name': p.name,
                'type_annotation': p.type_annotation,
                'default_value': p.default_value,
            }
            for p in f.parameters
        ],
        'return_type': f.return_type,
        'body_summary': f.body_summary,
    }


def _dict_to_function(d: dict[str, object]) -> FunctionInfo:
    return FunctionInfo(
        name=str(d['name']),
        file_path=str(d.get('file_path', '')),
        line_number=int(d.get('line_number', 0)),
        docstring=d.get('docstring') if d.get('docstring') is not None else None,  # type: ignore[arg-type]
        decorators=[str(x) for x in d.get('decorators', [])],  # type: ignore[arg-type]
        parameters=[
            ParamInfo(
                name=str(p['name']),
                type_annotation=p.get('type_annotation') if p.get('type_annotation') is not None else None,  # type: ignore[arg-type]
                default_value=p.get('default_value') if p.get('default_value') is not None else None,  # type: ignore[arg-type]
            )
            for p in d.get('parameters', [])  # type: ignore[arg-type]
        ],
        return_type=d.get('return_type') if d.get('return_type') is not None else None,  # type: ignore[arg-type]
        body_summary=str(d.get('body_summary', '')),
    )


def _class_to_dict(c: ClassInfo) -> dict[str, object]:
    return {
        'name': c.name,
        'file_path': c.file_path,
        'line_number': c.line_number,
        'docstring': c.docstring,
        'decorators': list(c.decorators),
        'base_classes': list(c.base_classes),
        'methods': [_function_to_dict(m) for m in c.methods],
        'body_summary': c.body_summary,
    }


def _dict_to_class(d: dict[str, object]) -> ClassInfo:
    return ClassInfo(
        name=str(d['name']),
        file_path=str(d.get('file_path', '')),
        line_number=int(d.get('line_number', 0)),
        docstring=d.get('docstring') if d.get('docstring') is not None else None,  # type: ignore[arg-type]
        decorators=[str(x) for x in d.get('decorators', [])],  # type: ignore[arg-type]
        base_classes=[str(x) for x in d.get('base_classes', [])],  # type: ignore[arg-type]
        methods=[_dict_to_function(m) for m in d.get('methods', [])],  # type: ignore[arg-type]
        body_summary=str(d.get('body_summary', '')),
    )