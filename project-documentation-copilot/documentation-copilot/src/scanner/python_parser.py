"""AST-based Python code analysis.

Walks Python source files to extract functions, classes, signatures, docstrings,
and type annotations. The extracted metadata feeds the wiki documentation generator.

Architecture note: deepseek-v4-flash does not support tool calling, so code extraction
is performed entirely in Python via `ast` before any LLM call. The LLM receives
pre-extracted metadata and only handles prose generation.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class FunctionInfo:
    name: str
    file_path: str
    line_number: int
    docstring: str | None
    decorators: list[str] = field(default_factory=list)
    parameters: list[ParamInfo] = field(default_factory=list)
    return_type: str | None = None
    body_summary: str = ''


@dataclass(slots=True)
class ClassInfo:
    name: str
    file_path: str
    line_number: int
    docstring: str | None
    decorators: list[str] = field(default_factory=list)
    base_classes: list[str] = field(default_factory=list)
    methods: list[FunctionInfo] = field(default_factory=list)
    body_summary: str = ''


@dataclass(slots=True)
class ParamInfo:
    name: str
    type_annotation: str | None
    default_value: str | None


@dataclass(slots=True)
class ModuleInfo:
    file_path: str
    functions: list[FunctionInfo]
    classes: list[ClassInfo]
    imports: list[str]


class _CodeVisitor(ast.NodeVisitor):
    """AST visitor that extracts function and class metadata."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.functions: list[FunctionInfo] = []
        self.classes: list[ClassInfo] = []
        self.imports: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ''
        for alias in node.names:
            self.imports.append(f'{module}.{alias.name}')
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        func = FunctionInfo(
            name=node.name,
            file_path=self.file_path,
            line_number=node.lineno,
            docstring=ast.get_docstring(node),
            decorators=[self._decorator_name(d) for d in node.decorator_list],
            parameters=self._extract_params(node.args),
            return_type=self._annotation_str(node.returns),
            body_summary=self._summarize_body(node.body),
        )
        self.functions.append(func)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        methods: list[FunctionInfo] = []
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                methods.append(FunctionInfo(
                    name=item.name,
                    file_path=self.file_path,
                    line_number=item.lineno,
                    docstring=ast.get_docstring(item),
                    decorators=[self._decorator_name(d)
                                for d in item.decorator_list],
                    parameters=self._extract_params(item.args),
                    return_type=self._annotation_str(item.returns),
                ))

        cls = ClassInfo(
            name=node.name,
            file_path=self.file_path,
            line_number=node.lineno,
            docstring=ast.get_docstring(node),
            decorators=[self._decorator_name(d) for d in node.decorator_list],
            base_classes=[self._base_name(b) for b in node.bases],
            methods=methods,
            body_summary=self._summarize_body(node.body),
        )
        self.classes.append(cls)
        self.generic_visit(node)

    @staticmethod
    def _decorator_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f'{ast.unparse(node.value)}.{node.attr}'
        return ast.unparse(node)

    @staticmethod
    def _base_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f'{ast.unparse(node.value)}.{node.attr}'
        return ast.unparse(node)

    @staticmethod
    def _annotation_str(node: ast.expr | None) -> str | None:
        if node is None:
            return None
        return ast.unparse(node)

    @staticmethod
    def _extract_params(args: ast.arguments) -> list[ParamInfo]:
        params: list[ParamInfo] = []
        defaults_offset = len(args.args) - len(args.defaults)
        for i, arg in enumerate(args.args):
            default_idx = i - defaults_offset
            default = None
            if default_idx >= 0 and args.defaults:
                default = ast.unparse(args.defaults[default_idx])
            params.append(ParamInfo(
                name=arg.arg,
                type_annotation=ast.unparse(
                    arg.annotation) if arg.annotation else None,
                default_value=default,
            ))
        return params

    @staticmethod
    def _summarize_body(body: list[ast.stmt]) -> str:
        count = len(body)
        raises = [
            'raises' for s in body if isinstance(s, ast.Raise)]
        returns = [
            'returns' for s in body
            if isinstance(s, ast.Return) and s.value is not None
        ]
        parts: list[str] = [f'{count} statements']
        if raises:
            parts.append(f'{len(raises)} raise(s)')
        if returns:
            parts.append(f'{len(returns)} return(s)')
        return ', '.join(parts)


def parse_python_file(file_path: Path) -> ModuleInfo:
    """Parse a single Python file and extract code metadata."""
    source = file_path.read_text(encoding='utf-8')
    tree = ast.parse(source, filename=str(file_path))
    visitor = _CodeVisitor(str(file_path))
    visitor.visit(tree)
    return ModuleInfo(
        file_path=str(file_path),
        functions=visitor.functions,
        classes=visitor.classes,
        imports=visitor.imports,
    )
