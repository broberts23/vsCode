"""Mermaid diagram builder.

Produces Mermaid syntax strings for class diagrams, sequence diagrams,
and flowcharts based on extracted code metadata. The output is embedded
directly into Azure DevOps wiki markdown using the `::: mermaid` fence.
"""

from __future__ import annotations

from src.scanner.python_parser import ClassInfo, FunctionInfo, ModuleInfo


def build_class_diagram(classes: list[ClassInfo]) -> str:
    """Build a Mermaid classDiagram showing class relationships."""
    if not classes:
        return ''

    lines: list[str] = ['classDiagram']
    for cls in classes:
        lines.append(f'    class {cls.name} {{')
        for method in cls.methods:
            params = ', '.join(
                f'{p.name}: {p.type_annotation or "Any"}'
                for p in method.parameters
            )
            return_str = f' {method.return_type}' if method.return_type else ''
            lines.append(f'        +{method.name}({params}){return_str}')
        lines.append('    }')

    for cls in classes:
        for base in cls.base_classes:
            lines.append(f'    {base} <|-- {cls.name}')

    return '\n'.join(lines)


def build_sequence_diagram(functions: list[FunctionInfo], title: str = 'Workflow') -> str:
    """Build a Mermaid sequenceDiagram for function call flow.

    When functions have decorators indicating roles (e.g., @router, @task),
    they are treated as participants in the sequence.
    """
    if not functions:
        return ''

    lines: list[str] = ['sequenceDiagram', f'    title {title}']
    participants: dict[str, str] = {}

    for func in functions:
        role = _infer_role(func)
        alias = f'p{len(participants)}'
        participants[func.name] = alias
        lines.append(f'    participant {alias} as {func.name} ({role})')

    func_names = list(participants.keys())
    for i in range(len(func_names) - 1):
        caller = participants[func_names[i]]
        callee = participants[func_names[i + 1]]
        lines.append(f'    {caller}->>+{callee}: invoke')

    return '\n'.join(lines)


def build_flowchart_diagram(module: ModuleInfo) -> str:
    """Build a Mermaid flowchart showing the module's execution flow."""
    all_symbols = [f.name for f in module.functions] + [c.name for c in module.classes]
    if not all_symbols:
        return ''

    lines: list[str] = ['graph TD']
    for i, sym in enumerate(all_symbols):
        lines.append(f'    N{i}[{sym}]')
        if i > 0:
            lines.append(f'    N{i - 1} --> N{i}')

    return '\n'.join(lines)


def wrap_mermaid_diagram(diagram: str) -> str:
    """Wrap a Mermaid diagram string in the Azure DevOps wiki Mermaid fence."""
    if not diagram.strip():
        return ''
    return f'::: mermaid\n{diagram}\n:::'


def _infer_role(func: FunctionInfo) -> str:
    decorators = ' '.join(func.decorators).lower()
    if 'route' in decorators or 'router' in decorators:
        return 'Router'
    if 'task' in decorators or 'celery' in decorators:
        return 'Task'
    if 'staticmethod' in decorators:
        return 'Static'
    if 'classmethod' in decorators:
        return 'ClassMethod'
    if 'property' in decorators:
        return 'Property'
    return 'Function'
