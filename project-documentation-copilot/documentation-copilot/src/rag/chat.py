"""LLM-augmented documentation generation.

Provides the prompt bridging layer that passes structured code metadata to
the Foundry model deployment and receives formatted documentation prose.

Architecture note: deepseek-v4-flash does NOT support tool calling, so this
module constructs a single well-structured prompt with all the code metadata
the model needs. No iterative tool-calling loop is required.
"""

from __future__ import annotations

from src.config import AppConfig
from src.foundry.project_client import complete_with_foundry
from src.scanner.python_parser import ClassInfo, FunctionInfo, ModuleInfo

DOCUMENTATION_SYSTEM_PROMPT = """You are a technical documentation copilot. Your task is to produce
high-quality Azure DevOps Wiki markdown entries for Python code modules.

Guidelines:
- Write clear, concise descriptions suitable for a developer audience.
- Use proper Markdown formatting compatible with Azure DevOps Wiki.
- When describing function parameters and return values, be precise.
- Identify potential edge cases, error conditions, and usage patterns.
- Never include placeholder text like "TODO" or "implement this".
- If the code metadata is incomplete, describe what is observable.
- Keep prose technical and direct. Avoid marketing language.
"""


def generate_function_description(func: FunctionInfo, settings: AppConfig) -> str:
    """Generate a narrative description for a single function."""
    prompt = _build_function_prompt(func)
    return complete_with_foundry(DOCUMENTATION_SYSTEM_PROMPT, prompt, settings)


def generate_class_description(cls: ClassInfo, settings: AppConfig) -> str:
    """Generate a narrative description for a class and its methods."""
    prompt = _build_class_prompt(cls)
    return complete_with_foundry(DOCUMENTATION_SYSTEM_PROMPT, prompt, settings)


def generate_module_overview(module: ModuleInfo, settings: AppConfig) -> str:
    """Generate a high-level overview of what the module does."""
    prompt = _build_module_overview_prompt(module)
    return complete_with_foundry(DOCUMENTATION_SYSTEM_PROMPT, prompt, settings)


def _build_function_prompt(func: FunctionInfo) -> str:
    params = ', '.join(
        f'{p.name}: {p.type_annotation or "Any"}'
        + (f' = {p.default_value}' if p.default_value else '')
        for p in func.parameters
    )
    return f"""Describe the following Python function for Azure DevOps Wiki documentation:

Function: {func.name}({params})
File: {func.file_path}:{func.line_number}
Return Type: {func.return_type or 'None'}
Decorators: {func.decorators or 'None'}
Docstring: {func.docstring or 'None'}"""


def _build_class_prompt(cls: ClassInfo) -> str:
    methods = '\n'.join(
        f'  - {m.name}({", ".join(p.name for p in m.parameters)}) -> {m.return_type or "None"}'
        for m in cls.methods
    )
    return f"""Describe the following Python class for Azure DevOps Wiki documentation:

Class: {cls.name}
File: {cls.file_path}:{cls.line_number}
Base Classes: {cls.base_classes or 'None'}
Decorators: {cls.decorators or 'None'}
Docstring: {cls.docstring or 'None'}
Methods:
{methods or '  (none)'}"""


def _build_module_overview_prompt(module: ModuleInfo) -> str:
    funcs = ', '.join(f.name for f in module.functions) or '(none)'
    classes = ', '.join(c.name for c in module.classes) or '(none)'
    imports = ', '.join(module.imports[:15]) or '(none)'
    return f"""Provide a high-level overview of the following Python module:

File: {module.file_path}
Functions: {funcs}
Classes: {classes}
Key Imports: {imports}"""
