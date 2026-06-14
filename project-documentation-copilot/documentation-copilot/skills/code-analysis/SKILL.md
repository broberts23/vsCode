---
name: code-analysis
description: Guidelines for analyzing Python source code to extract accurate metadata for documentation generation.
---

# Code Analysis Skill

## Purpose
This skill governs how the Documentation Copilot analyzes Python source code to produce structured metadata that feeds wiki generation. It ensures extraction is complete, accurate, and safe.

## Guidelines

### Extraction Standards
- Parse ALL Python files in the target repository, excluding virtual environments and cache directories.
- For each module, extract: functions (with signatures, decorators, return types, docstrings), classes (with base classes, decorators, methods, docstrings), and imports.
- Parameter type annotations and default values MUST be captured when present.
- Handle `SyntaxError` gracefully — skip unparseable files and log a warning.

### Dependency Resolution
- Classify imports as internal (within the project namespace) or external (third-party/stdlib).
- Internal packages are identified by matching import prefixes against discovered module paths.
- External dependencies include both third-party packages and Python standard library modules.

### Safety Constraints
- Never execute or import the scanned code. Analysis is static (AST-based) only.
- Skip files in `.git`, `.venv`, `venv`, `__pycache__`, `.pytest_cache`, `node_modules`, `.tox`, `build`, `dist`, `.eggs`.
- Do not extract sensitive values like secrets, tokens, or API keys that may appear in source code.
- Limit per-module import analysis to the first 50 unique imports to avoid noise from large modules.

### Metadata Completeness
- Every extracted function and class MUST include its file path and line number.
- Docstrings are extracted as-is — do not modify, summarize, or interpret them.
- The `@` prefix is included for decorator names to match Python convention.
