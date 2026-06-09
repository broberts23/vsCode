---
name: wiki-authoring
description: Guidelines for producing high-quality Azure DevOps Wiki markdown entries from Python source code.
---

# Wiki Authoring Skill

## Purpose
This skill governs how the Documentation Copilot produces Azure DevOps Wiki entries from code analysis. It ensures consistency, accuracy, and readability in all generated documentation.

## Guidelines

### Content Quality
- Every wiki page MUST include an Overview section, Function/Class details, Dependencies, and (where applicable) Workflow Diagrams.
- Descriptions MUST be technical, direct, and avoid marketing language.
- Never include placeholder text like "TODO", "TBD", or "implement this".
- If a function has no docstring, state "No docstring provided" rather than fabricating one.

### Markdown Standards
- Use Azure DevOps Wiki-compatible Markdown only.
- Code references must use backtick formatting (e.g., `function_name()`).
- Tables must have proper header row and separator row.
- Headings must be hierarchical (H1 for title, H2 for sections, H3 for individual items).

### Diagram Inclusion
- Modules with 3+ functions or 1+ classes MUST include a Mermaid workflow diagram.
- Class diagrams are required when 2+ classes are defined in a module.
- Diagrams must use the `::: mermaid` fence for Azure DevOps Wiki compatibility.
- Use `graph` (not `flowchart`) for Mermaid flowcharts — Azure DevOps Wiki does not support the `flowchart` keyword.

### Publishing Rules
- When updating an existing page, fetch the current version (ETag) first and pass it in the If-Match header to prevent conflicts.
- Wiki page paths follow the pattern: `API-Reference/{TargetName}/{ModuleName}`.
- Log all publish operations with the correlation ID for provenance tracking.
