"""Local fallback summarization helper.

PowerShell bridge:
- List comprehensions are compact loops that build a new list.
- `any(...)` is similar to "does at least one condition match" across a collection.
"""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ingest.graph_ingest import GovernanceDocument


def summarize_for_prompt(prompt: str, documents: list[GovernanceDocument]) -> str:
    # Split the prompt into simple keywords for a lightweight local matching strategy.
    keywords = [word.lower() for word in prompt.split() if len(word) > 3]
    matched = [document for document in documents if any(keyword in document.content.lower() or keyword in document.title.lower() for keyword in keywords)]
    selected = matched[:3] if matched else documents[:3]

    lines = [f"Prompt: {prompt}", "Grounded facts:"]
    for document in selected:
        lines.append(f"- {document.title}: {document.content}")

    return "\n".join(lines)