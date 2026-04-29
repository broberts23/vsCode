"""Simple response scrubbing.

PowerShell bridge:
- This is the same idea as running a final string-replacement pass before writing output.
"""

from __future__ import annotations


def mask_answer(answer: str) -> str:
    # Start with a narrow, predictable masking rule before introducing broader redaction patterns.
    return answer.replace('@contosolab.onmicrosoft.com', '@redacted.example')