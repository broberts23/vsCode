"""Simple output scrubbing.

PowerShell bridge:
- Think of this as a final string cleanup step before writing objects or text to the pipeline.
"""

from __future__ import annotations


def mask_answer(answer: str) -> str:
    masked = answer.replace('breakglass@contoso.com', 'breakglass@redacted.example')
    masked = masked.replace('automation-admin', 'automation-admin-redacted')
    return masked
