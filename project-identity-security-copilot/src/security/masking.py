"""Simple output scrubbing.

PowerShell bridge:
- Think of this as a final string cleanup step before writing objects or text to the
    pipeline.
- The goal is not broad data loss; it is a narrow and predictable final pass over the
    generated output.
"""

from __future__ import annotations


def mask_answer(answer: str) -> str:
    """Redact a few predictable sensitive strings from the final response.

    PowerShell bridge:
    - This is like applying a last string replacement pass before writing to output.
    - The function stays intentionally small so the masking rules are easy to audit.
    """

    # Apply the replacements one at a time so the behavior is obvious and easy to extend.
    masked = answer.replace('breakglass@contoso.com', 'breakglass@redacted.example')
    masked = masked.replace('automation-admin', 'automation-admin-redacted')
    return masked
