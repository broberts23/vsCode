"""Simple output scrubbing.

Redacts sensitive strings from generated output before publishing.
Adapted from `project-identity-security-copilot-v2`.
"""

from __future__ import annotations


def mask_answer(answer: str) -> str:
    """Redact predictable sensitive strings from final output."""
    masked = answer.replace('Authorization: Basic', 'Authorization: [REDACTED]')
    masked = masked.replace('AZURE_DEVOPS_PAT=', 'AZURE_DEVOPS_PAT=[REDACTED]')
    return masked
