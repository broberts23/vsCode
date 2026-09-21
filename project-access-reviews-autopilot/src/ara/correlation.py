"""Correlation key helpers for Slack message ↔ review-item mapping."""

from __future__ import annotations

import re

_CORRELATION_RE = re.compile(r"^ara-[a-z0-9-]+$", re.IGNORECASE)


def normalize_correlation_id(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ValueError("correlation id is empty")
    return value


def is_valid_correlation_id(raw: str) -> bool:
    try:
        value = normalize_correlation_id(raw)
    except ValueError:
        return False
    return bool(_CORRELATION_RE.match(value)) or value.startswith("ara-sim-")


def slack_action_value(correlation_id: str, decision: str) -> str:
    return f"{normalize_correlation_id(correlation_id)}|{decision}"


def parse_slack_action_value(value: str) -> tuple[str, str]:
    parts = (value or "").split("|", 1)
    if len(parts) != 2:
        raise ValueError("Slack action value must be correlationId|Decision")
    correlation_id, decision = parts[0].strip(), parts[1].strip()
    if not correlation_id or decision not in {"Approve", "Deny"}:
        raise ValueError("Invalid Slack action value")
    return correlation_id, decision
