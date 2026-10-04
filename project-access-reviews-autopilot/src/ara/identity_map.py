"""Lab Identity Map: Entra Reviewer → Slack user id (sandbox stub)."""

from __future__ import annotations


class LabIdentityMap:
    """Resolves every Entra Reviewer to one configured Slack user id.

    Production end-state is SSO Identity (see ADR 0002), not this map.
    """

    def __init__(self, slack_user_id: str) -> None:
        if not slack_user_id.strip():
            raise ValueError("lab identity map slack user id is required")
        self._slack_user_id = slack_user_id.strip()

    def resolve_slack_user_id(self, reviewer_upn: str) -> str:
        _ = reviewer_upn
        return self._slack_user_id
