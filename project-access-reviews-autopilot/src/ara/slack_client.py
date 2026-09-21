"""Slack Block Kit posting. Without tokens, logs the payload (local dry run)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ara.correlation import slack_action_value
from ara.models import ReviewWorkMessage
from ara.settings import Settings

logger = logging.getLogger(__name__)


def build_review_blocks(work: ReviewWorkMessage) -> list[dict[str, Any]]:
    due = work.due_date_time.isoformat()
    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Access review: {work.event_type.value}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Principal*\n{work.principal_display_name}"},
                {"type": "mrkdwn", "text": f"*UPN*\n{work.principal_upn}"},
                {"type": "mrkdwn", "text": f"*Resource*\n{work.resource_display_name}"},
                {"type": "mrkdwn", "text": f"*Type*\n{work.resource_type}"},
                {"type": "mrkdwn", "text": f"*Due*\n{due}"},
                {
                    "type": "mrkdwn",
                    "text": f"*Recommendation*\n{work.recommendation or 'n/a'}",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Correlation*\n`{work.correlation_id}`\n{work.notes}",
            },
        },
        {
            "type": "actions",
            "block_id": "ara_decision",
            "elements": [
                {
                    "type": "button",
                    "action_id": "ara_approve",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "value": slack_action_value(work.correlation_id, "Approve"),
                },
                {
                    "type": "button",
                    "action_id": "ara_deny",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "style": "danger",
                    "value": slack_action_value(work.correlation_id, "Deny"),
                },
            ],
        },
    ]


def build_applied_blocks(
    work: ReviewWorkMessage,
    *,
    decision: str,
    decided_by: str,
) -> list[dict[str, Any]]:
    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Applied: {decision}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{work.principal_display_name}* on "
                    f"*{work.resource_display_name}*\n"
                    f"Decision by `{decided_by}` · `{work.correlation_id}`\n"
                    "_Simulated apply — Cosmos updated, Graph not called._"
                ),
            },
        },
    ]


class SlackNotifier:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def enabled(self) -> bool:
        return bool(self._settings.slack_bot_token and self._settings.slack_channel_id)

    def post_review_card(self, work: ReviewWorkMessage) -> tuple[str, str]:
        blocks = build_review_blocks(work)
        if not self.enabled:
            logger.info(
                "Slack dry-run (no bot token/channel). correlationId=%s blocks=%s",
                work.correlation_id,
                blocks,
            )
            return ("dry-run", f"local-{work.correlation_id}")

        payload = {
            "channel": self._settings.slack_channel_id,
            "text": f"Access review {work.event_type.value}: {work.principal_display_name}",
            "blocks": blocks,
        }
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                "https://slack.com/api/chat.postMessage",
                headers={
                    "Authorization": f"Bearer {self._settings.slack_bot_token}",
                    "Content-Type": "application/json; charset=utf-8",
                },
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        if not data.get("ok"):
            raise RuntimeError(f"Slack chat.postMessage failed: {data.get('error')}")
        return str(data["channel"]), str(data["ts"])

    def update_review_card(
        self,
        *,
        channel_id: str,
        message_ts: str,
        work: ReviewWorkMessage,
        decision: str,
        decided_by: str,
    ) -> None:
        blocks = build_applied_blocks(work, decision=decision, decided_by=decided_by)
        if not self.enabled or channel_id == "dry-run":
            logger.info(
                "Slack dry-run update correlationId=%s decision=%s",
                work.correlation_id,
                decision,
            )
            return

        payload = {
            "channel": channel_id,
            "ts": message_ts,
            "text": f"Applied {decision} for {work.correlation_id}",
            "blocks": blocks,
        }
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                "https://slack.com/api/chat.update",
                headers={
                    "Authorization": f"Bearer {self._settings.slack_bot_token}",
                    "Content-Type": "application/json; charset=utf-8",
                },
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        if not data.get("ok"):
            raise RuntimeError(f"Slack chat.update failed: {data.get('error')}")
