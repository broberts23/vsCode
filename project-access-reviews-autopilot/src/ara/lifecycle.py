"""Review Work notify lifecycle: idempotent refresh, nudge, no-reopen."""

from __future__ import annotations

import logging
from typing import Literal, Protocol

from ara.identity_map import LabIdentityMap
from ara.models import CorrelationDocument, ReviewEventType, ReviewStatus, ReviewWorkMessage
from ara.settings import Settings

logger = logging.getLogger(__name__)

NotifyOutcome = Literal["posted", "nudged", "refreshed", "skipped_terminal"]


class CorrelationStore(Protocol):
    def get(self, correlation_id: str) -> CorrelationDocument | None: ...

    def upsert_from_work(self, work: ReviewWorkMessage) -> CorrelationDocument: ...

    def mark_notified(
        self,
        correlation_id: str,
        *,
        channel_id: str,
        message_ts: str,
    ) -> CorrelationDocument: ...

    def mark_failed(self, correlation_id: str) -> CorrelationDocument: ...


class ReviewInbox(Protocol):
    def post_review_card(self, work: ReviewWorkMessage) -> tuple[str, str]: ...

    def nudge_review_card(
        self,
        *,
        channel_id: str,
        message_ts: str,
        work: ReviewWorkMessage,
    ) -> None: ...


def should_mark_failed(*, delivery_count: int, max_delivery_count: int) -> bool:
    return delivery_count >= max_delivery_count


def process_review_event(
    store: CorrelationStore,
    slack: ReviewInbox,
    work: ReviewWorkMessage,
    settings: Settings,
) -> NotifyOutcome:
    work.validate_for_worker()
    mapped_slack_user_id = LabIdentityMap(
        settings.lab_identity_map_slack_user_id
    ).resolve_slack_user_id(work.reviewer_upn)

    existing = store.get(work.correlation_id)
    if existing is not None and existing.status in (
        ReviewStatus.APPLIED,
        ReviewStatus.FAILED,
    ):
        logger.info(
            "Skipping Review Event for terminal Review Work correlationId=%s status=%s",
            work.correlation_id,
            existing.status.value,
        )
        return "skipped_terminal"

    doc = store.upsert_from_work(work)

    if doc.status == ReviewStatus.NOTIFIED and doc.slack_channel_id and doc.slack_message_ts:
        if work.event_type in (ReviewEventType.OVERDUE, ReviewEventType.REMINDER_DUE):
            slack.nudge_review_card(
                channel_id=doc.slack_channel_id,
                message_ts=doc.slack_message_ts,
                work=work,
            )
            logger.info(
                "Nudged Inbox correlationId=%s event=%s labMappedSlackUserId=%s",
                work.correlation_id,
                work.event_type.value,
                mapped_slack_user_id,
            )
            return "nudged"
        logger.info(
            "Refreshed open Review Work correlationId=%s event=%s",
            work.correlation_id,
            work.event_type.value,
        )
        return "refreshed"

    channel_id, message_ts = slack.post_review_card(work)
    store.mark_notified(
        work.correlation_id,
        channel_id=channel_id,
        message_ts=message_ts,
    )
    logger.info(
        "Notified Slack correlationId=%s reviewer=%s labMappedSlackUserId=%s",
        work.correlation_id,
        work.reviewer_upn,
        mapped_slack_user_id,
    )
    return "posted"
