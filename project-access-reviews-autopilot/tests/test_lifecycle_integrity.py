"""Domain/worker seam: idempotent Review Events, nudge, no-reopen, Failed."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ara.fixtures import load_fixture_by_stem
from ara.lifecycle import process_review_event, record_terminal_failure, should_mark_failed
from ara.models import CorrelationDocument, ReviewStatus, ReviewWorkMessage
from ara.settings import Settings

FIXTURES = Path(__file__).resolve().parents[1] / "config" / "simulated-events"


@dataclass
class FakeStore:
    docs: dict[str, CorrelationDocument] = field(default_factory=dict)

    def get(self, correlation_id: str) -> CorrelationDocument | None:
        return self.docs.get(correlation_id)

    def upsert_from_work(self, work: ReviewWorkMessage) -> CorrelationDocument:
        existing = self.docs.get(work.correlation_id)
        if existing is None:
            doc = CorrelationDocument.from_work(work)
            self.docs[work.correlation_id] = doc
            return doc
        if existing.status in (ReviewStatus.APPLIED, ReviewStatus.FAILED):
            return existing
        existing.event_type = work.event_type.value
        existing.review_work = work.model_dump(by_alias=True, mode="json")
        existing.updated_at = datetime.now(timezone.utc)
        self.docs[work.correlation_id] = existing
        return existing

    def mark_notified(
        self,
        correlation_id: str,
        *,
        channel_id: str,
        message_ts: str,
    ) -> CorrelationDocument:
        doc = self.docs[correlation_id]
        doc.status = ReviewStatus.NOTIFIED
        doc.slack_channel_id = channel_id
        doc.slack_message_ts = message_ts
        doc.updated_at = datetime.now(timezone.utc)
        return doc

    def mark_failed(self, correlation_id: str) -> CorrelationDocument:
        doc = self.docs[correlation_id]
        if doc.status == ReviewStatus.APPLIED:
            return doc
        doc.status = ReviewStatus.FAILED
        doc.updated_at = datetime.now(timezone.utc)
        return doc


def _settings() -> Settings:
    return Settings(
        lab_identity_map_slack_user_id="U_LAB_SHARED",
        slack_channel_id="C_LAB",
    )


def _slack() -> MagicMock:
    slack = MagicMock()
    slack.post_review_card.return_value = ("C_LAB", "111.222")
    return slack


def test_first_event_posts_and_marks_notified() -> None:
    store = FakeStore()
    slack = _slack()
    work = load_fixture_by_stem(FIXTURES, "review-pending")
    outcome = process_review_event(store, slack, work, _settings())
    assert outcome == "posted"
    assert store.docs[work.correlation_id].status == ReviewStatus.NOTIFIED
    slack.post_review_card.assert_called_once()
    slack.nudge_review_card.assert_not_called()


def test_republish_open_work_refreshes_without_second_post() -> None:
    store = FakeStore()
    slack = _slack()
    work = load_fixture_by_stem(FIXTURES, "review-pending")
    process_review_event(store, slack, work, _settings())
    slack.reset_mock()
    again = work.model_copy(
        update={"notes": "replayed pending"},
    )
    outcome = process_review_event(store, slack, again, _settings())
    assert outcome == "refreshed"
    assert store.docs[work.correlation_id].review_work["notes"] == "replayed pending"
    assert store.docs[work.correlation_id].status == ReviewStatus.NOTIFIED
    slack.post_review_card.assert_not_called()
    slack.nudge_review_card.assert_not_called()


def test_overdue_while_notified_nudges_existing_card() -> None:
    store = FakeStore()
    slack = _slack()
    pending = load_fixture_by_stem(FIXTURES, "review-pending")
    process_review_event(store, slack, pending, _settings())
    slack.reset_mock()
    overdue = load_fixture_by_stem(FIXTURES, "review-overdue")
    overdue = overdue.model_copy(update={"correlation_id": pending.correlation_id})
    outcome = process_review_event(store, slack, overdue, _settings())
    assert outcome == "nudged"
    assert store.docs[pending.correlation_id].event_type == "ReviewOverdue"
    slack.post_review_card.assert_not_called()
    slack.nudge_review_card.assert_called_once()
    args = slack.nudge_review_card.call_args.kwargs
    assert args["channel_id"] == "C_LAB"
    assert args["message_ts"] == "111.222"


def test_reminder_due_while_notified_nudges_existing_card() -> None:
    store = FakeStore()
    slack = _slack()
    pending = load_fixture_by_stem(FIXTURES, "review-pending")
    process_review_event(store, slack, pending, _settings())
    slack.reset_mock()
    reminder = load_fixture_by_stem(FIXTURES, "review-reminder-due")
    reminder = reminder.model_copy(update={"correlation_id": pending.correlation_id})
    outcome = process_review_event(store, slack, reminder, _settings())
    assert outcome == "nudged"
    assert store.docs[pending.correlation_id].event_type == "ReviewReminderDue"
    slack.nudge_review_card.assert_called_once()


def test_applied_work_does_not_reopen() -> None:
    store = FakeStore()
    slack = _slack()
    work = load_fixture_by_stem(FIXTURES, "review-pending")
    process_review_event(store, slack, work, _settings())
    doc = store.docs[work.correlation_id]
    doc.status = ReviewStatus.APPLIED
    doc.decision = "Approve"
    slack.reset_mock()
    overdue = load_fixture_by_stem(FIXTURES, "review-overdue")
    overdue = overdue.model_copy(update={"correlation_id": work.correlation_id})
    outcome = process_review_event(store, slack, overdue, _settings())
    assert outcome == "skipped_terminal"
    assert store.docs[work.correlation_id].status == ReviewStatus.APPLIED
    assert store.docs[work.correlation_id].decision == "Approve"
    slack.post_review_card.assert_not_called()
    slack.nudge_review_card.assert_not_called()


def test_mark_failed_sets_failed_status() -> None:
    store = FakeStore()
    work = load_fixture_by_stem(FIXTURES, "review-pending")
    store.upsert_from_work(work)
    store.mark_failed(work.correlation_id)
    assert store.docs[work.correlation_id].status == ReviewStatus.FAILED


def test_record_terminal_failure_for_poison_creates_failed_document() -> None:
    store = FakeStore()
    poison = load_fixture_by_stem(FIXTURES, "poison")
    assert should_mark_failed(delivery_count=10, max_delivery_count=10)
    marked = record_terminal_failure(
        store,
        work=poison,
        correlation_id=poison.correlation_id,
    )
    assert marked is True
    assert store.docs[poison.correlation_id].status == ReviewStatus.FAILED


def test_should_mark_failed_when_delivery_exhausted() -> None:
    assert should_mark_failed(delivery_count=10, max_delivery_count=10) is True
    assert should_mark_failed(delivery_count=9, max_delivery_count=10) is False
    assert should_mark_failed(delivery_count=1, max_delivery_count=10) is False


def test_poison_still_opt_in_on_simulate(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    monkeypatch.setenv("ARA_AUTH_BYPASS", "true")
    from ara.settings import get_settings

    get_settings.cache_clear()
    from api.main import app

    published: list[str] = []

    def fake_publish(_settings: Settings, work: ReviewWorkMessage) -> None:
        published.append(work.correlation_id)

    with (
        TestClient(app) as client,
        patch("api.main.ensure_local_entities"),
        patch("api.main.publish_review_work", side_effect=fake_publish),
    ):
        response = client.post("/api/simulate", json={"include_poison": False})
    get_settings.cache_clear()
    assert response.status_code == 200
    assert "ara-sim-poison-001" not in response.json()["published"]
