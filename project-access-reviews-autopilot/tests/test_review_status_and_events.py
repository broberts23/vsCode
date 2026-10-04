"""Domain seam: Review Status Received; supported Review Event kinds."""

from pathlib import Path

import pytest

from ara.fixtures import load_fixture_by_stem
from ara.models import CorrelationDocument, ReviewEventType, ReviewStatus

FIXTURES = Path(__file__).resolve().parents[1] / "config" / "simulated-events"


def test_review_status_has_no_pending_value() -> None:
    values = {member.value for member in ReviewStatus}
    assert "pending" not in values
    assert ReviewStatus.RECEIVED.value == "received"
    assert {m.value for m in ReviewStatus} == {
        "received",
        "notified",
        "applied",
        "failed",
    }


def test_from_work_starts_as_received() -> None:
    work = load_fixture_by_stem(FIXTURES, "review-pending")
    doc = CorrelationDocument.from_work(work)
    assert doc.status == ReviewStatus.RECEIVED
    assert doc.status.value == "received"
    assert doc.event_type == "ReviewPending"


def test_supported_review_events_only() -> None:
    names = {member.name for member in ReviewEventType}
    values = {member.value for member in ReviewEventType}
    assert names == {"PENDING", "OVERDUE", "REMINDER_DUE"}
    assert values == {"ReviewPending", "ReviewOverdue", "ReviewReminderDue"}
    assert "NOT_STARTED" not in names
    assert "ReviewNotStarted" not in values


def test_review_not_started_rejected() -> None:
    work = load_fixture_by_stem(FIXTURES, "review-pending")
    payload = work.model_dump(by_alias=True, mode="json")
    payload["eventType"] = "ReviewNotStarted"
    with pytest.raises(ValueError):
        work.__class__.model_validate(payload)
