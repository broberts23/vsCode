"""Unit tests — no Azure, no Slack required."""

from datetime import datetime, timezone

import pytest

from ara.correlation import (
    is_valid_correlation_id,
    normalize_correlation_id,
    parse_slack_action_value,
    slack_action_value,
)
from ara.fixtures import load_all_fixtures, load_fixture_by_stem
from ara.models import ReviewWorkMessage
from ara.slack_sig import SlackSignatureError, verify_slack_signature
from pathlib import Path


FIXTURES = Path(__file__).resolve().parents[1] / "config" / "simulated-events"


def test_normalize_correlation_id():
    assert normalize_correlation_id(" ara-sim-pending-001 ") == "ara-sim-pending-001"
    with pytest.raises(ValueError):
        normalize_correlation_id("  ")


def test_is_valid_correlation_id():
    assert is_valid_correlation_id("ara-sim-pending-001")
    assert is_valid_correlation_id("ara-abc-123")
    assert not is_valid_correlation_id("")


def test_slack_action_roundtrip():
    value = slack_action_value("ara-sim-pending-001", "Approve")
    cid, decision = parse_slack_action_value(value)
    assert cid == "ara-sim-pending-001"
    assert decision == "Approve"
    with pytest.raises(ValueError):
        parse_slack_action_value("nope")


def test_fixture_mapping_pending():
    work = load_fixture_by_stem(FIXTURES, "review-pending")
    assert work.event_type.value == "ReviewPending"
    assert work.correlation_id == "ara-sim-pending-001"
    assert work.principal_display_name == "Alex Reviewer"
    work.validate_for_worker()


def test_fixture_overdue_and_reminder():
    overdue = load_fixture_by_stem(FIXTURES, "review-overdue")
    reminder = load_fixture_by_stem(FIXTURES, "review-reminder-due")
    assert overdue.event_type.value == "ReviewOverdue"
    assert reminder.event_type.value == "ReviewReminderDue"


def test_poison_fails_worker_validation():
    poison = load_fixture_by_stem(FIXTURES, "poison")
    with pytest.raises(ValueError, match="forcePoison"):
        poison.validate_for_worker()


def test_load_all_fixtures():
    fixtures = load_all_fixtures(FIXTURES)
    assert len(fixtures) >= 4
    stems = {f.correlation_id for f in fixtures}
    assert "ara-sim-poison-001" in stems


def test_review_work_json_roundtrip():
    work = load_fixture_by_stem(FIXTURES, "review-pending")
    raw = work.model_dump_json(by_alias=True)
    again = ReviewWorkMessage.model_validate_json(raw)
    assert again.correlation_id == work.correlation_id
    assert again.due_date_time.replace(tzinfo=timezone.utc) == work.due_date_time.replace(
        tzinfo=timezone.utc
    )


def test_slack_signature_valid():
    import hashlib
    import hmac
    import time

    secret = "test_secret"
    ts = str(int(time.time()))
    body = "payload=%7B%7D"
    basestring = f"v0:{ts}:{body}".encode()
    digest = hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    verify_slack_signature(
        signing_secret=secret,
        timestamp=ts,
        body=body,
        signature=f"v0={digest}",
    )


def test_slack_signature_rejects_bad():
    import time

    with pytest.raises(SlackSignatureError):
        verify_slack_signature(
            signing_secret="test_secret",
            timestamp=str(int(time.time())),
            body="payload={}",
            signature="v0=deadbeef",
        )
