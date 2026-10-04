"""Inbox seam: Lab Identity Map reaches Slack delivery payload."""

from pathlib import Path

from ara.fixtures import load_fixture_by_stem
from ara.slack_client import build_review_blocks

FIXTURES = Path(__file__).resolve().parents[1] / "config" / "simulated-events"


def test_review_blocks_mention_lab_mapped_reviewer() -> None:
    work = load_fixture_by_stem(FIXTURES, "review-pending")
    blocks = build_review_blocks(work, reviewer_slack_user_id="U_LAB_SHARED")
    rendered = str(blocks)
    assert "<@U_LAB_SHARED>" in rendered
    assert "Lab Identity Map" in rendered
