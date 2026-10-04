"""Domain/API seam: Apply Justification stub and Lab Identity Map."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

from ara.correlation import slack_action_value
from ara.identity_map import LabIdentityMap
from ara.models import (
    ApplyDecisionMessage,
    CorrelationDocument,
    DecisionAction,
    ReviewStatus,
)
from ara.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = ROOT / "config" / "simulated-events"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("ARA_AUTH_BYPASS", "true")
    monkeypatch.setenv("LAB_IDENTITY_MAP_SLACK_USER_ID", "U_LAB_SHARED")
    monkeypatch.setenv(
        "LAB_APPLY_JUSTIFICATION",
        "Lab simulated apply; Justification stub.",
    )
    from ara.settings import get_settings

    get_settings.cache_clear()
    from api.main import app

    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_lab_identity_map_resolves_all_reviewers_to_same_slack_id() -> None:
    mapper = LabIdentityMap(slack_user_id="U_LAB_SHARED")
    assert mapper.resolve_slack_user_id("sam.approver@contoso.lab") == "U_LAB_SHARED"
    assert mapper.resolve_slack_user_id("other.reviewer@contoso.lab") == "U_LAB_SHARED"
    assert mapper.resolve_slack_user_id("") == "U_LAB_SHARED"


def test_apply_message_includes_justification_distinct_from_decision() -> None:
    apply = ApplyDecisionMessage(
        correlationId="ara-sim-pending-001",
        decision=DecisionAction.APPROVE,
        decidedBy="decider",
        justification="Lab simulated apply; Justification stub.",
    )
    assert apply.justification == "Lab simulated apply; Justification stub."
    assert apply.decision == DecisionAction.APPROVE
    assert apply.justification != apply.decision.value


def test_correlation_document_can_store_justification() -> None:
    from ara.fixtures import load_fixture_by_stem

    work = load_fixture_by_stem(FIXTURES, "review-pending")
    doc = CorrelationDocument.from_work(work)
    assert doc.justification is None
    assert work.recommendation == "Approve"
    doc.status = ReviewStatus.APPLIED
    doc.decision = DecisionAction.DENY.value
    doc.justification = "Lab simulated apply; Justification stub."
    assert doc.decision != doc.justification
    assert doc.justification != work.recommendation


def test_slack_interaction_queues_apply_with_justification_stub(
    client: TestClient,
) -> None:
    published: list[ApplyDecisionMessage] = []

    def fake_publish(_settings: Settings, message: ApplyDecisionMessage) -> None:
        published.append(message)

    form = urlencode(
        {
            "payload": json.dumps(
                {
                    "type": "block_actions",
                    "user": {"id": "U_CLICKER", "username": "clicker"},
                    "channel": {"id": "C1"},
                    "message": {"ts": "1.2"},
                    "actions": [
                        {
                            "value": slack_action_value(
                                "ara-sim-pending-001", "Approve"
                            )
                        }
                    ],
                }
            )
        }
    )
    with patch("api.main.publish_apply_decision", side_effect=fake_publish):
        response = client.post(
            "/slack/interactions",
            content=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    assert response.status_code == 200
    assert len(published) == 1
    apply = published[0]
    assert apply.justification == "Lab simulated apply; Justification stub."
    assert apply.decision == DecisionAction.APPROVE
    assert apply.correlation_id == "ara-sim-pending-001"


def test_graph_client_stub_mentions_delegated_reviewer_only() -> None:
    from ara.review_client import GraphAccessReviewClient

    doc = (GraphAccessReviewClient.__doc__ or "").lower()
    assert "delegated" in doc
    assert "reviewer" in doc
    assert "not supported" in doc
    assert "managed identity" not in doc
