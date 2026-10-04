"""HTTP seam: Slack-only Inbox; Operator inject via simulate; no pending UI."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("ARA_AUTH_BYPASS", "true")
    from ara.settings import get_settings

    get_settings.cache_clear()
    from api.main import app

    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_pending_route_absent(client: TestClient) -> None:
    response = client.get("/api/pending")
    assert response.status_code == 404


def test_health_ok(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_simulate_publishes_review_work(client: TestClient) -> None:
    published: list[str] = []

    def fake_publish(_settings: object, work: object) -> None:
        published.append(work.correlation_id)  # type: ignore[attr-defined]

    with (
        patch("api.main.ensure_local_entities"),
        patch("api.main.publish_review_work", side_effect=fake_publish),
    ):
        response = client.post("/api/simulate", json={"include_poison": False})

    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 3
    assert "ara-sim-pending-001" in body["published"]
    assert "ara-sim-poison-001" not in body["published"]
    assert published == body["published"]


def test_store_has_no_list_pending_helper() -> None:
    from ara.cosmos_store import CosmosCorrelationStore

    assert not hasattr(CosmosCorrelationStore, "list_pending")
