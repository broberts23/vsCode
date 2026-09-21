"""HTTP API: pending list, simulate inject, Slack interactivity."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

_src = Path(__file__).resolve().parents[1] / "src"
if _src.is_dir() and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ara.auth import require_oidc
from ara.correlation import parse_slack_action_value
from ara.cosmos_store import CosmosCorrelationStore
from ara.fixtures import load_all_fixtures, load_fixture_by_stem
from ara.messaging import ensure_local_entities, publish_apply_decision, publish_review_work
from ara.models import ApplyDecisionMessage, DecisionAction
from ara.secrets import resolve_slack_signing_secret
from ara.settings import Settings, get_settings
from ara.slack_sig import SlackSignatureError, verify_slack_signature

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ara.api")

app = FastAPI(
    title="Access Reviews Autopilot API",
    description=(
        "OIDC-protected API for a Slack access-review inbox. "
        "All review triggers are simulated fixtures — no live Graph polling."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def settings_dep() -> Settings:
    return get_settings()


def store_dep(settings: Settings = Depends(settings_dep)) -> CosmosCorrelationStore:
    return CosmosCorrelationStore(settings)


class SimulateRequest(BaseModel):
    fixture: str | None = Field(
        default=None,
        description="Fixture stem, e.g. review-pending. Omit to publish all non-poison fixtures.",
    )
    include_poison: bool = False


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/pending")
def list_pending(
    request: Request,
    settings: Settings = Depends(settings_dep),
    store: CosmosCorrelationStore = Depends(store_dep),
) -> dict[str, Any]:
    require_oidc(request, settings)
    items = store.list_pending()
    return {
        "count": len(items),
        "items": [item.model_dump(mode="json") for item in items],
    }


@app.post("/api/simulate")
def simulate(
    body: SimulateRequest,
    request: Request,
    settings: Settings = Depends(settings_dep),
) -> dict[str, Any]:
    """Inject Graph-shaped fixtures onto Service Bus. OIDC-protected."""
    require_oidc(request, settings)
    ensure_local_entities(settings)

    published: list[str] = []
    if body.fixture:
        work = load_fixture_by_stem(settings.fixtures_path, body.fixture)
        publish_review_work(settings, work)
        published.append(work.correlation_id)
    else:
        for work in load_all_fixtures(settings.fixtures_path):
            if work.force_poison and not body.include_poison:
                continue
            publish_review_work(settings, work)
            published.append(work.correlation_id)

    return {"published": published, "count": len(published)}


@app.post("/slack/interactions")
async def slack_interactions(
    request: Request,
    settings: Settings = Depends(settings_dep),
) -> JSONResponse:
    raw = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")
    signing_secret = resolve_slack_signing_secret(settings)

    if settings.ara_auth_bypass and not signing_secret:
        logger.warning("Skipping Slack signature verify (local bypass, no secret)")
    else:
        try:
            verify_slack_signature(
                signing_secret=signing_secret,
                timestamp=timestamp,
                body=raw,
                signature=signature,
            )
        except SlackSignatureError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    form = parse_qs(raw.decode("utf-8"))
    payload_raw = form.get("payload", ["{}"])[0]
    payload = json.loads(payload_raw)

    if payload.get("type") == "url_verification":
        return JSONResponse({"challenge": payload.get("challenge")})

    actions = payload.get("actions") or []
    if not actions:
        return JSONResponse({"ok": True})

    action = actions[0]
    try:
        correlation_id, decision = parse_slack_action_value(action.get("value", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    user = payload.get("user") or {}
    channel = payload.get("channel") or {}
    message = payload.get("message") or {}
    decided_by = user.get("username") or user.get("name") or user.get("id") or "slack-user"

    apply = ApplyDecisionMessage(
        correlationId=correlation_id,
        decision=DecisionAction(decision),
        decidedBy=decided_by,
        slackUserId=user.get("id"),
        slackChannelId=channel.get("id"),
        slackMessageTs=message.get("ts"),
    )
    publish_apply_decision(settings, apply)
    logger.info(
        "Queued apply-decision correlationId=%s decision=%s",
        correlation_id,
        decision,
    )
    return JSONResponse(
        {
            "response_type": "ephemeral",
            "text": f"Queued {decision} for `{correlation_id}` (simulated apply).",
        }
    )


@app.get("/api/correlations/{correlation_id}")
def get_correlation(
    correlation_id: str,
    request: Request,
    settings: Settings = Depends(settings_dep),
    store: CosmosCorrelationStore = Depends(store_dep),
) -> dict[str, Any]:
    require_oidc(request, settings)
    doc = store.get(correlation_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="Not found")
    return doc.model_dump(mode="json")
