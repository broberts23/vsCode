"""KEDA-friendly worker: consume slack-notify and apply-decision subscriptions."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

_src = Path(__file__).resolve().parents[1] / "src"
if _src.is_dir() and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from ara.cosmos_store import CosmosCorrelationStore
from ara.lifecycle import process_review_event, should_mark_failed
from ara.messaging import (
    ensure_local_entities,
    parse_apply_decision,
    parse_review_work,
    service_bus_client,
)
from ara.models import ReviewWorkMessage
from ara.review_client import SimulatedAccessReviewClient
from ara.secrets import resolve_slack_bot_token
from ara.settings import Settings, get_settings
from ara.slack_client import SlackNotifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ara.worker")


def handle_notify(
    store: CosmosCorrelationStore,
    slack: SlackNotifier,
    work: ReviewWorkMessage,
    settings: Settings,
) -> None:
    process_review_event(store, slack, work, settings)


def handle_apply(
    store: CosmosCorrelationStore,
    review_client: SimulatedAccessReviewClient,
    slack: SlackNotifier,
    body: bytes | str,
) -> None:
    apply = parse_apply_decision(body)
    doc = store.get(apply.correlation_id)
    if doc is None:
        raise KeyError(f"Unknown correlationId {apply.correlation_id}")

    review_client.apply_decision(
        correlation_id=apply.correlation_id,
        decision=apply.decision,
        decided_by=apply.decided_by,
        justification=apply.justification,
    )

    work = ReviewWorkMessage.model_validate(doc.review_work)
    channel = apply.slack_channel_id or doc.slack_channel_id or "dry-run"
    ts = apply.slack_message_ts or doc.slack_message_ts or f"local-{apply.correlation_id}"
    slack.update_review_card(
        channel_id=channel,
        message_ts=ts,
        work=work,
        decision=apply.decision.value,
        decided_by=apply.decided_by,
    )
    logger.info("Applied decision correlationId=%s", apply.correlation_id)


def _message_body(message) -> bytes:
    body = message.body
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    return b"".join(bytes(chunk) for chunk in body)


def _delivery_count(message) -> int:
    count = getattr(message, "delivery_count", None)
    if count is None:
        return 1
    return int(count)


def _try_mark_failed(
    store: CosmosCorrelationStore,
    *,
    work: ReviewWorkMessage | None,
    correlation_id: str | None,
) -> None:
    if not correlation_id:
        return
    try:
        if store.get(correlation_id) is None and work is not None:
            store.upsert_from_work(work)
        store.mark_failed(correlation_id)
        logger.info("Marked Review Work Failed correlationId=%s", correlation_id)
    except KeyError:
        logger.warning(
            "Could not mark Failed; no correlation document correlationId=%s",
            correlation_id,
        )


def run_once(mode: str) -> int:
    settings = get_settings()
    if settings.slack_bot_token == "" and settings.key_vault_uri:
        settings.slack_bot_token = resolve_slack_bot_token(settings)

    ensure_local_entities(settings)
    store = CosmosCorrelationStore(settings)
    slack = SlackNotifier(settings)
    review_client = SimulatedAccessReviewClient(store)

    subscription = (
        settings.service_bus_subscription_notify
        if mode == "notify"
        else settings.service_bus_subscription_apply
    )

    processed = 0
    with service_bus_client(settings) as client:
        receiver = client.get_subscription_receiver(
            topic_name=settings.service_bus_topic,
            subscription_name=subscription,
            max_wait_time=5,
        )
        with receiver:
            for message in receiver:
                correlation_id: str | None = None
                notify_work: ReviewWorkMessage | None = None
                try:
                    raw = _message_body(message)
                    if mode == "notify":
                        notify_work = parse_review_work(raw)
                        correlation_id = notify_work.correlation_id
                        handle_notify(store, slack, notify_work, settings)
                    else:
                        apply = parse_apply_decision(raw)
                        correlation_id = apply.correlation_id
                        handle_apply(store, review_client, slack, raw)

                    receiver.complete_message(message)
                    processed += 1
                except Exception:
                    terminal = should_mark_failed(
                        delivery_count=_delivery_count(message),
                        max_delivery_count=settings.service_bus_max_delivery_count,
                    )
                    logger.exception(
                        "Failed processing message; terminal=%s",
                        terminal,
                    )
                    if terminal:
                        _try_mark_failed(
                            store,
                            work=notify_work,
                            correlation_id=correlation_id,
                        )
                        receiver.complete_message(message)
                    else:
                        receiver.abandon_message(message)
    return processed


def run_loop(mode: str, idle_sleep: float = 2.0) -> None:
    logger.info("Worker starting mode=%s", mode)
    while True:
        count = run_once(mode)
        if count == 0:
            time.sleep(idle_sleep)


def main() -> None:
    parser = argparse.ArgumentParser(description="ARA Service Bus worker")
    parser.add_argument(
        "--mode",
        choices=["notify", "apply"],
        required=True,
        help="Which subscription to consume",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process available messages once and exit (useful for jobs)",
    )
    args = parser.parse_args()
    if args.once:
        n = run_once(args.mode)
        logger.info("Processed %s messages", n)
    else:
        run_loop(args.mode)


if __name__ == "__main__":
    main()
