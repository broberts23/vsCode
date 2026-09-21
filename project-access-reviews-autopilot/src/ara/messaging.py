"""Service Bus publish/receive. Emulator uses connection string; Azure uses MI."""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from typing import Iterator

from azure.identity import DefaultAzureCredential
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from azure.servicebus.management import ServiceBusAdministrationClient

from ara.models import ApplyDecisionMessage, ReviewWorkMessage
from ara.settings import Settings

logger = logging.getLogger(__name__)


def _client(settings: Settings) -> ServiceBusClient:
    if settings.use_service_bus_emulator:
        return ServiceBusClient.from_connection_string(
            settings.service_bus_connection_string
        )
    if not settings.service_bus_fully_qualified_namespace:
        raise RuntimeError(
            "SERVICE_BUS_FULLY_QUALIFIED_NAMESPACE is required when not using the emulator"
        )
    credential = DefaultAzureCredential()
    return ServiceBusClient(
        fully_qualified_namespace=settings.service_bus_fully_qualified_namespace,
        credential=credential,
    )


@contextmanager
def service_bus_client(settings: Settings) -> Iterator[ServiceBusClient]:
    client = _client(settings)
    try:
        yield client
    finally:
        client.close()


def publish_review_work(settings: Settings, work: ReviewWorkMessage) -> None:
    body = work.model_dump_json(by_alias=True)
    message = ServiceBusMessage(
        body,
        content_type="application/json",
        subject=work.event_type.value,
        correlation_id=work.correlation_id,
        application_properties={"eventType": work.event_type.value},
    )
    with service_bus_client(settings) as client:
        with client.get_topic_sender(topic_name=settings.service_bus_topic) as sender:
            sender.send_messages(message)
    logger.info(
        "Published %s correlationId=%s",
        work.event_type.value,
        work.correlation_id,
    )


def publish_apply_decision(settings: Settings, apply: ApplyDecisionMessage) -> None:
    body = apply.model_dump_json(by_alias=True)
    message = ServiceBusMessage(
        body,
        content_type="application/json",
        subject="ApplyDecision",
        correlation_id=apply.correlation_id,
        application_properties={"eventType": "ApplyDecision"},
    )
    with service_bus_client(settings) as client:
        with client.get_topic_sender(topic_name=settings.service_bus_topic) as sender:
            sender.send_messages(message)
    logger.info("Published ApplyDecision correlationId=%s", apply.correlation_id)


def parse_review_work(body: bytes | str) -> ReviewWorkMessage:
    text = body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else body
    return ReviewWorkMessage.model_validate(json.loads(text))


def parse_apply_decision(body: bytes | str) -> ApplyDecisionMessage:
    text = body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else body
    return ApplyDecisionMessage.model_validate(json.loads(text))


def ensure_local_entities(settings: Settings) -> None:
    """Best-effort topic/subscription create for the emulator. No-op on Azure."""
    if not settings.use_service_bus_emulator:
        return
    try:
        from azure.servicebus.management import SqlRuleFilter

        admin = ServiceBusAdministrationClient.from_connection_string(
            settings.service_bus_connection_string
        )
        try:
            admin.get_topic(settings.service_bus_topic)
        except Exception:
            admin.create_topic(settings.service_bus_topic)

        # Emulator validates against BrokeredMessage (Label), not Subject.
        for name, sql in (
            (
                settings.service_bus_subscription_notify,
                "sys.Label <> 'ApplyDecision'",
            ),
            (
                settings.service_bus_subscription_apply,
                "sys.Label = 'ApplyDecision'",
            ),
        ):
            try:
                admin.get_subscription(settings.service_bus_topic, name)
            except Exception:
                admin.create_subscription(settings.service_bus_topic, name)
            try:
                admin.delete_rule(settings.service_bus_topic, name, "$Default")
            except Exception:
                pass
            try:
                admin.get_rule(settings.service_bus_topic, name, "filter")
            except Exception:
                admin.create_rule(
                    settings.service_bus_topic,
                    name,
                    "filter",
                    filter=SqlRuleFilter(sql),
                )
        admin.close()
    except Exception as exc:  # noqa: BLE001 — local convenience only
        logger.warning("Could not ensure Service Bus entities: %s", exc)
