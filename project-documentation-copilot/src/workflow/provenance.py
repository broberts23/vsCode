"""Provenance recording for the documentation copilot.

Emits structured log events for each step of the documentation lifecycle:
code scan → LLM generation → wiki publish. Enables observability via
Application Insights when deployed on Foundry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import time
import uuid

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ProvenanceEvent:
    event_type: str
    correlation_id: str
    details: dict[str, object] = field(default_factory=dict)
    timestamp_ms: int = 0


def record_event(event_type: str, correlation_id: str, **details: object) -> None:
    """Emit a structured provenance event to the log."""
    event = ProvenanceEvent(
        event_type=event_type,
        correlation_id=correlation_id,
        details=details,
        timestamp_ms=int(time.time() * 1000),
    )
    logger.info(
        'provenance: %s',
        json.dumps({
            'event_type': event.event_type,
            'correlation_id': event.correlation_id,
            'timestamp_ms': event.timestamp_ms,
            **{k: str(v) for k, v in event.details.items()},
        }, default=str),
    )


def new_correlation_id() -> str:
    return str(uuid.uuid4())
