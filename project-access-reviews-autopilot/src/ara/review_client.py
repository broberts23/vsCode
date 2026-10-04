"""Access-review apply boundary.

This lab ships SimulatedAccessReviewClient only. GraphAccessReviewClient is a
stub for a future tenant that has real access-review traffic and P2 licensing.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from ara.cosmos_store import CosmosCorrelationStore
from ara.models import DecisionAction

logger = logging.getLogger(__name__)


class IAccessReviewClient(ABC):
    @abstractmethod
    def apply_decision(
        self,
        *,
        correlation_id: str,
        decision: DecisionAction,
        decided_by: str,
        justification: str,
    ) -> None:
        raise NotImplementedError


class SimulatedAccessReviewClient(IAccessReviewClient):
    """Updates Cosmos. Does not call Microsoft Graph."""

    def __init__(self, store: CosmosCorrelationStore) -> None:
        self._store = store

    def apply_decision(
        self,
        *,
        correlation_id: str,
        decision: DecisionAction,
        decided_by: str,
        justification: str,
    ) -> None:
        self._store.mark_applied(
            correlation_id,
            decision=decision.value,
            decided_by=decided_by,
            justification=justification,
        )
        logger.info(
            "Simulated apply correlationId=%s decision=%s by=%s",
            correlation_id,
            decision.value,
            decided_by,
        )


class GraphAccessReviewClient(IAccessReviewClient):
    """Stub only. Not used at runtime in this lab.

    A future implementation must PATCH accessReviewInstanceDecisionItem with
    delegated AccessReview.ReadWrite.All as the Reviewer. Application
    permissions are not supported for that call. Do not wire this class into
    DI until SSO Identity (or equivalent) can obtain a Reviewer delegated token.
    """

    def apply_decision(
        self,
        *,
        correlation_id: str,
        decision: DecisionAction,
        decided_by: str,
        justification: str,
    ) -> None:
        raise NotImplementedError(
            "GraphAccessReviewClient is intentionally unimplemented. "
            f"Would apply {decision.value} for {correlation_id} by {decided_by} "
            f"with justification={justification!r}."
        )
