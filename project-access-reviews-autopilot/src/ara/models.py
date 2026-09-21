from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class ReviewEventType(str, Enum):
    PENDING = "ReviewPending"
    OVERDUE = "ReviewOverdue"
    NOT_STARTED = "ReviewNotStarted"
    REMINDER_DUE = "ReviewReminderDue"


class DecisionAction(str, Enum):
    APPROVE = "Approve"
    DENY = "Deny"


class ReviewStatus(str, Enum):
    PENDING = "pending"
    NOTIFIED = "notified"
    APPLIED = "applied"
    FAILED = "failed"


class ReviewWorkMessage(BaseModel):
    """Graph-shaped review work item. Fixtures map 1:1 onto this contract."""

    event_type: ReviewEventType = Field(alias="eventType")
    correlation_id: str = Field(alias="correlationId")
    definition_id: str = Field(alias="definitionId")
    instance_id: str = Field(alias="instanceId")
    decision_item_id: str = Field(alias="decisionItemId")
    principal_display_name: str = Field(alias="principalDisplayName")
    principal_upn: str = Field(alias="principalUpn")
    principal_object_id: str = Field(alias="principalObjectId")
    resource_display_name: str = Field(alias="resourceDisplayName")
    resource_type: str = Field(alias="resourceType")
    resource_id: str = Field(alias="resourceId")
    reviewer_display_name: str = Field(alias="reviewerDisplayName")
    reviewer_upn: str = Field(alias="reviewerUpn")
    due_date_time: datetime = Field(alias="dueDateTime")
    recommendation: str | None = None
    access_review_url: str = Field(default="", alias="accessReviewUrl")
    notes: str = ""
    force_poison: bool = Field(default=False, alias="forcePoison")

    model_config = {"populate_by_name": True}

    @field_validator("due_date_time", mode="before")
    @classmethod
    def parse_due(cls, value: Any) -> Any:
        if isinstance(value, str) and value.endswith("Z"):
            return value.replace("Z", "+00:00")
        return value

    def validate_for_worker(self) -> None:
        if self.force_poison:
            raise ValueError("forcePoison=true: intentional DLQ fixture")
        if not self.correlation_id.strip():
            raise ValueError("correlationId is required")
        if not self.decision_item_id.strip():
            raise ValueError("decisionItemId is required")
        if not self.principal_display_name.strip():
            raise ValueError("principalDisplayName is required")
        if not self.resource_display_name.strip():
            raise ValueError("resourceDisplayName is required")


class ApplyDecisionMessage(BaseModel):
    correlation_id: str = Field(alias="correlationId")
    decision: DecisionAction
    decided_by: str = Field(alias="decidedBy")
    decided_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        alias="decidedAt",
    )
    slack_user_id: str | None = Field(default=None, alias="slackUserId")
    slack_channel_id: str | None = Field(default=None, alias="slackChannelId")
    slack_message_ts: str | None = Field(default=None, alias="slackMessageTs")

    model_config = {"populate_by_name": True}


class CorrelationDocument(BaseModel):
    id: str
    partition_key: str
    correlation_id: str
    status: ReviewStatus
    event_type: str
    review_work: dict[str, Any]
    slack_channel_id: str | None = None
    slack_message_ts: str | None = None
    decision: str | None = None
    decided_by: str | None = None
    decided_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ttl: int = 60 * 60 * 24 * 30  # 30 days

    @classmethod
    def from_work(cls, work: ReviewWorkMessage) -> "CorrelationDocument":
        return cls(
            id=work.correlation_id,
            partition_key=work.correlation_id,
            correlation_id=work.correlation_id,
            status=ReviewStatus.PENDING,
            event_type=work.event_type.value,
            review_work=work.model_dump(by_alias=True, mode="json"),
        )


def new_correlation_id(prefix: str = "ara") -> str:
    return f"{prefix}-{uuid4()}"
