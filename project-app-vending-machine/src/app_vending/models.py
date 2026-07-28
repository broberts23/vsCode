from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class VendRequestBody(BaseModel):
    offeringId: str
    displayName: str
    owners: list[str] = Field(default_factory=list)
    justification: str
    callbackUrl: HttpUrl | None = None
    callbackSecret: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class VendAcceptedResponse(BaseModel):
    requestId: str
    status: str = "accepted"
    statusUrl: str
    pollAfterSeconds: int = 5


class VendStatusResponse(BaseModel):
    requestId: str
    status: str
    offeringId: str | None = None
    executionMode: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    createdAt: str | None = None
    completedAt: str | None = None


class CallbackPayload(BaseModel):
    requestId: str
    status: str
    offeringId: str
    executionMode: str
    result: dict[str, Any] | None = None
    error: str | None = None
