"""SCIM 2.0 Pydantic core specifications (RFC 7643)."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class ScimName(BaseModel):
    formatted: str | None = None
    familyName: str
    givenName: str


class ScimMeta(BaseModel):
    resourceType: str = "User"
    created: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lastModified: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    location: str | None = None


class ScimUserBase(BaseModel):
    schemas: list[str] = ["urn:ietf:params:scim:schemas:core:2.0:User"]
    userName: str = Field(..., description="Unique UPN or email identifier")
    name: ScimName
    displayName: str | None = None
    active: bool = True


class ScimUserCreate(ScimUserBase):
    pass


class ScimUserResponse(ScimUserBase):
    id: str = Field(..., description="Resource GUID assigned by the SCIM gateway")
    meta: ScimMeta = Field(default_factory=ScimMeta)


class ListResponse(BaseModel):
    schemas: list[str] = ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    totalResults: int
    itemsPerPage: int
    startIndex: int
    Resources: list[ScimUserResponse] = []


class PatchOperation(BaseModel):
    op: str = Field(..., description="Operation: add, remove, replace")
    path: str | None = None
    value: str | bool | dict | list | None = None


class PatchRequest(BaseModel):
    schemas: list[str] = ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]
    Operations: list[PatchOperation]


class ScimError(BaseModel):
    schemas: list[str] = ["urn:ietf:params:scim:api:messages:2.0:Error"]
    status: str
    detail: str
    scimType: str | None = None
