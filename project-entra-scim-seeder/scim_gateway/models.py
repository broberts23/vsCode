"""Pydantic document model for local identity state stored in Cosmos DB."""

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field


class LocalUser(BaseModel):
    """Tracks identity state synced from Entra ID via SCIM.

    Stored as a JSON document in Cosmos DB. `userName` is the partition key.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    userName: str
    givenName: str
    familyName: str
    displayName: str | None = None
    active: bool = True
    entraId: str | None = None
    created: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lastModified: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_scim(self, location_root: str = "/scim/v2/Users") -> dict:
        """Render the stored document as a SCIM 2.0 User response dict."""
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": self.id,
            "userName": self.userName,
            "name": {
                "formatted": f"{self.givenName} {self.familyName}",
                "givenName": self.givenName,
                "familyName": self.familyName,
            },
            "displayName": self.displayName,
            "active": self.active,
            "meta": {
                "resourceType": "User",
                "created": self.created,
                "lastModified": self.lastModified,
                "location": f"{location_root}/{self.id}",
            },
        }
