"""Pydantic models for the mock identity document."""

from pydantic import BaseModel, ConfigDict, Field


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str = Field(min_length=1, description="Document id and Cosmos partition key value")
    display_name: str | None = Field(default=None, alias="displayName")

    def to_cosmos_item(self) -> dict[str, object]:
        item: dict[str, object] = {"id": self.id}
        if self.display_name is not None:
            item["displayName"] = self.display_name
        return item


class IdentityPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    display_name: str | None = Field(default=None, alias="displayName")
