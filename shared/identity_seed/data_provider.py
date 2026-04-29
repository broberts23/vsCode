from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
from pathlib import Path
from typing import Any, Protocol


JsonDict = dict[str, Any]
BundleCollection = list[JsonDict]

COLLECTION_FILE_NAMES: dict[str, str] = {
    "users": "users.json",
    "groups": "groups.json",
    "roles": "roles.json",
    "access_reviews": "access_reviews.json",
    "incidents": "incidents.json",
    "approvals": "approvals.json",
    "evidence": "evidence.json",
}


class DataMode(StrEnum):
    SEED = "seed"
    GRAPH = "graph"
    HYBRID = "hybrid"


@dataclass(slots=True)
class IdentityDataBundle:
    users: list[JsonDict]
    groups: list[JsonDict]
    roles: list[JsonDict]
    access_reviews: list[JsonDict]
    incidents: list[JsonDict]
    approvals: list[JsonDict]
    evidence: list[JsonDict]

    def as_dict(self) -> JsonDict:
        return {
            "users": self.users,
            "groups": self.groups,
            "roles": self.roles,
            "access_reviews": self.access_reviews,
            "incidents": self.incidents,
            "approvals": self.approvals,
            "evidence": self.evidence,
        }


class IdentityDataProvider(Protocol):
    mode: DataMode

    def load_bundle(self) -> IdentityDataBundle:
        ...


class GraphCollectionFetcher(Protocol):
    def fetch_collection(self, resource_name: str) -> BundleCollection:
        ...


class FileSeedDataProvider:
    mode = DataMode.SEED

    def __init__(self, dataset_root: str | Path, collection_name: str = "seed") -> None:
        self._dataset_root = Path(dataset_root)
        self._seed_root = self._dataset_root / collection_name

    def load_bundle(self) -> IdentityDataBundle:
        return IdentityDataBundle(
            users=self._load_collection(COLLECTION_FILE_NAMES["users"]),
            groups=self._load_collection(COLLECTION_FILE_NAMES["groups"]),
            roles=self._load_collection(COLLECTION_FILE_NAMES["roles"]),
            access_reviews=self._load_collection(COLLECTION_FILE_NAMES["access_reviews"]),
            incidents=self._load_collection(COLLECTION_FILE_NAMES["incidents"]),
            approvals=self._load_collection(COLLECTION_FILE_NAMES["approvals"]),
            evidence=self._load_collection(COLLECTION_FILE_NAMES["evidence"]),
        )

    def _load_collection(self, file_name: str) -> list[JsonDict]:
        file_path = self._seed_root / file_name
        with file_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        if not isinstance(payload, list):
            raise ValueError(f"Expected a JSON array in {file_path}")

        return payload


class GraphBackedDataProvider:
    mode = DataMode.GRAPH

    def __init__(self, fetcher: GraphCollectionFetcher) -> None:
        self._fetcher = fetcher

    def load_bundle(self) -> IdentityDataBundle:
        return IdentityDataBundle(
            users=self._normalize_users(self._safe_fetch("users")),
            groups=self._normalize_groups(self._safe_fetch("groups")),
            roles=self._normalize_roles(self._safe_fetch("role_assignments")),
            access_reviews=self._normalize_access_reviews(self._safe_fetch("access_reviews")),
            incidents=self._normalize_incidents(self._safe_fetch("incidents")),
            approvals=self._normalize_approvals(self._safe_fetch("approvals")),
            evidence=self._normalize_evidence(self._safe_fetch("evidence")),
        )

    def _safe_fetch(self, resource_name: str) -> BundleCollection:
        payload = self._fetcher.fetch_collection(resource_name)
        if not isinstance(payload, list):
            raise ValueError(f"Expected a list payload from Graph fetcher for {resource_name}")
        return payload

    def _normalize_users(self, items: BundleCollection) -> BundleCollection:
        normalized: BundleCollection = []
        for item in items:
            normalized.append(
                {
                    "id": item.get("id") or item.get("userId"),
                    "user_principal_name": item.get("userPrincipalName") or item.get("mail"),
                    "display_name": item.get("displayName"),
                    "user_type": item.get("userType", "Member"),
                    "department": item.get("department"),
                    "job_title": item.get("jobTitle"),
                    "manager_id": item.get("managerId"),
                    "group_ids": item.get("groupIds", []),
                    "risk_state": item.get("riskState", "unknown"),
                    **self._metadata(item),
                }
            )
        return normalized

    def _normalize_groups(self, items: BundleCollection) -> BundleCollection:
        normalized: BundleCollection = []
        for item in items:
            normalized.append(
                {
                    "id": item.get("id"),
                    "display_name": item.get("displayName"),
                    "group_type": self._group_type(item),
                    "classification": item.get("classification") or item.get("sensitivityLabel", "Unclassified"),
                    "owner_ids": item.get("ownerIds", []),
                    "member_ids": item.get("memberIds", []),
                    **self._metadata(item),
                }
            )
        return normalized

    def _normalize_roles(self, items: BundleCollection) -> BundleCollection:
        normalized: BundleCollection = []
        for item in items:
            normalized.append(
                {
                    "id": item.get("id") or item.get("assignmentId"),
                    "role_definition": item.get("roleDefinitionDisplayName") or item.get("roleDefinitionName"),
                    "principal_id": item.get("principalId"),
                    "assignment_type": item.get("assignmentType", "Active"),
                    "scope": item.get("directoryScopeId", "/"),
                    "start_utc": item.get("startDateTime"),
                    "end_utc": item.get("endDateTime"),
                    **self._metadata(item),
                }
            )
        return normalized

    def _normalize_access_reviews(self, items: BundleCollection) -> BundleCollection:
        normalized: BundleCollection = []
        for item in items:
            decisions = item.get("decisions", [])
            normalized.append(
                {
                    "id": item.get("id"),
                    "name": item.get("displayName") or item.get("name"),
                    "target_group_id": item.get("targetGroupId"),
                    "reviewer_ids": item.get("reviewerIds", []),
                    "reviewed_principal_ids": item.get("reviewedPrincipalIds", []),
                    "status": item.get("status", "unknown"),
                    "due_utc": item.get("endDateTime") or item.get("dueDateTime"),
                    "decisions": decisions if isinstance(decisions, list) else [],
                    **self._metadata(item),
                }
            )
        return normalized

    def _normalize_incidents(self, items: BundleCollection) -> BundleCollection:
        normalized: BundleCollection = []
        for item in items:
            normalized.append(
                {
                    "id": item.get("id"),
                    "title": item.get("title") or item.get("displayName") or "Untitled incident",
                    "severity": item.get("severity", "medium"),
                    "status": item.get("status", "active"),
                    "principal_id": item.get("principalId") or item.get("userId"),
                    "occurred_utc": item.get("occurredDateTime") or item.get("createdDateTime"),
                    "signals": item.get("signals", []),
                    "evidence_ids": item.get("evidenceIds", []),
                    **self._metadata(item),
                }
            )
        return normalized

    def _normalize_approvals(self, items: BundleCollection) -> BundleCollection:
        normalized: BundleCollection = []
        for item in items:
            normalized.append(
                {
                    "id": item.get("id"),
                    "request_type": item.get("requestType") or item.get("action"),
                    "target_principal_id": item.get("targetPrincipalId"),
                    "target_group_id": item.get("targetGroupId"),
                    "requested_by_id": item.get("requestedById"),
                    "approver_ids": item.get("approverIds", []),
                    "status": item.get("status", "pending"),
                    "justification": item.get("justification"),
                    "requested_utc": item.get("requestedDateTime"),
                    "resolved_utc": item.get("resolvedDateTime"),
                    **self._metadata(item),
                }
            )
        return normalized

    def _normalize_evidence(self, items: BundleCollection) -> BundleCollection:
        normalized: BundleCollection = []
        for item in items:
            normalized.append(
                {
                    "id": item.get("id"),
                    "evidence_type": item.get("evidenceType") or item.get("type", "graphRecord"),
                    "title": item.get("title") or item.get("displayName") or "Evidence record",
                    "principal_id": item.get("principalId"),
                    "uri": item.get("uri") or item.get("webUrl"),
                    "summary": item.get("summary") or item.get("description"),
                    **self._metadata(item),
                }
            )
        return normalized

    def _metadata(self, item: JsonDict) -> JsonDict:
        return {
            "source": "graph",
            "seed_version": "graph-live",
            "last_updated_utc": item.get("lastModifiedDateTime") or item.get("createdDateTime") or item.get("lastUpdatedUtc"),
        }

    def _group_type(self, item: JsonDict) -> str:
        group_types = item.get("groupTypes", [])
        if "Unified" in group_types:
            return "Microsoft365"
        if item.get("mailEnabled"):
            return "MailEnabledSecurity"
        return "Security"


def merge_bundles(primary: IdentityDataBundle, secondary: IdentityDataBundle) -> IdentityDataBundle:
    return IdentityDataBundle(
        users=_merge_by_id(primary.users, secondary.users),
        groups=_merge_by_id(primary.groups, secondary.groups),
        roles=_merge_by_id(primary.roles, secondary.roles),
        access_reviews=_merge_by_id(primary.access_reviews, secondary.access_reviews),
        incidents=_merge_by_id(primary.incidents, secondary.incidents),
        approvals=_merge_by_id(primary.approvals, secondary.approvals),
        evidence=_merge_by_id(primary.evidence, secondary.evidence),
    )


def _merge_by_id(primary: list[JsonDict], secondary: list[JsonDict]) -> list[JsonDict]:
    merged: dict[str, JsonDict] = {}
    for item in secondary + primary:
        item_id = item.get("id")
        if not item_id:
            raise ValueError("All seed entities must include an 'id' field.")
        merged[str(item_id)] = item
    return list(merged.values())