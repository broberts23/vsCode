"""Turn the canonical identity bundle into search-ready documents.

PowerShell bridge:
- `dataclass` is a lightweight way to declare a data-focused class without writing boilerplate.
- `dict[str, Any]` is a type hint meaning "dictionary keyed by strings with flexible values".
- `str | None` means the value can be a string or null, similar to a nullable property.
- `def name(...) -> Something:` uses `->` to describe the return type; it does not change runtime behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PROJECT_ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shared.identity_seed import FileSeedDataProvider
from shared.identity_seed.data_provider import IdentityDataBundle


JsonDict = dict[str, Any]


# `slots=True` reduces dynamic attribute overhead.
# Think of it like declaring a fixed property shape instead of allowing arbitrary note properties.
@dataclass(slots=True)
class GovernanceDocument:
    id: str
    source_type: str
    title: str
    content: str
    principal_id: str | None
    severity: str | None = None

    def as_dict(self) -> JsonDict:
        # Azure SDK clients want plain dictionaries for upload, so this is the conversion point.
        return {
            "id": self.id,
            "source_type": self.source_type,
            "title": self.title,
            "content": self.content,
            "principal_id": self.principal_id,
            "severity": self.severity,
        }


def load_bundle() -> IdentityDataBundle:
    # Environment variables let the scripts switch between `seed` and `noisy` data without code edits.
    dataset_root = Path(os.environ["IDENTITY_DATASET_ROOT"])
    dataset_pack = os.environ.get("IDENTITY_DATASET_PACK", "seed")
    provider = FileSeedDataProvider(dataset_root, collection_name=dataset_pack)
    return provider.load_bundle()


def build_documents(bundle: IdentityDataBundle) -> list[GovernanceDocument]:
    # This function is the normalization layer: many identity record types become one search document shape.
    documents: list[GovernanceDocument] = []

    for role in bundle.roles:
        documents.append(
            GovernanceDocument(
                id=f"role::{role['id']}",
                source_type="role",
                title=f"Role assignment: {role.get('role_definition', 'Unknown role')}",
                content=(
                    f"Principal {role.get('principal_id')} has {role.get('assignment_type')} "
                    f"assignment to {role.get('role_definition')} scoped to {role.get('scope')}."
                ),
                principal_id=role.get("principal_id"),
            )
        )

    for review in bundle.access_reviews:
        # Python f-strings are similar to PowerShell string interpolation with `$variable` and `$()`.
        documents.append(
            GovernanceDocument(
                id=f"review::{review['id']}",
                source_type="access_review",
                title=f"Access review: {review.get('name', review['id'])}",
                content=(
                    f"Review status is {review.get('status')} with due date {review.get('due_utc')}. "
                    f"Targets group {review.get('target_group_id')} and covers principals "
                    f"{', '.join(review.get('reviewed_principal_ids', []))}."
                ),
                principal_id=None,
            )
        )

    for incident in bundle.incidents:
        documents.append(
            GovernanceDocument(
                id=f"incident::{incident['id']}",
                source_type="incident",
                title=incident.get("title", incident["id"]),
                content=(
                    f"Incident severity is {incident.get('severity')} and status is {incident.get('status')}. "
                    f"Signals include {', '.join(incident.get('signals', []))}."
                ),
                principal_id=incident.get("principal_id"),
                severity=incident.get("severity"),
            )
        )

    for approval in bundle.approvals:
        documents.append(
            GovernanceDocument(
                id=f"approval::{approval['id']}",
                source_type="approval",
                title=f"Approval request: {approval.get('request_type')}",
                content=(
                    f"Approval status is {approval.get('status')} for principal "
                    f"{approval.get('target_principal_id')}. Justification: {approval.get('justification')}."
                ),
                principal_id=approval.get("target_principal_id"),
            )
        )

    for evidence in bundle.evidence:
        documents.append(
            GovernanceDocument(
                id=f"evidence::{evidence['id']}",
                source_type="evidence",
                title=evidence.get("title", evidence["id"]),
                content=evidence.get("summary", "No summary available."),
                principal_id=evidence.get("principal_id"),
            )
        )

    return documents