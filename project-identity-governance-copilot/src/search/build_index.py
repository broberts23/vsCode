"""Define and create the Azure AI Search index.

PowerShell bridge:
- The Azure SDK model types are strongly typed equivalents of the hashtables you might build in PowerShell.
- `build_index_definition() -> SearchIndex` returns an in-memory object that is later submitted by the client.
"""

from __future__ import annotations

from pathlib import Path
import sys

from azure.search.documents.indexes.models import (
    SearchIndex,
    SearchableField,
    SemanticConfiguration,
    SemanticField,
    SemanticPrioritizedFields,
    SemanticSearch,
    SimpleField,
    SearchFieldDataType,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.search.service import create_index_client, get_index_name


def build_index_definition() -> SearchIndex:
    # This is the schema contract for indexed documents, similar to defining a table or object shape.
    return SearchIndex(
        name=get_index_name(),
        fields=[
            SimpleField(name="id", type=SearchFieldDataType.String, key=True),
            SearchableField(name="source_type", type=SearchFieldDataType.String, filterable=True),
            SearchableField(name="title", type=SearchFieldDataType.String),
            SearchableField(name="content", type=SearchFieldDataType.String),
            SimpleField(name="principal_id", type=SearchFieldDataType.String, filterable=True),
            SimpleField(name="severity", type=SearchFieldDataType.String, filterable=True),
        ],
        # Semantic configuration tells Search which fields matter most for ranking and grounding.
        semantic_search=SemanticSearch(
            configurations=[
                SemanticConfiguration(
                    name="default",
                    prioritized_fields=SemanticPrioritizedFields(
                        title_field=SemanticField(field_name="title"),
                        content_fields=[SemanticField(field_name="content")],
                        keywords_fields=[SemanticField(field_name="source_type")],
                    ),
                )
            ]
        ),
    )


def main() -> None:
    index_definition = build_index_definition()
    client = create_index_client()
    # `create_or_update_index` is idempotent: rerunning it updates the index if it already exists.
    client.create_or_update_index(index_definition)
    print(f"Created or updated Azure AI Search index '{index_definition.name}'.")


if __name__ == "__main__":
    main()