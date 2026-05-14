"""Create or update the Azure AI Search index.

PowerShell bridge:
- The index definition is like a strongly typed schema object that gets sent to the service.
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

from src.config import AppConfig
from src.search.service import create_index_client


def build_index_definition(settings: AppConfig) -> SearchIndex:
    return SearchIndex(
        name=settings.azure_search_index_name,
        fields=[
            SimpleField(name='id', type=SearchFieldDataType.String, key=True),
            SearchableField(name='source_type', type=SearchFieldDataType.String, filterable=True),
            SearchableField(name='title', type=SearchFieldDataType.String),
            SearchableField(name='content', type=SearchFieldDataType.String),
            SimpleField(name='file_path', type=SearchFieldDataType.String, filterable=True),
            SearchableField(name='heading', type=SearchFieldDataType.String),
            SearchableField(name='tags', type=SearchFieldDataType.String, filterable=True),
        ],
        semantic_search=SemanticSearch(
            configurations=[
                SemanticConfiguration(
                    name='default',
                    prioritized_fields=SemanticPrioritizedFields(
                        title_field=SemanticField(field_name='title'),
                        content_fields=[SemanticField(field_name='content')],
                        keywords_fields=[SemanticField(field_name='tags')],
                    ),
                )
            ]
        ),
    )


def main() -> None:
    settings = AppConfig.from_env()
    client = create_index_client(settings)
    index_definition = build_index_definition(settings)
    client.create_or_update_index(index=index_definition)
    print(f'Index {settings.azure_search_index_name} is ready.')


if __name__ == '__main__':
    main()
