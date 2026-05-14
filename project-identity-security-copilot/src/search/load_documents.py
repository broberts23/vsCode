"""Upload markdown documents into Azure AI Search.

PowerShell bridge:
- This file is the same idea as reading objects, reshaping them, and sending them to a cloud service.
"""

from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import AppConfig
from src.content.markdown_loader import build_search_documents
from src.search.service import create_search_client


def main() -> None:
    settings = AppConfig.from_env()
    documents = [document.as_dict() for document in build_search_documents(settings.knowledge_root)]
    client = create_search_client(settings)
    results = client.upload_documents(documents=documents)
    succeeded = sum(1 for result in results if result.succeeded)
    failed = len(results) - succeeded
    print(f'Uploaded {succeeded} markdown documents to Azure AI Search; {failed} failed.')


if __name__ == '__main__':
    main()
