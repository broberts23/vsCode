"""Upload markdown documents into Azure AI Search.

PowerShell bridge:
- This file is the same idea as reading objects, reshaping them, and sending them to
    a cloud service.
- It is intentionally tiny because the interesting part is the data flow, not the
    amount of orchestration code.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.search.service import create_search_client
from src.content.markdown_loader import build_search_documents
from src.config import AppConfig


def main() -> None:
    """Load local markdown, project it into search documents, and upload them.

    PowerShell bridge:
    - This reads like a short deployment helper that pulls data from one step and
      pushes it into the next step.
    """

    settings = AppConfig.from_env()
    # The markdown loader returns typed objects, which we immediately flatten into
    # dictionaries for Azure SDK upload compatibility.
    documents = [document.as_dict()
                 for document in build_search_documents(settings.knowledge_root)]
    client = create_search_client(settings)
    results = client.upload_documents(documents=documents)
    # Summarize the upload outcome so the script acts like a useful command.
    succeeded = sum(1 for result in results if result.succeeded)
    failed = len(results) - succeeded
    print(
        f'Uploaded {succeeded} markdown documents to Azure AI Search; {failed} failed.')


if __name__ == '__main__':
    # The file stays runnable on its own, which is convenient for local ingestion.
    main()
