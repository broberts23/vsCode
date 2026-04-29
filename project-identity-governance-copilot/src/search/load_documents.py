"""Upload normalized governance documents into Azure AI Search.

PowerShell bridge:
- The list comprehension here is similar to piping objects through `ForEach-Object` to reshape them.
- The upload result contains one status object per document, which we count for a simple success summary.
"""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ingest.graph_ingest import build_documents, load_bundle
from src.search.service import create_search_client


def main() -> None:
    bundle = load_bundle()
    # `document.as_dict()` converts our typed Python object into a plain payload for the SDK.
    documents = [document.as_dict() for document in build_documents(bundle)]
    client = create_search_client()
    results = client.upload_documents(documents=documents)
    succeeded = sum(1 for result in results if result.succeeded)
    failed = len(results) - succeeded
    print(f"Uploaded {succeeded} governance documents to Azure AI Search; {failed} failed.")


if __name__ == "__main__":
    main()