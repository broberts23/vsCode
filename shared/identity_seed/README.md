# Shared identity seed data

This folder contains a reusable seed-data pattern for the AI-103 and AB-620 identity security labs.

Contents:

- `data_provider.py`: shared provider contract, JSON-backed seed loader, and Graph normalization stub
- `datasets/seed/*.json`: starter seed corpus used across governance, operations, and incident labs
- `datasets/noisy/*.json`: larger noisy seed corpus for more realistic retrieval and triage testing
- `datasets/eval/`: placeholder evaluation fixtures for stable regression scenarios

Recommended usage:

```python
from pathlib import Path

from shared.identity_seed import FileSeedDataProvider

provider = FileSeedDataProvider(Path("shared/identity_seed/datasets"))
bundle = provider.load_bundle()
print(bundle.as_dict().keys())
```

To load the larger noisy pack, pass a different collection name:

```python
from pathlib import Path

from shared.identity_seed import FileSeedDataProvider

provider = FileSeedDataProvider(Path("shared/identity_seed/datasets"), collection_name="noisy")
bundle = provider.load_bundle()
print(len(bundle.users))
```

The Graph-backed provider is intentionally a stub: inject a fetcher that returns raw Graph payloads for each resource, and the provider will normalize them into the same bundle shape used by the seed datasets.
