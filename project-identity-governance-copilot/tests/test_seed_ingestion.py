"""Basic ingestion test.

PowerShell bridge:
- `monkeypatch` is pytest's temporary environment override helper, similar to setting env vars for one test run.
- `assert` is the built-in test check syntax.
"""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PROJECT_ROOT.parent
for path_value in (PROJECT_ROOT, REPO_ROOT):
    if str(path_value) not in sys.path:
        sys.path.insert(0, str(path_value))

from src.ingest.graph_ingest import build_documents, load_bundle


def test_seed_bundle_produces_documents(monkeypatch) -> None:
    # Point the test at the shared deterministic dataset instead of relying on machine-global state.
    dataset_root = REPO_ROOT / 'shared' / 'identity_seed' / 'datasets'
    monkeypatch.setenv('IDENTITY_DATASET_ROOT', str(dataset_root))
    monkeypatch.setenv('IDENTITY_DATASET_PACK', 'seed')

    bundle = load_bundle()
    documents = build_documents(bundle)

    assert bundle.users
    assert documents