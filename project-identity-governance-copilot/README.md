# Identity Governance Copilot

Python and Azure AI reference implementation for a secure identity-governance copilot. The project combines Microsoft Graph ingestion, Azure AI Search grounding, Azure OpenAI inference, and Copilot-friendly API patterns so you can ask natural-language questions about privileged access, guest exposure, and access review state without giving an LLM direct Graph access.

This project is the Lab 1 implementation from the combined AI-103 and AB-620 study track. It is intentionally seed-first: you can develop and test the full retrieval and inference flow with simulated data, then switch to live Graph ingestion later.

## What this project gives you

- A repeatable identity-governance RAG pattern for users, groups, roles, access reviews, incidents, approvals, and evidence.
- A file-based seed ingestion path using the shared `shared/identity_seed/` package.
- A Graph-ready ingestion path that normalizes live tenant data into the same schema.
- A cloud-backed RAG flow that retrieves from Azure AI Search and completes with Azure OpenAI.
- A small Python API surface you can use directly or front with Copilot Studio.
- Bicep and PowerShell scaffolding for Azure AI Search, Azure OpenAI, storage, and managed identity.

## Project Structure

```text
project-identity-governance-copilot/
├── PYTHON-FOR-POWERSHELL.md
├── README.md
├── blog.md
├── infra/
│   ├── main.bicep
│   └── parameters.dev.json
├── scripts/
│   ├── Deploy-Infrastructure.ps1
│   ├── Export-AppEnvironment.ps1
│   ├── Invoke-SeedIngestion.ps1
│   └── Test-Inference.ps1
├── src/
│   ├── requirements.txt
│   ├── app.py
│   ├── ingest/
│   │   └── graph_ingest.py
│   ├── rag/
│   │   └── chat.py
│   ├── review/
│   │   └── recommendation_engine.py
│   ├── search/
│   │   ├── build_index.py
│   │   ├── load_documents.py
│   │   └── service.py
│   └── security/
│       └── masking.py
└── tests/
    └── test_seed_ingestion.py
```

## Data Modes

The project supports the same three modes defined in the shared package:

- `seed`: load from `shared/identity_seed/datasets/seed` or `shared/identity_seed/datasets/noisy`
- `graph`: load from live Graph through a fetcher and normalize into the canonical bundle shape
- `hybrid`: merge live Graph data with simulated reviews, incidents, or evidence

For the first implementation pass, start with `seed` mode.

## Quick Start

1. Deploy the Azure resources:

   `pwsh ./scripts/Deploy-Infrastructure.ps1 -Environment dev -ResourceGroupName <rg-name>`

2. Export the app environment variables from the latest deployment:

   `pwsh ./scripts/Export-AppEnvironment.ps1 -ResourceGroupName <rg-name>`

3. Create and activate a Python virtual environment.

4. Install dependencies:

   `python -m pip install -r ./src/requirements.txt`

5. Ingest seed data into Azure AI Search:

   `pwsh ./scripts/Invoke-SeedIngestion.ps1 -DatasetPack seed`

6. Run a simple inference smoke test:

   `pwsh ./scripts/Test-Inference.ps1 -Prompt "Which guest users still have privileged access?"`

## Required Configuration

Set these environment variables locally or through your deployment environment:

- `AZURE_SEARCH_ENDPOINT`
- `AZURE_SEARCH_INDEX_NAME`
- `AZURE_OPENAI_ENDPOINT`
- `AZURE_OPENAI_CHAT_DEPLOYMENT`
- `IDENTITY_DATASET_ROOT`

Optional:

- `IDENTITY_DATASET_PACK` with values such as `seed` or `noisy`
- `AZURE_OPENAI_API_VERSION` if you need to override the default API version

`Export-AppEnvironment.ps1` prints the required variables in PowerShell format, Bash format, or both so you can copy them directly into your local shell session.

## Simulated Data

The project reuses `shared/identity_seed/` rather than duplicating fixtures in the project folder. That gives you:

- a small starter pack for deterministic tests
- a noisy pack with 66 users and noisier incidents for more realistic retrieval tests
- a Graph-backed provider stub that can be swapped in later without changing the downstream schema

## Local Test Loop

1. Deploy infra once.
2. Run seed ingestion whenever you update fixtures or the index schema.
3. Use `Test-Inference.ps1` to run targeted prompts against the RAG service.
4. Run `pytest ./tests` for local validation.

The project now uses `azure-search-documents` for index creation, document upload, and retrieval, and `azure-identity` for both Azure AI Search and Azure OpenAI authentication via `DefaultAzureCredential`.

## Security Notes

- Prefer managed identity for deployed Azure resources.
- Keep the RAG layer read-only for the first milestone.
- Filter or mask sensitive fields before returning results to callers.
- Do not let the LLM call Microsoft Graph directly.

## Next Step

See `blog.md` for the full narrative, design rationale, file-by-file explanation, and deployment walkthrough.
