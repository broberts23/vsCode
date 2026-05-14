# Identity Governance Copilot: Secure RAG over Microsoft Graph, Azure AI Search, and Azure OpenAI

## Introduction

Identity governance data is exactly the kind of information people want to query in plain English and exactly the kind of data you should be careful exposing. Security teams, governance analysts, and platform administrators all want answers to questions like these:

- Who still has privileged directory access?
- Which guest accounts are overdue for review?
- Which approvals are still pending for risky identity changes?
- What evidence supports this access review recommendation?

The usual approach is either too manual or too dangerous. Manual exports from Microsoft Graph and Entra admin centers are slow, brittle, and hard to keep current. Letting an LLM call Graph directly is the opposite problem: the results may be useful, but the security boundary is wrong. A model should not have unconstrained, privileged, live access to the identity plane.

This project implements a more defensible pattern: ingest approved identity-governance data, normalize it into a controlled schema, index it into Azure AI Search, and use Azure OpenAI only for grounded retrieval-based answers. That gives you a practical RAG pipeline for identity governance without turning the model into a privileged operator.

It focuses on a narrow, useful slice of governance data: users, groups, role assignments, access reviews, incidents, approvals, and supporting evidence. It is designed to work in a small lab tenant, which means simulated data is a first-class design requirement, not an afterthought.

## Scenario Narrative

Imagine you are running a small security engineering team inside a tenant that has Microsoft Entra ID, Azure AI Search, Azure OpenAI, and a growing backlog of identity-governance tasks. Your tenant is not large enough to generate the volume of incidents, reviews, and privilege drift you see in a real enterprise, but you still want to build the operational experience a real team would use.

Your goal is to create an internal governance copilot that can answer questions, summarize evidence, and help reviewers make decisions without exposing Microsoft Graph directly to the model. The copilot should be able to reason over:

- privileged role assignments
- guest group membership
- access review state and overdue decisions
- incident evidence related to risky sign-ins or stale access
- approval history for sensitive actions

The copilot is not a write-back engine in this first version. It is a grounded read path. That is deliberate. Starting read-only keeps the security boundary simpler, makes the project easier to test, and still covers the most important exam topics: retrieval design, Azure AI Search, RAG, evaluation, monitoring, secure integration, and Copilot-facing API patterns.

## Project Summary

The repository is split into the same major parts used across the rest of this monorepo:

- `README.md` is the quick-start.
- `blog.md` is the design notebook and walkthrough.
- `infra/` contains Bicep for Azure resource deployment.
- `scripts/` contains PowerShell 7.4 entry points for deploy, ingestion, and testing.
- `src/` contains the Python implementation for ingestion, indexing, retrieval, masking, and inference.
- `tests/` contains lightweight validation for the seed ingestion flow.

The key design choice is that the project does not own its own seed fixtures. Instead, it consumes the shared provider and datasets in `shared/identity_seed/`. That keeps the schema stable across the other labs and makes it possible to reuse the same entity corpus for governance, orchestration, and triage scenarios.

## Repository Structure

```text
project-identity-governance-copilot/
├── README.md
├── blog.md
├── infra/
│   ├── main.bicep
│   └── parameters.dev.json
├── scripts/
│   ├── Deploy-Infrastructure.ps1
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

## File-by-File Walkthrough

### `README.md`

This file is the quick-start. It explains what the project does, the data modes it supports, the top-level structure, and the basic deployment and local test loop. If someone opens this project without context, `README.md` should be enough to get them from zero to a working seed-backed ingestion and inference run.

### `infra/main.bicep`

This Bicep file provisions the core Azure resources for the scenario:

- an Azure AI Search service
- an Azure OpenAI account and model deployment reference
- a storage account for ingestion artifacts or future document staging
- a user-assigned managed identity for app-side authentication

The template is intentionally narrow. It provisions only the minimum set of cloud resources needed to demonstrate the retrieval path and leaves room to extend later with App Service, Container Apps, or Function App hosting if you decide to operationalize the Python API.

### `infra/parameters.dev.json`

This is the development parameter file. It sets the base names, SKU values, dataset defaults, and index names for a lab deployment. Keeping these values in a parameter file makes it easier to spin up multiple environments or vary SKUs without editing the template.

### `scripts/Deploy-Infrastructure.ps1`

This script is the repo-style deployment entry point. It wraps Bicep deployment with PowerShell 7.4, validates the environment and parameter file, and runs a resource-group deployment. It exists so the local developer loop looks like the rest of the monorepo rather than requiring raw Azure CLI commands every time.

### `scripts/Invoke-SeedIngestion.ps1`

This script is the ingestion runner for the lab. It calls the Python ingestion and indexing code with a chosen dataset pack such as `seed` or `noisy`, so you can rehydrate the search index quickly after changing fixtures or schema. This is the easiest path for local testing because it avoids any live Graph dependency.

### `scripts/Test-Inference.ps1`

This script is the smoke test for the cloud-backed chat flow. It sends a prompt into the Python entry point, which retrieves grounded documents from Azure AI Search and then calls Azure OpenAI to produce the answer. That makes it the simplest end-to-end validation path for the project after indexing is complete.

### `src/requirements.txt`

This file defines the Python runtime dependencies. The important detail now is that the dependencies are not just placeholders anymore. `azure-identity` is used for `DefaultAzureCredential`, which lets the project authenticate to Azure AI Search with the local developer identity or a managed identity in Azure. `azure-search-documents` is used for both index management and document upload. Keeping those dependencies explicit matters because this lab is now using the real Azure SDK path instead of a mock indexing flow.

### `src/app.py`

This is the thin application entry point. It exposes a minimal CLI-friendly and API-friendly path that routes prompts through the cloud-backed RAG flow. If you later front this with Copilot Studio or a web app, this is the natural composition layer.

### `src/ingest/graph_ingest.py`

This module is responsible for turning raw bundle data into normalized governance documents that can be indexed into Azure AI Search. In seed mode, it loads from the shared provider package. In graph mode, it can switch to the Graph-backed provider and receive the same bundle shape. This file is where the document model for users, groups, roles, reviews, incidents, approvals, and evidence is flattened into searchable text.

### `src/search/build_index.py`

This module now uses the real Azure AI Search SDK to create or update the index. It authenticates through `DefaultAzureCredential`, builds a typed `SearchIndex` definition, and applies it through `SearchIndexClient`. The current schema is intentionally small: `id`, `source_type`, `title`, `content`, `principal_id`, and `severity`. It also enables semantic ranking configuration so the search service can prioritize the title and content fields during retrieval.

This is one of the most important files in the project because the quality of the RAG answers depends heavily on how the index is shaped. Right now the implementation is a real keyword plus semantic search index. Vector retrieval is the next natural step once an embedding pipeline is added.

### `src/search/load_documents.py`

This module pushes the normalized governance documents into Azure AI Search using the real `SearchClient`. It loads the seed or Graph-normalized bundle, converts it into search documents, and uploads them with the SDK. This is the bridge between data preparation and retrieval. In a fuller implementation this is also where batching, retry policy, chunking strategy, and partial-failure handling would live.

### `src/search/service.py`

This shared helper centralizes Azure AI Search connection details. It reads the service endpoint and index name from environment variables, constructs `DefaultAzureCredential`, and returns either a `SearchIndexClient` or `SearchClient`. Keeping authentication and client creation in one place makes the rest of the indexing code easier to read and keeps the security model obvious.

### `src/rag/chat.py`

This module now contains the real chat path. It uses the Azure AI Search SDK to run a semantic search query against the governance index, formats the returned documents as grounded context, and then calls Azure OpenAI through the `openai` Python package using Azure AD authentication from `DefaultAzureCredential`. The answer is produced from retrieved context and then passed through the masking layer before being returned.

This is where `azure-identity` and `azure-search-documents` become part of the inference path instead of just the indexing path. `azure-identity` provides the credential chain and bearer token provider, while `azure-search-documents` provides the query client for retrieval.

### `src/review/recommendation_engine.py`

This module applies access-review-specific reasoning. It turns retrieved governance facts into a recommendation-oriented summary such as approve, remove, or escalate. That makes the project useful both as a general governance copilot and as a precursor to a more agentic review workflow.

### `src/security/masking.py`

This module centralizes the masking rules for sensitive fields. For example, it can suppress or redact raw identifiers, principal names, or evidence details depending on how much data the caller should see. This is where the project reinforces the rule that retrieval and inference should respect security boundaries instead of blindly returning everything in the index.

### `tests/test_seed_ingestion.py`

This test checks the seed ingestion path and validates the canonical bundle assumptions. It is not trying to be a full test suite yet. Its purpose is to confirm that the shared seed pack loads, that the ingestion flow produces documents, and that the same canonical schema can feed the governance lab consistently.

## How Simulated Data Works

This project assumes that a small lab tenant will not give you enough realistic telemetry to make RAG and governance workflows interesting. Because of that, simulated data is a core part of the architecture.

The seed flow works like this:

1. The project loads a bundle from `shared/identity_seed/` using `FileSeedDataProvider`.
2. The bundle includes users, groups, roles, access reviews, incidents, approvals, and evidence in one canonical schema.
3. The ingestion module turns those entities into retrieval documents.
4. The search loader uploads those documents into a real Azure AI Search index.
5. The RAG layer retrieves grounded documents and sends only those facts to Azure OpenAI.

This has three immediate advantages:

- You can build the project before you have interesting live Graph data.
- You can create edge cases that would be rare or awkward to reproduce manually.
- You get stable evaluation data for regression tests and prompt tuning.

The project supports two shared seed packs today:

- `seed`: small deterministic starter pack
- `noisy`: larger pack with 66 users, more varied groups, more incidents, and noisier approvals for more realistic retrieval testing

The long-term deployment model is hybrid. In that mode, live Graph objects can be loaded through the Graph-backed provider and merged with simulated incidents, reviews, and evidence so you still have rich governance scenarios even in a smaller tenant.

## Deployment Walkthrough

### 1. Deploy Azure resources

From the project folder, run:

```powershell
pwsh ./scripts/Deploy-Infrastructure.ps1 -Environment dev -ResourceGroupName <rg-name>
```

This deploys the Bicep template in `infra/main.bicep` using `infra/parameters.dev.json` by default.

### 2. Create the Python environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r ./src/requirements.txt
```

### 3. Configure environment variables

At minimum, configure:

- `AZURE_SEARCH_ENDPOINT`
- `AZURE_SEARCH_INDEX_NAME`
- `AZURE_OPENAI_ENDPOINT`
- `AZURE_OPENAI_CHAT_DEPLOYMENT`
- `IDENTITY_DATASET_ROOT`
- `IDENTITY_DATASET_PACK`

For a first run, set `IDENTITY_DATASET_ROOT` to the shared dataset location and `IDENTITY_DATASET_PACK` to `seed` or `noisy`.

For the real Azure AI Search SDK flow to work, the identity running the scripts must also have Azure AI Search data-plane permissions. In practice, that usually means using your signed-in Azure developer identity locally or a managed identity in Azure and assigning the appropriate Search roles. The current implementation uses `DefaultAzureCredential`, so it can pick up Azure CLI, Azure PowerShell, Visual Studio Code, or managed identity credentials automatically.

### 4. Build or update the search index

```powershell
python ./src/search/build_index.py
```

This now performs a real `create_or_update_index` call against Azure AI Search. It does not just print a schema. If the command succeeds, the target index exists in the service and is ready to receive documents.

### 5. Ingest documents

```powershell
pwsh ./scripts/Invoke-SeedIngestion.ps1 -DatasetPack noisy
```

This runs the seed-based ingestion path, normalizes the shared bundle into retrieval documents, and uploads them through the Azure AI Search SDK. The upload step returns per-document status from the service, which is the point where you would later add better retry logic or dead-letter handling.

## Test And Inference Flow

There are two levels of validation in the first version.

### Seed ingestion validation

Run:

```powershell
pytest ./tests
```

This confirms the seed-backed data flow produces a usable bundle and a non-empty document set.

### Retrieval and inference smoke tests

Run:

```powershell
pwsh ./scripts/Test-Inference.ps1 -Prompt "Which guest users still have privileged access?"
pwsh ./scripts/Test-Inference.ps1 -Prompt "Which access reviews are overdue?"
pwsh ./scripts/Test-Inference.ps1 -Prompt "Summarize the highest severity incident and cite the evidence."
```

These smoke tests validate the end-to-end cloud-backed flow:

1. query enters the RAG layer
2. Azure AI Search retrieves relevant governance documents from the indexed corpus
3. masking rules apply as needed
4. Azure OpenAI produces a grounded response

If the answer is thin or off-target, the first places to look are the search index schema, the uploaded document shape, and the grounded context passed to the model.

## How Azure OpenAI And Azure AI Search Fit Together

This project is designed around the most practical relationship between the two services:

- Azure AI Search is the system of retrieval.
- Azure OpenAI is the system of reasoning and answer generation.

The sequence is straightforward:

1. governance entities are normalized into search documents
2. Azure AI Search stores those documents in a real index created through the SDK
3. Azure AI Search handles keyword and semantic retrieval over that index
4. the top grounded documents are passed to Azure OpenAI
5. the model produces an answer constrained by those facts

This pattern matters for security. You are not asking the model to explore the tenant. You are asking it to reason over a curated, indexed, bounded subset of governance data.

The current implementation fully wires the indexing, retrieval, and answer-generation path into Azure SDK clients. It still stops short of vector search because it does not yet generate embeddings. That is a deliberate milestone boundary, not a design limitation. Once an embedding step is added, the same document model and index-create flow can be extended to support hybrid vector retrieval.

## Why This Fits The Repo

This project matches the existing repo conventions:

- top-level `project-<name>` folder
- `README.md` for fast start
- `blog.md` for the long-form explanation
- `infra/` for Bicep
- `scripts/` for PowerShell 7.4 operational entry points
- `src/` for implementation code
- `tests/` for local validation

It also aligns well with the rest of the identity-focused projects in the monorepo because it keeps the identity data model explicit, leans on shared seed data, and treats automation and testing as first-class parts of the scenario rather than optional extras.

## Next Iterations

The first milestone is a secure, grounded read path. After that, natural extensions are:

- a hosted API or Function App wrapper for the Python service
- Copilot Studio integration as an enterprise agent front end
- hybrid data mode that merges live Graph objects with simulated evidence
- richer evaluation sets and automated relevance scoring
- approval-aware action recommendations for access review workflows

That is enough to make this project useful as both an exam study lab and a credible portfolio sample.
