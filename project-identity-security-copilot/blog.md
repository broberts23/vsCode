# Build an Identity Security Copilot in Azure AI Foundry

## Why this lab matters

The AI-103 exam now expects more than raw prompt experimentation. You need to understand how to build a practical AI application around a Foundry project, choose the right SDK entry points, wire retrieval to real content, and keep the security boundary explicit.

Identity security is a strong scenario for this because it forces good engineering discipline. The subject matter is sensitive, the questions are practical, and the application cannot get away with vague answers or uncontrolled data access.

This project implements a narrow but realistic shape:

- Microsoft Foundry project endpoint for model access and project metadata
- Azure AI Search for grounding over a local markdown knowledge base
- Python code that stays small enough to read top to bottom
- PowerShell deployment and local test scripts
- comments that translate Python concepts for someone who already knows PowerShell deeply

## Scenario

Assume you want a copilot that helps an identity engineering team answer questions such as:

- Which Conditional Access controls are missing from a privileged admin scenario?
- What are the operational risks of workload identities without governance?
- What evidence should an access reviewer inspect before approving an exception?
- What controls should be documented before enabling a new privileged automation account?

The goal is not to let the model roam through live tenant data. The goal is to create a secure, grounded assistant over approved identity-security content.

## What this project demonstrates

### Foundry project awareness

The app is configured around `AZURE_AI_PROJECT_ENDPOINT`, not around a collection of unrelated endpoints. This reflects the current Foundry SDK model, where the project client is the entry point for project-native operations and can also produce an OpenAI-compatible client for responses.

### Retrieval over internal markdown

The repo includes a small local knowledge base under `knowledge/`. A markdown loader turns those files into Azure AI Search documents, keeping the ingestion path easy to understand.

### Model selection by task

The application distinguishes between a chat model deployment and an optional summary deployment. Even if both point to the same model in a lab, the config shape reflects the exam skill of choosing appropriate models for different tasks.

### Secure defaults

The code uses `DefaultAzureCredential`, deterministic citations, and a final masking pass. The Bicep template also deploys supporting services such as App Configuration, Key Vault, and Log Analytics so the project can grow into a more production-like shape.

## Design choices

### Why not start with a full agent?

Because Topic 1 is better served by a readable app than by a large amount of orchestration code. A full Foundry agent with tools, approvals, and evaluations is a good next step, but it would make the first project harder to understand.

### Why not use embeddings yet?

Because the Foundry study topic here is broader than vector search. The app first proves the simpler path: project setup, semantic retrieval, grounded responses, and deployment scaffolding. Vector search can be added later as a focused follow-up.

### Why keep the corpus in the repo?

Because the project needs to stand alone. A reader should be able to clone this one folder, deploy the dependencies, ingest the markdown files, and get useful behavior without depending on another repo folder.

## File-by-file walkthrough

### `src/app.py`

This is the thin CLI entry point. It works like a small PowerShell script with a `param()` block: it accepts a prompt, calls the chat workflow, and prints the answer.

### `src/config.py`

This file centralizes environment variable loading into a typed dataclass. Think of it like a strongly shaped configuration object instead of scattering `Get-Item env:` calls throughout the repo.

### `src/foundry/project_client.py`

This module creates and validates the Azure AI Foundry project client. It also exposes a helper that lists deployments so you can confirm your configured deployment names exist.

### `src/search/build_index.py`

This creates the Azure AI Search index used for markdown grounding. The schema is intentionally small and optimized for semantic search.

### `src/content/markdown_loader.py`

This module reads markdown files from the repo, splits them into sections by heading, and converts them into search documents.

### `src/search/load_documents.py`

This uploads the search documents into Azure AI Search.

### `src/rag/chat.py`

This is the app orchestrator: retrieve documents, format evidence, call the model, append citations, and mask the final answer.

### `src/security/masking.py`

This performs a final response scrub to prevent a few obvious identity examples from leaking into the output unchanged.

## Infrastructure shape

The Bicep template deploys:

- Azure AI Search
- Storage account for future document staging
- Key Vault
- App Configuration
- Log Analytics workspace
- Application Insights
- user-assigned managed identity

The template does not attempt to create the Foundry project itself. At the time of writing, many teams still provision the Foundry project and its connected resources through the portal or a separate management flow. This lab keeps that boundary explicit: the repo deploys supporting resources and expects an existing Foundry project endpoint.

## How to study with this repo

Use the repo in three passes.

### Pass 1: understand the code shape

Read the files in this order:

1. `README.md`
2. `PYTHON-FOR-POWERSHELL.md`
3. `src/app.py`
4. `src/config.py`
5. `src/rag/chat.py`

### Pass 2: run the local workflow

1. Deploy the infra.
2. Export the environment variables.
3. Build the index.
4. Upload the markdown knowledge base.
5. Run a few smoke-test prompts.

### Pass 3: extend the lab

After the baseline works, add one feature at a time:

- vector retrieval
- Foundry evaluations
- read-only tools
- tracing
- CI pipeline

## Exam criteria covered

This project directly supports the AI-103 study guide topic:

- Choose the appropriate Foundry services for generative AI and agents.
- Choose an appropriate model for each task.
- Choose an appropriate method for retrieval and indexing.
- Set up AI solutions in Foundry.
- Configure model deployments.
- Design Azure infrastructure for AI apps.
- Integrate projects with CI/CD in a natural next step.

## Suggested follow-up posts

- Add Foundry evaluations to an identity-security copilot.
- Convert this project from semantic search to hybrid retrieval.
- Add read-only function tools for access review evidence lookup.
- Add tracing and KQL-based troubleshooting for the copilot runtime.
