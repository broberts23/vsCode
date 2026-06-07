# Identity Security Copilot

Standalone Python reference project for building an identity-security copilot in Azure AI Foundry. The project is intentionally small and readable, and it assumes the reader already thinks fluently in PowerShell and is learning Python.

The copilot answers questions about Conditional Access, access reviews, workload identities, privileged access patterns, and related operational controls. It uses:

- Microsoft Foundry project endpoint for model access and project metadata
- Azure AI Search for grounding over local markdown content
- Managed identity or developer identity through `DefaultAzureCredential`
- PowerShell 7.4 scripts for deployment and local execution

## Why this project exists

This repo is designed to align directly to the AI-103 study topic "Build an Identity Security Copilot in Azure AI Foundry".

It demonstrates:

- a Foundry project-aware Python application
- model selection by task
- a retrieval layer over internal markdown content
- deployment scaffolding for Azure AI Search and supporting services
- a simple, readable codebase with PowerShell-to-Python translation comments

## Architecture

The app flow is deliberately simple:

1. Load configuration from environment variables.
2. Connect to the Azure AI Foundry project by using `AIProjectClient`.
3. Query Azure AI Search for grounded identity-security content.
4. Build a compact evidence block from the retrieved sections.
5. Send the prompt and evidence to a model deployment through the Foundry project.
6. Append deterministic citations and run a final masking pass.

## Repository structure

```text
project-identity-security-copilot/
├── .gitignore
├── PYTHON-FOR-POWERSHELL.md
├── README.md
├── blog.md
├── infra/
│   ├── main.bicep
│   └── parameters.dev.json
├── knowledge/
│   ├── access-reviews.md
│   ├── conditional-access.md
│   └── workload-identities.md
├── scripts/
│   ├── Deploy-Infrastructure.ps1
│   ├── Export-AppEnvironment.ps1
│   ├── Invoke-MarkdownIngestion.ps1
│   └── Test-Chat.ps1
├── src/
│   ├── app.py
│   ├── config.py
│   ├── requirements.txt
│   ├── content/
│   │   └── markdown_loader.py
│   ├── foundry/
│   │   └── project_client.py
│   ├── rag/
│   │   └── chat.py
│   ├── search/
│   │   ├── build_index.py
│   │   ├── load_documents.py
│   │   └── service.py
│   └── security/
│       └── masking.py
└── tests/
    └── test_markdown_loader.py
```

## Prerequisites

- Python 3.10 or later
- PowerShell 7.4
- Azure CLI logged in with `az login`
- An existing Azure AI Foundry project endpoint
- An Azure AI Search service
- RBAC on the Foundry project and Azure AI Search

## Required environment variables

The application uses a short set of environment variables.

- `AZURE_AI_PROJECT_ENDPOINT`
- `AZURE_AI_CHAT_DEPLOYMENT`
- `AZURE_AI_SUMMARY_DEPLOYMENT` optional, defaults to the chat deployment
- `AZURE_SEARCH_ENDPOINT`
- `AZURE_SEARCH_INDEX_NAME`
- `KNOWLEDGE_ROOT` optional, defaults to `./knowledge`

Optional tracing and diagnostics:

- `AZURE_AI_PROJECTS_CONSOLE_LOGGING`
- `AZURE_EXPERIMENTAL_ENABLE_GENAI_TRACING`
- `AZURE_TRACING_GEN_AI_ENABLE_TRACE_CONTEXT_PROPAGATION`

## Quick start

1. Create the Python virtual environment.

   `python -m venv .venv`

2. Activate it.

   `./.venv/Scripts/Activate.ps1`

3. Install dependencies.

   `python -m pip install -r ./src/requirements.txt`

4. Deploy Azure AI Search and supporting resources.

   `pwsh ./scripts/Deploy-Infrastructure.ps1 -Environment dev -ResourceGroupName <rg-name>`

5. Export local environment variables.

   `pwsh ./scripts/Export-AppEnvironment.ps1 -ResourceGroupName <rg-name> -FoundryProjectEndpoint <project-endpoint> -ChatDeployment <chat-model-deployment>`

6. Build the search index and upload the local markdown knowledge base.

   `pwsh ./scripts/Invoke-MarkdownIngestion.ps1`

7. Run a smoke test.

   `pwsh ./scripts/Test-Chat.ps1 -Prompt "Which workload identities need stronger controls?"`

## What is intentionally simple

This project does not try to implement every Foundry feature at once.

- Retrieval uses semantic search, not vectors.
- The app uses a direct responses call rather than a full Foundry agent definition.
- The markdown knowledge base is local and repo-hosted.
- The infrastructure deploys supporting Azure resources, but you still supply an existing Foundry project endpoint.

Those choices keep the project readable while still hitting the exam criteria for project setup, retrieval, model selection, and secure app design.

## Study-guide alignment

This project maps to the AI-103 topic:

- Choose appropriate models, Foundry services, retrieval methods, and memory/tool/knowledge integration services.
- Set up Foundry projects, deployments, and CI/CD integration.
- Design Azure infrastructure for AI apps and agent-based solutions.

## Next steps

- Add vector search and embeddings.
- Add Foundry evaluations for groundedness, fluency, and task adherence.
- Add read-only function tools for access-review evidence lookup.
- Add Application Insights tracing from the Foundry project telemetry endpoint.

See [blog.md](blog.md) for the narrative walkthrough and design rationale.
