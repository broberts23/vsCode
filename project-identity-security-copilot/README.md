# Identity Security Copilot

This project is the expanded implementation of the AI-103 study topic "Build an Identity Security Copilot in Azure AI Foundry". The scope is deliberately broader than a single chat demo. It now treats the copilot as a small, grounded assistant platform: a Foundry project-aware Python app, task-based model selection for chat and summarization, a read-only tool path for deeper evidence lookups, and a deployment workflow that carries infrastructure and application configuration forward together.

The copilot answers questions about Conditional Access, access reviews, workload identities, privileged access patterns, and adjacent operational controls. It uses:

- Azure AI Foundry as the project control plane for model access
- Azure AI Search for retrieval over curated markdown knowledge
- Task routing between grounded Q&A and summary workflows
- Read-only tool use for additional evidence lookup and deployment awareness
- PowerShell 7.4 deployment scripts for infrastructure and centralized app configuration

## Problem statement

Identity security questions rarely stay in one lane. One request may need a grounded answer about Conditional Access, another may need a short executive summary, and a third may need the assistant to narrow the search space before it can answer defensibly. If the project only demonstrates one chat call against one model, it misses the way real AI apps are assembled in Azure.

This repo exists to show the broader pattern: build the assistant around a Foundry project, separate model roles by task, keep retrieval over approved documentation, and treat deployment plus configuration as part of the solution rather than an afterthought.

## Solution overview

The application flow is intentionally small enough to read in one sitting:

1. Load environment-driven settings for the Foundry project, model deployments, and Search index.
2. Route each incoming request to either grounded Q&A or summary mode.
3. Retrieve evidence from Azure AI Search over the repo-hosted identity security markdown set.
4. Let the chat deployment answer directly or, when needed, call a narrow read-only tool for another evidence lookup.
5. Append deterministic citations and apply a final masking pass.

That gives the project three exam-relevant slices in one codebase:

- project-aware model usage through `AIProjectClient`
- task-based model selection through separate chat and summary deployments
- tool and knowledge integration through retrieval plus controlled function calling

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
│   ├── Publish-AppConfiguration.ps1
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
    ├── test_chat_routing.py
    └── test_markdown_loader.py
```

## Prerequisites

- Python 3.10 or later
- PowerShell 7.4
- Azure CLI authenticated with `az login`
- An Azure AI Foundry project with at least one chat-capable deployment
- RBAC on the Foundry project, Azure AI Search, and Azure App Configuration

## Required environment variables

The application reads a compact set of environment variables for local execution.

- `AZURE_AI_PROJECT_ENDPOINT`
- `AZURE_AI_CHAT_DEPLOYMENT`
- `AZURE_AI_SUMMARY_DEPLOYMENT` optional, defaults to the chat deployment
- `AZURE_SEARCH_ENDPOINT`
- `AZURE_SEARCH_INDEX_NAME`
- `KNOWLEDGE_ROOT` optional, defaults to `./knowledge`

The deployment scripts can also export operational values that matter when you host the app or centralize configuration:

- `AZURE_APP_CONFIGURATION_ENDPOINT`
- `AZURE_KEY_VAULT_URI`
- `APPLICATIONINSIGHTS_CONNECTION_STRING`
- `AZURE_CLIENT_ID`

Optional tracing flags:

- `AZURE_AI_PROJECTS_CONSOLE_LOGGING`
- `AZURE_EXPERIMENTAL_ENABLE_GENAI_TRACING`
- `AZURE_TRACING_GEN_AI_ENABLE_TRACE_CONTEXT_PROPAGATION`

## Quick start

1. Create a virtual environment.

   `python -m venv .venv`

2. Activate it.

   `./.venv/Scripts/Activate.ps1`

3. Install dependencies.

   `python -m pip install -r ./src/requirements.txt`

4. Deploy the supporting Azure resources.

   `pwsh ./scripts/Deploy-Infrastructure.ps1 -Environment dev -ResourceGroupName <rg-name>`

5. Export local environment variables from the latest deployment.

   `pwsh ./scripts/Export-AppEnvironment.ps1 -ResourceGroupName <rg-name> -FoundryProjectEndpoint <project-endpoint> -ChatDeployment <chat-model-deployment> -SummaryDeployment <summary-model-deployment>`

6. Optionally publish the same settings into Azure App Configuration for a hosted runtime.

   `pwsh ./scripts/Publish-AppConfiguration.ps1 -ResourceGroupName <rg-name> -FoundryProjectEndpoint <project-endpoint> -ChatDeployment <chat-model-deployment> -SummaryDeployment <summary-model-deployment>`

7. Build the Search index and upload the markdown knowledge base.

   `pwsh ./scripts/Invoke-MarkdownIngestion.ps1`

8. Ask a grounded question through automatic routing.

   `python ./src/app.py --prompt "Which workload identities need stronger controls?"`

9. Force summary mode when you want an overview instead of grounded Q&A.

   `python ./src/app.py --mode summarize --prompt "Summarize the Conditional Access content for a security engineering lead."`

## Resolution

This repo is intentionally not a giant agent framework. It stays narrow on purpose.

- Retrieval is semantic and markdown-first rather than a full hybrid-vector stack.
- Tool use is read-only and local to the process, which keeps the trust boundary simple.
- The deployment scripts provision supporting services and publish app settings, while the Foundry project and model deployments remain explicit inputs to the lab.

That tradeoff keeps the implementation readable while still reflecting the expanded exam scenario: project setup, task-aware model use, retrieval, tool integration, and deployment configuration.

## Study-guide alignment

This project now lines up directly to the expanded scope for project 1 in the study backlog.

- Choose appropriate models, Foundry services, retrieval methods, and memory/tool/knowledge integration services.
- Set up Foundry projects, deployments, and CI/CD-adjacent configuration flow.
- Design Azure infrastructure for AI apps and agent-based solutions.

## Conclusion

The project is now closer to a realistic Azure AI application pattern than a single RAG sample. It shows how to combine a Foundry project, task-based model selection, governed knowledge retrieval, a small tool surface, and deployment-time configuration without turning the codebase into a black box.

See [blog.md](blog.md) for the narrative walkthrough.
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
