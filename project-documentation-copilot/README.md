# Documentation Copilot

AI-powered Foundry Hosted Agent that generates Azure DevOps Wiki entries for Python codebases directly from the developer's IDE.

**Status:** Scaffold. No implementation code is written yet. See [`OUTLINE.md`](./OUTLINE.md) for the full design contract and phased implementation plan.

## What it does

```text
Developer: "update the wiki for calculate_total to capture the latest changes"

Copilot:   [scans repo] → [extracts function metadata] → [generates wiki markdown]
           → [builds Mermaid diagrams] → [publishes to Azure DevOps Wiki]

Result:    A new wiki page at API-Reference/calculate_total/calculator with:
           • Function signature, parameters, return type, docstring
           • Internal and external dependencies
           • Mermaid workflow diagram
```

## Architecture

| Component | Implementation |
| --- | --- |
| **Model** | deepseek-v4-flash on Azure AI Foundry (serverless API) |
| **Code analysis** | Python `ast` module — static, no execution |
| **Wiki generation** | Structured pipeline: code metadata → LLM prose → formatted markdown |
| **Diagram generation** | Mermaid DSL (class diagrams, sequence diagrams, flowcharts) |
| **Wiki publishing** | Azure DevOps REST API v7.1 with Bearer token (managed identity) or PAT auth |
| **Deployment** | Foundry Hosted Agent via `azd` (source-code deployment) |
| **Observability** | Provenance recorder + Application Insights |

## Repository layout

```text
project-documentation-copilot/
├── OUTLINE.md                # Design contract + implementation phases
├── README.md                 # This file
├── blog.md                   # Narrative walkthrough
├── azure.yaml                # azd project manifest
├── docs/                     # Feasibility, connector design, azd journey
├── infra/                    # main.bicep, parameters.dev.json
├── knowledge/                # Grounding knowledge (wiki format, Mermaid, ADO API)
├── skills/                   # Foundry Skills (wiki-authoring, code-analysis)
├── agents/documentation-copilot/  # Foundry Hosted Agent
├── mcp/                      # MCP toolbox surfaces
├── src/                      # Shared library (scanner, wiki, ado, foundry, rag)
└── tests/                    # Unit tests for all modules
```

## Quick start (after implementation)

```pwsh
# 1. Set environment variables
$env:AZURE_AI_PROJECT_ENDPOINT = "https://..."
$env:AZURE_DEVOPS_ORG_URL = "https://dev.azure.com/myorg"
$env:AZURE_DEVOPS_PROJECT = "myproject"
$env:AZURE_DEVOPS_PAT = "<your-pat>"
$env:TARGET_REPO_ROOT = "C:\Repo\my-project"

# 2. Scan for functions
python -m src.app --prompt "find the load_config function" --mode scan-only

# 3. Generate and publish wiki
python -m src.app --prompt "update the wiki for load_config" --mode auto

# 4. Run tests
pytest tests/ -v

# 5. Deploy to Foundry
azd provision
azd deploy
azd ai agent invoke "update the wiki for MyFunction"
```

## Key design decisions

1. **No LLM tool calling** — deepseek-v4-flash doesn't support it. All code scanning, API calls, and diagram generation happen in Python. The LLM handles prose only.
2. **Single-agent architecture** — no coordinator/specialist topology. One container, one deploy. Simpler than the multi-agent `project-identity-security-copilot-v2`.
3. **Static analysis only** — code is never executed. The `ast` module parses source files safely.
4. **ETag-based updates** — existing wiki pages are fetched for their version before updating, preventing concurrent edit conflicts.

## Requirements satisfied

See [`docs/feasibility-research.md`](./docs/feasibility-research.md) for the technical analysis confirming all requirements are achievable:

| Requirement | Status |
| --- | --- |
| Hosted on Azure AI Foundry | ✅ Feasible |
| deepseek-v4-flash model | ✅ Feasible (serverless API, no tool calling → Python orchestrator) |
| Azure DevOps Wiki creation/updates | ✅ Feasible (REST API v7.1) |
| Function/class documentation | ✅ Feasible (AST-based extraction) |
| Input/output objects | ✅ Feasible (type annotations + docstring extraction) |
| Dependencies | ✅ Feasible (import analysis + prefix heuristic) |
| Mermaid workflow diagrams | ✅ Feasible (ADO Wiki native Mermaid support) |
| Custom ADO connector | ✅ Feasible (PAT-based REST client) |
| Same workflow as v2 template | ✅ Feasible (identical azd journey) |

## Next steps

Open [`OUTLINE.md`](./OUTLINE.md) and start with **Phase 0 — Verify scaffold**: `pytest tests/ -v`
