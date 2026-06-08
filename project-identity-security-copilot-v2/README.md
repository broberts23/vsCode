# Identity Security Copilot v2

Natural evolution of the `project-identity-security-copilot` v1 reference project. v2 keeps the v1 spine (Foundry project, AI Search grounding, PowerShell deploy, typed config, output masking) and layers on three new ideas drawn from `scratch.md` A2A/MCP extension block:

1. A coordinator agent that routes policy, governance, and workload identity questions to specialist agents using explicit agent-to-agent handoff payloads.
2. Three MCP servers (retrieval, markdown, configuration) that re-export v1's helpers as governed tools.
3. A comparison harness that runs the same scenarios synchronously and via delegated agent workflows.

## Status

This directory is a **scaffold**. It contains the project outline, README, blog placeholder, and empty Python packages. No implementation code is written yet. See [`OUTLINE.md`](./OUTLINE.md) for the full design contract and the phased implementation plan.

## Repository layout (scaffold)

```text
project-identity-security-copilot-v2/
├── OUTLINE.md                # the contract for v2
├── README.md                 # this file
├── blog.md                   # narrative walk-through (placeholder)
├── PYTHON-FOR-POWERSHELL.md  # v2 patterns (placeholder)
├── requirements.txt          # v1 deps + mcp + a2a helpers
├── .gitignore
├── docs/                     # a2a-handoff.md, mcp-servers.md, sync-vs-delegated.md
├── infra/                    # main.bicep, parameters.dev.json, mcp-host.bicep
├── knowledge/                # v1 markdown + governance-evidence.md + handoff-examples.md
├── scripts/                  # v1 scripts + Start-McpServers.ps1 + Test-Chat-Delegated.ps1
├── src/                      # carried-over v1 modules + new agents/ mcp_servers/ workflow/ packages
└── tests/                    # v1 tests + a2a + sync-vs-delegated + mcp contracts
```

## What is new vs v1

| Layer | v1 | v2 |
| --- | --- | --- |
| Orchestration | Single-process `rag/chat.py` | Coordinator + three specialists, explicit A2A handoffs |
| Tooling | In-process Python helpers | Three stdio MCP servers (retrieval, markdown, config) |
| Workflow | One path (sync) | Sync + delegated runners with a comparison harness |
| Observability | App Insights, basic tracing | Same plus a provenance recorder for handoffs and tool calls |
| Security | `mask_answer` final pass | Same plus `redaction_policy.py` applied to every envelope |
| RBAC | One managed identity per environment | One identity per MCP server, narrower grants |

## Quick start (after implementation)

Not runnable yet. Once the phased plan in `OUTLINE.md` is complete, the quick start will mirror v1 with two additions:

1. `pwsh ./scripts/Start-McpServers.ps1` to launch the three MCP servers locally.
2. `pwsh ./scripts/Test-Chat-Delegated.ps1 -Prompt "..."` to exercise the delegated path.

## Next steps

Open [`OUTLINE.md`](./OUTLINE.md) and start with **Phase 0 — Carryover**.
