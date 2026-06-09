# Technical Feasibility Research

**Date:** 2026-06-09  
**Project:** `project-documentation-copilot`

## Summary

All requirements are **technically feasible** with one architectural caveat addressed in the design.

---

## 1. Azure DevOps Wiki REST API — Page CRUD

**Verdict: FEASIBLE**

- **Create/Update endpoint:** `PUT https://dev.azure.com/{org}/{project}/_apis/wiki/wikis/{wikiId}/pages?path={path}&api-version=7.1`
- **Auth:** PAT-based Basic auth with `Wiki Read & Write` scope. Service principals supported for headless automation.
- **Version tracking:** `ETag` header provides version for safe concurrent editing via `If-Match`.
- **Markdown content:** Delivered as plain string in JSON body. Mermaid diagrams embedded as `::: mermaid` fence blocks are passed through directly.
- **Rate limits:** 200 concurrent requests max. The copilot makes sequential PUT requests to stay well within limits.

**Reference:** Microsoft Learn — Azure DevOps REST API v7.1, Pages - Create Or Update

---

## 2. deepseek-v4-flash on Azure AI Foundry

**Verdict: FEASIBLE — with architectural adaptation**

| Property | Value |
|---|---|
| **Availability** | Listed in Foundry Models sold by Azure (Preview) |
| **Deployment type** | Global Standard (serverless API) |
| **Tool calling** | **NOT supported** |
| **Context window** | 1,000,000 tokens input, 384,000 tokens output |
| **Response formats** | Text, JSON |
| **SKU** | Serverless API model — billed per token, no SKU selection |

**Architectural decision:** Because deepseek-v4-flash does not support tool calling, the Documentation Copilot performs all code scanning, dependency resolution, wiki API calls, and diagram generation **in Python** — not via LLM tool calls. The model receives pre-extracted, structured code metadata and only handles prose generation. This is the same pattern as the v1 Identity Security Copilot where retrieval happens in code before the LLM is called.

**Reference:** Microsoft Learn — Foundry Models sold by Azure, DeepSeek section (2026-05-13)

---

## 3. Mermaid in Azure DevOps Wiki

**Verdict: FEASIBLE**

Azure DevOps Wiki **natively renders Mermaid diagrams**. The Mermaid DSL is embedded in markdown using the `::: mermaid` fence:

```
::: mermaid
graph TD
    A --> B
:::
```

**Supported diagram types:** `sequenceDiagram`, `graph` (NOT `flowchart`), `classDiagram`, `stateDiagram-v2`, `gantt`, `pie`, `journey`, `erDiagram`, `gitGraph`, `timeline`, `requirementDiagram`.

**Limitations:**

- `flowchart` keyword not supported — use `graph` instead.
- No HTML inside diagrams.
- No Font Awesome icons.
- `---->` LongArrow not supported.

**Reference:** Azure DevOps Markdown guidance, "Work with Mermaid diagrams" (2026-06-03)

---

## 4. Python AST-based Code Analysis

**Verdict: FEASIBLE**

Python's standard library `ast` module provides complete static analysis without executing code. The `NodeVisitor` pattern allows visiting function definitions, class definitions, import statements, decorators, and extracting docstrings and type annotations.

**Limitations:**

- Static analysis only — cannot detect dynamically generated functions or metaclass-manipulated classes.
- Type annotations are extracted as strings, not resolved to actual types.
- This is acceptable for documentation generation where the goal is readability, not type-checking.

---

## 5. Foundry Hosted Agent Deployment

**Verdict: FEASIBLE**

The `project-identity-security-copilot-v2` OUTLINE.md §9 defines a complete `azd`-driven deployment journey:

- `azd ai agent init` → scaffold
- `azd provision` → infrastructure
- `azd ai agent run` + `azd ai agent invoke --local` → local testing
- `azd deploy` → cloud deployment
- `azd ai agent show` → status polling
- `azd ai agent invoke` → production invocation

The Documentation Copilot follows this exact workflow with a single Hosted Agent (no multi-agent topology needed).

---

## Overall Verdict

| Area | Status | Blocker? |
|---|---|---|
| DevOps Wiki API — page CRUD | ✅ Feasible | No |
| deepseek-v4-flash on Foundry | ✅ Feasible (no tool calling → Python orchestrator) | No |
| Mermaid in DevOps Wiki | ✅ Feasible | No |
| Python AST code analysis | ✅ Feasible | No |
| Foundry Hosted Agent deployment | ✅ Feasible | No |

**All requirements are achievable.** The architectural adaptation (Python orchestrator handles API calls, LLM handles prose generation only) is the standard pattern in this project family and is proven by v1.
