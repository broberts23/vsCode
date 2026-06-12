# Azure DevOps REST API Connector Design

## Overview

The Documentation Copilot includes a custom Azure AI Foundry connector that integrates with Azure DevOps Wiki via REST API. This connector is implemented as a Python module (`src/ado/`) and exposed through the MCP toolbox for governed access.

## Architecture

```
User Prompt → app.py → wiki_service.py → ado/client.py → Azure DevOps REST API
                          ↓
                   wiki/generator.py → foundry/project_client.py → deepseek-v4-flash
                          ↓
                   scanner/ → Local repository
```

## Components

### 1. Auth Layer (`src/ado/auth.py`)

Two-tier authentication strategy:

**Production path (managed identity — no secrets):**

- Uses `DefaultAzureCredential()` from `azure-identity` to acquire a Bearer token
- Token scope: `https://app.vssps.visualstudio.com/.default`
- The Foundry Hosted Agent's platform-assigned managed identity is automatically resolved
- Token is short-lived (1 hour), automatically rotated by Azure
- Sent as `Authorization: Bearer {token}` on REST API calls

**Local development fallback (PAT):**

- Reads `AZURE_DEVOPS_PAT` from environment variable
- Constructs Basic auth header with base64-encoded PAT
- Fails fast with descriptive error if PAT is missing and no managed identity is available
- PAT should be scoped to **Wiki Read & Write** only

The runtime auto-selects between these paths: if `DefaultAzureCredential` can acquire a token, the Bearer path is used. Otherwise, the PAT fallback is used.

### 2. REST Client (`src/ado/client.py`)

- `AdoWikiClient` class wrapping `requests.Session`
- Typed `WikiPage` and `WikiPageResult` dataclasses
- Methods: `get_page()`, `create_or_update_page()`, `delete_page()`, `list_pages()`
- ETag-based version tracking for safe concurrent editing
- Graceful error handling with typed error results

### 3. Service Orchestrator (`src/ado/wiki_service.py`)

- `update_wiki_for_target()` — the main entry point
- Coordinates: scan → generate → publish pipeline
- Handles page path construction following `API-Reference/{Target}/{Module}` convention

### 4. MCP Toolbox (`mcp/wiki-publisher/`)

- Exposes `publish_wiki_page`, `get_wiki_page`, `list_wiki_pages` as governed tools
- Skill-attached for behavioural guidelines
- Narrow RBAC scope: only wiki operations, no wider ADO access

## API Surface

| Operation | Method | Endpoint Pattern |
|---|---|---|
| Get page | GET | `{org_url}/{project}/_apis/wiki/wikis/{wikiId}/pages?path={path}&api-version=7.1&includeContent=true` |
| Create/Update | PUT | `{org_url}/{project}/_apis/wiki/wikis/{wikiId}/pages?path={path}&api-version=7.1` |
| Delete | DELETE | `{org_url}/{project}/_apis/wiki/wikis/{wikiId}/pages?path={path}&api-version=7.1` |
| List pages | GET | `{org_url}/{project}/_apis/wiki/wikis/{wikiId}/pages?api-version=7.1&recursionLevel=full` |

## Security

**Production (managed identity):**

- The agent's platform-assigned managed identity is authenticated via Microsoft Entra ID — no shared secrets, no long-lived tokens
- Tokens expire every hour and are automatically refreshed by `DefaultAzureCredential`
- The managed identity is explicitly added to Azure DevOps with **Wiki Read & Write** permissions only
- Azure DevOps uses its own permission model (not Microsoft Entra application permissions) — see [Microsoft documentation](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity?view=azure-devops)
- All Entra tokens are fetched in-memory; none are stored to disk or logged

**Local development (PAT):**

- PAT scoped to **Wiki Read & Write** only — no broader ADO permissions
- PAT stored in Key Vault as fallback, never in code or config files
- Base64 encoding for transport (Basic auth), not for storage

**Cross-cutting:**

- Output masking via `src/security/masking.py` redacts both PAT and Bearer token strings from logs
- Provenance recorder tracks all wiki operations with correlation IDs

## Error Handling

| Scenario | Behaviour |
|---|---|
| Missing PAT (no managed identity available) | `RuntimeError` at startup |
| Managed identity token acquisition failure | Falls back to PAT; logs warning |
| 401 Unauthorized | `WikiPageResult(status='error', ...)` with error message |
| 403 Forbidden (managed identity not added to ADO) | `WikiPageResult(status='error', ...)` — check identity has been added as Azure DevOps user |
| 404 Page not found | `get_page()` returns `None` |
| 429 Rate limited | Exponential backoff (future enhancement) |
| Network timeout | `requests.HTTPError` → `WikiPageResult(status='error', ...)` |
| Concurrent edit conflict | `412 Precondition Failed` when ETag mismatch → retry with fresh version

## References

- [Authenticate to Azure DevOps with service principals and managed identities](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity?view=azure-devops)
- [Azure DevOps Wiki REST API (Pages)](https://learn.microsoft.com/en-us/rest/api/azure/devops/wiki/pages)
- [Azure Identity client library (DefaultAzureCredential)](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential) |
