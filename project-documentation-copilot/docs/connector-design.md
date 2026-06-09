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

- Reads `AZURE_DEVOPS_PAT` from environment
- Constructs Basic auth header with base64-encoded PAT
- Fails fast with descriptive error if PAT is missing

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

- PAT scoped to **Wiki Read & Write** only — no broader ADO permissions
- PAT stored as environment variable, never in code or config files
- Base64 encoding for transport (Basic auth), not for storage
- Output masking via `src/security/masking.py` redacts auth headers from logs
- Provenance recorder tracks all wiki operations with correlation IDs

## Error Handling

| Scenario | Behaviour |
|---|---|
| Missing PAT | `RuntimeError` at startup |
| 401 Unauthorized | `WikiPageResult(status='error', ...)` with error message |
| 404 Page not found | `get_page()` returns `None` |
| 429 Rate limited | Exponential backoff (future enhancement) |
| Network timeout | `requests.HTTPError` → `WikiPageResult(status='error', ...)` |
| Concurrent edit conflict | `412 Precondition Failed` when ETag mismatch → retry with fresh version |
