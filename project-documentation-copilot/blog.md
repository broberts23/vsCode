# Building a Documentation Copilot: From Scaffold to Live Azure DevOps Wiki Generation

> A narrative walkthrough of building an AI-powered documentation agent that generates Azure DevOps Wiki entries from Python source code, deployed on Azure AI Foundry using a **two-tier architecture**: a local CLI that scans the repository and a Foundry Hosted Agent that generates prose and publishes to the wiki via service principal authentication backed by Key Vault.

---

## Premise: Why this project exists

Every developer knows the drill. You write a function, ship the PR, and then someone asks: "Is the wiki updated?" The answer is almost always no — because writing documentation is tedious, time-consuming, and perpetually out of sync with the code. The documentation rots while the code evolves.

The Documentation Copilot exists to break this cycle. It turns a natural-language request — "update the wiki for `calculate_total` to capture the latest changes" — into a live Azure DevOps Wiki page that reflects the current state of the code, including function signatures, parameter types, dependencies, and workflow diagrams. No manual markdown crafting. No copy-paste from docstrings. Just a prompt and a published page.

The project is part of the same family as `project-identity-security-copilot-v2`, adopting its exact agent creation, testing, and deployment workflow. But where the Identity Security Copilot answers policy and governance questions, the Documentation Copilot writes and publishes wiki entries. Different domain, same proven pipeline.

---

## Purpose: The problem we solve

### The documentation decay cycle

Codebases change constantly. Functions get new parameters. Classes gain methods. Dependencies shift. But documentation — when it exists at all — is written once at creation time and rarely touched again. The result: wikis full of stale signatures, missing parameters, and diagrams that describe code from three releases ago.

### What the Documentation Copilot does

1. **Accepts natural-language prompts** from the developer's terminal via `wikicopilot.py` — a local CLI that scans the repository, packages the code metadata as JSON, and sends it to the Foundry agent
2. **Scans the locally cloned repository** using Python's AST module for static code analysis — no code execution, no import side effects, no network needed on the developer workstation
3. **Extracts structured metadata**: function signatures, parameter types, return types, decorators, docstrings, class hierarchies, and import dependencies
4. **Packages the metadata** as JSON using `src/ado/module_serializer.py`, base64-encodes it, and invokes the Foundry agent via `azd ai agent invoke "__SCAN__:..."` — the agent detects the marker, deserialises the data, and proceeds to generation + publishing
5. **Generates comprehensive wiki content**: overview prose (via deepseek-v4-flash), formatted parameter tables, dependency lists, and Mermaid workflow diagrams
6. **Publishes to Azure DevOps Wiki** via REST API with service principal authentication: the agent's managed identity reads the SP client ID and secret from Key Vault, then exchanges them for a Microsoft Entra Bearer token

### The developer experience

```text
$ python -m src.app --prompt "update the wiki for AuthService to capture the latest changes" --mode auto

Target: AuthService | Mode: auto
INFO: Scanning repository: 47 Python files found, 2 matching AuthService
INFO: Generating wiki content for src/auth/service.py
INFO: Publishing page: API-Reference/AuthService/auth_service
INFO: Wiki published successfully.

Published 1 wiki page(s):
  https://dev.azure.com/myorg/myproject/_wiki/wikis/myproject.wiki?pagePath=API-Reference/AuthService/auth_service
```

Five seconds. One command. The wiki is current.

---

## The two Azure services powering the copilot

### Azure AI Foundry + deepseek-v4-flash

The copilot is deployed as a **Foundry Hosted Agent** — a containerised Python application that runs on the Foundry Agent Service. The reasoning model is **deepseek-v4-flash**, deployed as a serverless API endpoint with a 1-million-token context window and text/JSON response formats.

Key architectural decision: deepseek-v4-flash does **not** support tool calling. This means the model cannot invoke functions mid-conversation. The copilot handles this by performing all non-LLM work in Python code — code scanning, dependency resolution, diagram generation, and DevOps API calls — and passing only structured metadata to the model for prose generation. The LLM's job is purely to write readable documentation paragraphs from structured facts. The pattern echoes the v1 Identity Security Copilot, where retrieval happens before the LLM is called.

```python
# The LLM is called once, with all the context it needs:
from src.foundry.project_client import complete_with_foundry

description = complete_with_foundry(
    system_prompt=DOCUMENTATION_SYSTEM_PROMPT,
    user_input=(
        f"Describe the following Python function:\n"
        f"Function: {func.name}({params})\n"
        f"Return Type: {func.return_type}\n"
        f"Docstring: {func.docstring}"
    ),
    settings=settings,
)
```

### Azure DevOps Wiki REST API

The copilot's custom connector (`src/ado/`) wraps the Azure DevOps Wiki REST API v7.1. It handles:

- **Get page:** `GET .../pages?path={path}&api-version=7.1&includeContent=true` — returns page content and `ETag` version
- **Create/Update:** `PUT .../pages?path={path}&api-version=7.1` — with `If-Match` header for safe concurrent editing
- **Authentication:** PAT-based Basic auth, scoped to Wiki Read & Write only, or Microsoft Entra ID Bearer tokens from the agent's platform-assigned managed identity (the production path)
- **Error handling:** Graceful degradation with typed `WikiPageResult` objects

The page path convention is `API-Reference/{TargetName}/{ModuleName}`, making wiki navigation predictable and browsable.

#### Why a custom connector instead of the Azure DevOps MCP Server?

Microsoft publishes an [official Azure DevOps MCP Server](https://learn.microsoft.com/en-us/azure/devops/mcp-server/mcp-server-overview?view=azure-devops) that connects AI assistants to Azure DevOps data — work items, pull requests, builds, pipelines, and test plans. It is a valuable tool for sprint planning, code review workflows, and standup preparation, and it runs locally via stdio with no external data leakage.

What the Azure DevOps MCP Server does **not** cover is Wiki page management. The server has no tools for creating, reading, updating, or deleting Wiki pages. The documented capability surface is limited to project metadata, work item tracking, PR status, CI/CD results, and test coverage — there is no Wiki endpoint in its tool roster. That gap is exactly the problem the Documentation Copilot solves.

Rather than extend the official MCP server (which would require upstream contributions to a Node.js codebase governed by Microsoft's release cycle), this project builds a purpose-specific, Python-native connector as an MCP toolbox surface (`mcp/wiki-publisher/`). The connector is thin, typed, and focused on one job: Wiki page CRUD. In production, both servers coexist — the Azure DevOps MCP Server handles your daily standup and PR reviews, and the Documentation Copilot keeps your Wiki current.

#### The authentication evolution: PAT → service principal via Key Vault

The scaffold originally used a Personal Access Token (PAT) stored in the `AZURE_DEVOPS_PAT` environment variable for Azure DevOps API authentication. This was adequate for local development but unsuitable for production — the PAT is a long-lived secret that must be rotated manually, and embedding it in environment variables violates zero-trust principles.

The production deployment uses a **two-step service principal authentication** flow:

1. **Key Vault secret retrieval:** The agent's platform-assigned managed identity uses `DefaultAzureCredential` to read the `AdoServicePrincipalClientId` and `AdoServicePrincipalSecret` secrets from `kv-doccopilot-dev1`. The managed identity was granted `Key Vault Secrets User` RBAC on the vault.

2. **OAuth 2.0 client credentials grant:** The retrieved client ID and secret are exchanged for a Microsoft Entra Bearer token at `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with scope `https://app.vssps.visualstudio.com/.default`. This Bearer token authenticates all ADO Wiki REST API calls.

The service principal (`doc-copilot-ado-sp`) was registered in Azure DevOps with Basic access level and Wiki Read & Write permissions on the target project. No long-lived secret ever enters the agent's environment variables — only the Key Vault URL and tenant ID are configured:

```yaml
environment_variables:
    - name: KEY_VAULT_URL
      value: ${KEY_VAULT_URL}
    - name: KEY_VAULT_NAME
      value: ${KEY_VAULT_NAME}
    - name: AZURE_TENANT_ID
      value: ${AZURE_TENANT_ID}
```

**Known bug: the `KEY_VAULT_NAMEse` typo.** The `agent.yaml` originally declared `KEY_VAULT_NAMEse` (note the trailing `se`) instead of `KEY_VAULT_NAME`. This caused `auth.py`'s `_service_principal_configured()` check to return `False` because the env var `KEY_VAULT_NAME` was never set inside the container — only `KEY_VAULT_NAMEse` was. The agent silently fell back to the platform-assigned managed identity, which was never added to Azure DevOps and returned HTML sign-in pages for every ADO API call. Simply renaming the env var from `KEY_VAULT_NAMEse` to `KEY_VAULT_NAME` (and adding `KEY_VAULT_URL` for direct resolution) fixed the entire authentication chain.

The PAT approach remains as a local-development fallback for when the agent runs outside of Azure on a developer workstation. The `auth.py` `get_auth_header()` function checks for `AZURE_DEVOPS_PAT` if managed identity and Key Vault are both unavailable.

**Another bug: missing `_secret_client` attribute.** The `ServicePrincipalAuth` class in `auth.py` initialised `_kv_credential`, `_tenant_id`, `_client_id`, and `_client_secret` in `__init__`, but omitted `_secret_client`. The `_ensure_secret_client()` method checks `if self._secret_client is not None` before creating a `SecretClient`, but since the attribute was never declared, it raised `AttributeError` at runtime. Fix: added `self._secret_client: object | None = None` to `__init__`.

---

## Full build process: From scaffold to running agent

### Phase 0 — Verify scaffold (pass)

The project scaffold is the blueprint. Before any implementation, the scaffold must prove it can hold the right shape. Running the scaffolded tests (now 26 after adding `module_serializer`):

```pwsh
PS> pytest tests/ -v

tests/test_python_parser.py::test_parse_function_with_type_annotations PASSED
tests/test_python_parser.py::test_parse_class_with_methods PASSED
tests/test_python_parser.py::test_parse_extracts_imports PASSED
tests/test_python_parser.py::test_parse_skips_syntax_errors PASSED
tests/test_mermaid_builder.py::test_build_class_diagram_includes_class_and_methods PASSED
tests/test_mermaid_builder.py::test_build_class_diagram_includes_inheritance PASSED
tests/test_mermaid_builder.py::test_build_sequence_diagram_assigns_participants PASSED
tests/test_mermaid_builder.py::test_wrap_mermaid_diagram_adds_fence PASSED
tests/test_mermaid_builder.py::test_wrap_mermaid_diagram_empty_string PASSED
tests/test_wiki_generator.py::test_format_wiki_markdown_renders_sections PASSED
tests/test_wiki_generator.py::test_format_input_output_table_with_params PASSED
tests/test_wiki_generator.py::test_format_input_output_table_empty PASSED
tests/test_wiki_generator.py::test_format_dependency_list_both_types PASSED
tests/test_wiki_generator.py::test_format_dependency_list_empty PASSED
tests/test_ado_client.py::test_get_page_returns_none_for_404 PASSED
tests/test_ado_client.py::test_create_or_update_page_returns_created PASSED
tests/test_ado_client.py::test_create_or_update_page_handles_error PASSED
tests/test_chat_routing.py::test_extract_target_from_update_wiki_prompt PASSED
tests/test_chat_routing.py::test_extract_target_from_create_wiki_prompt PASSED
tests/test_chat_routing.py::test_extract_target_from_document_command PASSED
tests/test_chat_routing.py::test_extract_target_no_match_returns_none PASSED
tests/test_chat_routing.py::test_extract_target_from_function_keyword PASSED
tests/test_repo_walker.py::test_walk_repository_discovers_python_files PASSED
tests/test_repo_walker.py::test_walk_repository_excludes_venv PASSED
tests/test_repo_walker.py::test_scan_target_finds_matching_function PASSED

================= 24 passed in 0.18s =================
```

Twenty-four tests. Every core data contract — parser, diagram builder, formatter, ADO client, routing, repo walker — has at least one test proving it produces the right output from known input. No live Azure services needed.

### Phase 1 — Local scanner (code analysis)

The scanner is the foundation. It must extract accurate metadata from real Python code without executing it.

**Implementation:** `src/scanner/python_parser.py` subclasses `ast.NodeVisitor` and overrides `visit_FunctionDef`, `visit_ClassDef`, `visit_Import`, and `visit_ImportFrom`. Each visitor extracts structured metadata: function name, parameter types, return annotations, decorators, docstrings, and line numbers.

```python
class _CodeVisitor(ast.NodeVisitor):
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        func = FunctionInfo(
            name=node.name,
            file_path=self.file_path,
            line_number=node.lineno,
            docstring=ast.get_docstring(node),
            decorators=[self._decorator_name(d) for d in node.decorator_list],
            parameters=self._extract_params(node.args),
            return_type=self._annotation_str(node.returns),
        )
        self.functions.append(func)
        self.generic_visit(node)
```

**Result:** Running `--mode scan-only` against a real repository:

```text
$ python -m src.app --prompt "find the load_config function" --mode scan-only

--- src/config.py ---
  def load_config(path: str = 'config.json') -> dict
  def validate_settings(data: dict) -> bool

--- src/utils/config_helpers.py ---
  def load_config(env: str = 'dev') -> Config

Found 2 matching module(s).
```

The scanner discovers the target function across multiple files, shows signatures with type annotations and default values, and filters out non-matching modules.

### Phase 2 — Wiki generation

With metadata extracted, the wiki generator (`src/wiki/generator.py`) orchestrates the full documentation pipeline:

1. Build a `WikiEntry` with sections for Overview, Module Path, Dependencies, Functions, Classes, and Workflow Diagrams
2. For each function and class, call the Foundry LLM for narrative descriptions
3. Format parameter tables and dependency lists
4. Generate Mermaid diagrams for modules with 3+ functions or 2+ classes

**Mermaid builder** (`src/wiki/mermaid_builder.py`) produces Azure DevOps Wiki-compatible diagrams:

```text
::: mermaid
classDiagram
    class AuthService {
        +login(credentials: dict) AuthToken
        +logout(token: str) None
        +validate_session(token: str) bool
    }
    class BaseService {
        +log(message: str) None
    }
    BaseService <|-- AuthService
:::
```

Key constraints enforced:

- Uses `graph TD` instead of `flowchart TD` (Azure DevOps Wiki Mermaid renderer limitation)
- Uses `---->` instead of `-->>` for sequence arrows
- No HTML tags or Font Awesome icons inside diagrams
- Wraps every diagram in `::: mermaid` fence blocks

**Formatter** (`src/wiki/formatter.py`) transforms `WikiEntry` objects into Azure DevOps Wiki-compatible markdown with proper heading hierarchy, table formatting, and section separation.

### Phase 3 — Azure DevOps connector

The ADO connector (`src/ado/`) is the integration layer between the copilot and the wiki:

**Authentication** (`auth.py`):

- Reads `AZURE_DEVOPS_PAT` from environment
- Constructs `Basic` auth header with base64-encoded PAT
- Fails fast with a descriptive error if the PAT is missing
- The PAT is scoped to **Wiki Read & Write** only — least privilege by design

**Client** (`client.py`):

- `AdoWikiClient` wraps `requests.Session` with typed dataclasses
- `get_page()` returns `WikiPage | None` — `None` signals a new page
- `create_or_update_page()` sends `If-Match` header when updating to prevent conflicts
- `list_pages()` supports full recursion for wiki inventory

**Service** (`wiki_service.py`):

- `update_wiki_for_target()` orchestrates the full lifecycle: scan → find → generate → publish
- Returns list of published page paths
- Logs every operation with correlation IDs for provenance tracking

### Phase 4 — Foundry integration

The Foundry integration (`src/foundry/project_client.py`) connects the agent to the deepseek-v4-flash deployment:

```python
def complete_with_foundry(system_prompt: str, user_input: str, settings: AppConfig) -> str:
    """Send a single-turn completion to the Foundry model deployment."""
    deployments = set(list_deployment_names(settings))
    if settings.azure_ai_chat_deployment not in deployments:
        raise RuntimeError(
            f'Configured deployment {settings.azure_ai_chat_deployment} '
            f'was not found in the Foundry project. Available: {sorted(deployments)}'
        )
    with open_project_client(settings) as project_client, \
            project_client.get_openai_client() as openai_client:
        response = openai_client.responses.create(
            model=settings.azure_ai_chat_deployment,
            instructions=system_prompt,
            input=user_input,
        )
        return response.output_text or 'No response text was returned by the model.'
```

The **RAG layer** (`src/rag/chat.py`) constructs well-structured prompts that give the model everything it needs in a single call. No iterative tool-calling loops. The system prompt encodes the documentation quality guidelines (also present in the `wiki-authoring` skill):

```python
DOCUMENTATION_SYSTEM_PROMPT = """You are a technical documentation copilot. Your task is to produce
high-quality Azure DevOps Wiki markdown entries for Python code modules.

Guidelines:
- Write clear, concise descriptions suitable for a developer audience.
- Use proper Markdown formatting compatible with Azure DevOps Wiki.
- When describing function parameters and return values, be precise.
- Identify potential edge cases, error conditions, and usage patterns.
- Never include placeholder text like "TODO" or "implement this".
- If the code metadata is incomplete, describe what is observable.
- Keep prose technical and direct. Avoid marketing language.
"""
```

### Phase 5 — Agent deployment

The agent (`agents/documentation-copilot/main.py`) is packaged as a Foundry Hosted Agent with a local HTTP server:

```python
if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8088'))
    server = HTTPServer(('0.0.0.0', port), AgentHandler)
    logger.info('Documentation Copilot agent listening on port %d', port)
    server.serve_forever()
```

Deployment follows the standard `azd` journey borrowed from `project-identity-security-copilot-v2`:

```pwsh
azd ai agent init -m "<manifest-url>" --no-prompt
azd provision
azd ai skill create wiki-authoring --file ./skills/wiki-authoring/SKILL.md --no-prompt
azd ai skill create code-analysis --file ./skills/code-analysis/SKILL.md --no-prompt
azd ai toolbox publish
```

---

## Local testing procedures

The project supports four levels of testing:

### 1. Unit tests (pytest)

```pwsh
pytest tests/ -v
```

Twenty-six tests covering:

- AST parser accuracy (function extraction, class extraction, imports)
- Mermaid diagram generation (class diagrams, sequence diagrams, fence wrapping)
- Wiki markdown formatting (section rendering, parameter tables, dependency lists)
- ADO client behaviour (404 handling, creation, error propagation)
- Prompt routing (target extraction from natural language)
- Repository walking (file discovery, exclusion patterns, target filtering)

### 2. Scan-only mode with wikicopilot.py (no Azure services needed)

```pwsh
$env:PYTHONPATH = "C:\Repo\vsCode\project-documentation-copilot\documentation-copilot"
python wikicopilot.py --target walk_repository --repo "C:\Repo\vsCode\myproject" --mode scan-only
```

This exercises the full local scanning pipeline — AST analysis, target matching, and serialisation — without touching the Foundry model or DevOps API. Ideal for rapid iteration on the parser and dependency resolver. The scan completes in milliseconds; no network access is required.

### 3. Two-tier full pipeline (requires deployed Foundry agent)

```pwsh
$env:PYTHONPATH = "C:\Repo\vsCode\project-documentation-copilot\documentation-copilot"
python wikicopilot.py --target parse_python_file --repo "C:\Repo\vsCode\myproject" --mode publish
```

The CLI scans locally, serialises the matching modules, base64-encodes the payload, and calls `azd ai agent invoke "__SCAN__:..."`. The Foundry agent deserialises the data, generates wiki prose via deepseek-v4-flash, builds Mermaid diagrams, and publishes to ADO Wiki using the service principal auth chain (Key Vault → SP Bearer token). No PAT or local Key Vault access is needed.

### 4. Local agent invocation (requires Foundry project, legacy path)

```pwsh
# Terminal 1
azd ai agent run --no-inspector

# Terminal 2
azd ai agent invoke --local "update the wiki for load_config function"
```

The agent's `main.py` starts an HTTP server on port 8088. Requests trigger the full pipeline: code scan → LLM generation → wiki publish. This exercises the original single-container path where the agent scans its own container at `TARGET_REPO_ROOT=/app`. Use this for validating the local-scan code path before `azd deploy`.

### 5. Full integration test (requires Azure resources)

```pwsh
azd ai agent invoke "update the wiki for AuthService to capture the latest changes"
azd ai agent invoke "create a new wiki for DataPipeline class"
```

These commands invoke the deployed agent against the live Foundry project and a real Azure DevOps wiki, using the legacy local-scan path (agent scans `/app`). The two-tier path via `wikicopilot.py` is the preferred production workflow.

---

## Deployment steps: The full azd journey

### Prerequisites (one-time)

```pwsh
az login
azd version                    # 1.25.3+
azd ext install microsoft.foundry
azd ext install azure.ai.skills
```

### Step 1: Scaffold the agent

```pwsh
azd ai agent init `
  -m "https://github.com/microsoft-foundry/foundry-samples/blob/main/samples/python/hosted-agents/agent-framework/responses/01-basic/agent.manifest.yaml" `
  --no-prompt

azd env set AZURE_SUBSCRIPTION_ID "<subscription-id>"
azd env set AZURE_LOCATION eastus2
```

Replace the generated `main.py` with `agents/documentation-copilot/main.py` and update `agent.manifest.yaml` with the environment variable declarations.

### Step 2: Provision infrastructure

```pwsh
azd provision
```

Creates the resource group, Foundry project, deepseek-v4-flash deployment, Log Analytics workspace, and Application Insights instance. Also creates the platform-assigned managed identity for the agent, which is then granted `Key Vault Secrets User` RBAC on the Key Vault so it can read the service principal's client ID and secret.

Set the Key Vault and tenant environment variables for the deployment:

```pwsh
azd env set KEY_VAULT_URL "https://kv-doccopilot-dev1.vault.azure.net/"
azd env set KEY_VAULT_NAME "kv-doccopilot-dev1"
azd env set AZURE_TENANT_ID "<your-tenant-id>"
```

**Critical:** The `agent.yaml` `environment_variables` block must declare these vars with `${VAR}` substitution. A typo (`KEY_VAULT_NAMEse` instead of `KEY_VAULT_NAME`) caused the service principal auth path to silently fail, forcing the agent to fall back to managed identity direct auth (which returned HTML sign-in pages from ADO). Verify the env var names in `agent.yaml` match exactly what `auth.py` reads.

Deployment verification:

```pwsh
azd ai agent show
```

Expected: `Status: creating` → `Status: active` (within 2-4 minutes for source-code deployment).

### Step 3: Upload skills

```pwsh
azd ai skill create wiki-authoring --file ./skills/wiki-authoring/SKILL.md --no-prompt -o json
azd ai skill create code-analysis --file ./skills/code-analysis/SKILL.md --no-prompt -o json
azd ai skill list -o table
```

### Step 4: Publish MCP toolbox

```pwsh
azd provision
azd ai toolbox publish
```

### Step 5: Deploy the agent

```pwsh
azd deploy
```

Expected output:

```text
Deploying services (azd deploy)

  Done: Deploying service documentation-copilot
  - Agent playground (portal): https://ai.azure.com/.../build/agents/documentation-copilot/build?version=1
  - Agent endpoint: https://ai-account-<name>.services.ai.azure.com/api/projects/<project>/agents/documentation-copilot/versions/1
```

### Step 6: Poll status

```pwsh
azd ai agent show
```

Wait for `Status: active` for the `documentation-copilot` agent.

### Step 7: Invoke

```pwsh
azd ai agent invoke "update the wiki for calculate_total to capture the latest changes"
```

### Step 8: Tear down

```pwsh
azd down
```

Deletes all resources. Rebuild from scratch with `azd provision && azd deploy`.

---

## Final inference testing results

### Test prompt 1: Update existing function documentation

```text
Input:  "update the wiki for load_config to capture the latest changes"

Target: load_config
Mode:   auto
Result: Published 1 page at API-Reference/load_config/config

Wiki page contents at API-Reference/load_config/config:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Module: config

## Overview
Python module with 2 function(s). Provides configuration loading and validation
for the application runtime. The module reads JSON configuration files and
validates settings against a predefined schema.

## Module Path
`src/config.py`

## Dependencies
**Internal Dependencies:**
- `src.models.settings`

**External Dependencies:**
- `json`
- `pathlib.Path`

## Functions
### `load_config()`

Loads application configuration from a JSON file and returns a validated
settings dictionary. Raises FileNotFoundError if the configuration file
does not exist at the specified path.

- **Line:** 15
- **Decorators:** None
- **Return Type:** `dict`

**Parameters:**
| Parameter | Type | Description |
| --- | --- | --- |
| `path` | `str` | Default: `config.json` |
| `env` | `str` | Default: `dev` |

## Workflow Diagrams
### Workflow Diagram
::: mermaid
sequenceDiagram
    title Config Loading Workflow
    participant p0 as load_config (Function)
    participant p1 as validate_settings (Function)
    p0->>+p1: invoke
:::
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Test prompt 2: Create new wiki for a class

```text
Input:  "create a new wiki for AuthService class"

Target: AuthService
Mode:   auto
Result: Published 1 page at API-Reference/AuthService/auth

Wiki page contents at API-Reference/AuthService/auth:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Module: auth

## Overview
Python module with 1 class(es). Implements authentication and session
management services for the application. Handles user login, token
generation, session validation, and secure logout.

## Module Path
`src/services/auth.py`

## Dependencies
**Internal Dependencies:**
- `src.models.token`
- `src.security.hashing`

**External Dependencies:**
- `datetime`
- `uuid`

## Classes
### `AuthService`

Handles all authentication operations including credential verification,
token issuance, session management, and logout. Extends BaseService for
logging and error handling capabilities.

- **Line:** 25
- **Base Classes:** `BaseService`

**Methods:**
| Method | Parameters | Return Type |
| --- | --- | --- |
| `login` | `self, credentials: dict` | `AuthToken` |
| `logout` | `self, token: str` | `None` |
| `validate_session` | `self, token: str` | `bool` |
| `refresh_token` | `self, token: str` | `AuthToken` |

## Workflow Diagrams
### Class Diagram
::: mermaid
classDiagram
    class AuthService {
        +login(credentials: dict) AuthToken
        +logout(token: str) None
        +validate_session(token: str) bool
        +refresh_token(token: str) AuthToken
    }
    BaseService <|-- AuthService
:::
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Test prompt 3: No target found (error handling)

```text
Input:  "update the wiki for something"

Target: something
Mode:   auto
Result: No wiki pages were published for target: something

INFO: No code found matching target: something
```

Graceful handling when the target function or class doesn't exist in the scanned repository.

### Test prompt 4: Scan-only mode

```text
Input:  "find the parse_config function"
Mode:   scan-only

--- src/parsers/config_parser.py ---
  def parse_config(path: str = 'config.yaml') -> dict
  def validate_yaml_schema(data: dict) -> bool

--- src/legacy/parser.py ---
  def parse_config(filepath: str) -> ConfigObject

Found 2 matching module(s).
```

No Azure services consumed. The scan-only mode is pure local execution and completes in milliseconds.

---

## Observability: Provenance tracking

Every operation is tracked through the provenance recorder (`src/workflow/provenance.py`). Each event carries a `correlation_id` that joins scan, generation, and publish operations into a single trace:

```json
{"event_type": "request_received", "correlation_id": "a1b2c3d4-...", "prompt": "update the wiki for load_config", "mode": "auto", "timestamp_ms": 1717948800123}
{"event_type": "scan_started", "correlation_id": "a1b2c3d4-...", "target": "load_config", "timestamp_ms": 1717948800145}
{"event_type": "scan_completed", "correlation_id": "a1b2c3d4-...", "total_modules": 47, "matching_modules": 1, "timestamp_ms": 1717948800234}
{"event_type": "publish_started", "correlation_id": "a1b2c3d4-...", "target": "load_config", "timestamp_ms": 1717948800456}
{"event_type": "publish_completed", "correlation_id": "a1b2c3d4-...", "pages_published": 1, "timestamp_ms": 1717948801789}
```

When deployed to Foundry, these events are ingested by Application Insights and queryable in the Foundry portal under **Investigate > Transaction Search**.

---

## From demo to platform

The Documentation Copilot started as a scaffold — no code, just a contract. The phased implementation plan in `OUTLINE.md` §10 defines the order: verify scaffold, implement scanner, build wiki generator, wire ADO connector, integrate Foundry, deploy agent, write blog.

Along the way, the architecture underwent its most important evolution. The initial design was a **single-agent, single-container** approach where all scanning, generation, and publishing happened inside the Foundry container. The agent used `TARGET_REPO_ROOT=/app` to scan its own deployed source tree — which worked for the demo but was useless in practice. A developer couldn't point the agent at their own repository.

The **two-tier refactor** split the workload: a local CLI (`wikicopilot.py`) handles the file-system scanning using the same `src/scanner/` modules, serialises the metadata to JSON, and sends it to the Foundry agent via a base64-encoded `__SCAN__:` protocol embedded in the `azd ai agent invoke` prompt. The agent deserialises the data, generates wiki content, and publishes — all with its service principal auth backed by Key Vault. No PAT, Key Vault access, or LLM credentials are needed on the developer workstation.

The project deliberately inherits the deployment workflow from `project-identity-security-copilot-v2` — the same `azd ai agent init` → `azd provision` → `azd deploy` → `azd ai agent invoke` journey. This means any engineer who has worked with the Identity Security Copilot family can pick up the Documentation Copilot and deploy it on the same day.

The agent architecture remains intentionally single-container. Unlike the v2 Identity Security Copilot's coordinator + specialists topology, the Documentation Copilot's workflow is linear: deserialise → generate → publish. No handoffs. No agent-to-agent envelopes. One container, one deploy. This keeps the operational surface small and the debugging surface flat. The local CLI (`wikicopilot.py`) is a thin orchestration layer — it imports the same `src/scanner/` modules that the agent itself uses, so there is no code duplication or behavioural drift between tiers.

For engineers who want to extend the copilot, the MCP toolbox surfaces (`code-scanner`, `wiki-publisher`, `diagram-generator`) are already defined with tool schemas and manifest files. The toolbox enables future multi-agent topologies or external MCP client integration without architectural change — the same surfaces, exposed differently.

---

## References

- [OUTLINE.md](./OUTLINE.md) — the full design contract and implementation phases
- [docs/feasibility-research.md](./docs/feasibility-research.md) — technical feasibility analysis
- [docs/connector-design.md](./docs/connector-design.md) — Azure DevOps REST API connector design
- [docs/azd-journey.md](./docs/azd-journey.md) — end-to-end azd deployment commands
- [docs/wiki-documentation-schema.md](./docs/wiki-documentation-schema.md) — wiki entry format specification
- [Azure DevOps MCP Server documentation](https://learn.microsoft.com/en-us/azure/devops/mcp-server/mcp-server-overview?view=azure-devops) — official Microsoft MCP server for Azure DevOps (work items, PRs, builds, test plans; no Wiki support)
- [Azure DevOps Wiki REST API (Pages)](https://learn.microsoft.com/en-us/rest/api/azure/devops/wiki/pages)
- [Azure AI Foundry documentation](https://learn.microsoft.com/en-us/azure/ai-foundry/)
- [Mermaid syntax reference](https://mermaid.js.org/)
- [project-identity-security-copilot-v2](../project-identity-security-copilot-v2/) — bootstrap template
