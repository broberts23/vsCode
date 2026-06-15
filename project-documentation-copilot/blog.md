# Building a Documentation Copilot: From Repository Scan to Live Wiki Page

A developer clones a repository, makes a change to a function signature, and types `python wikicopilot.py --target AuthService --mode publish`. Eight seconds later, the Azure DevOps Wiki page for `AuthService` has been updated with the correct parameters, return types, decorators, and a Mermaid class diagram showing the inheritance hierarchy. No markdown was written by hand. No wiki page was opened in a browser. No pull request was sent to a documentation repo that nobody maintains.

This project fills a gap that Microsoft's official Azure DevOps MCP Server leaves open. The MCP Server connects AI assistants to work items, pull requests, builds, pipelines, and test plans — it is a capable tool for sprint standups and code review workflows. What it does not expose is Wiki page management. There is no endpoint in its tool roster for creating, reading, updating, or deleting wiki pages. That gap is where the Documentation Copilot lives.

The project is a Foundry Hosted Agent paired with a local CLI that automates the most tedious part of developer documentation: keeping wiki entries in sync with live code. The CLI scans the repository on the developer's machine. The agent, running in Azure, generates prose, builds diagrams, and publishes the result through the Azure DevOps Wiki REST API. The boundary between them is clean. The developer never needs a PAT, never needs access to Key Vault, and never needs to know what a service principal is.

[Screenshot: Terminal output showing "Published 2 wiki page(s) for AuthService" with page paths]

---

## Azure AI Foundry

Azure AI Foundry is Microsoft's platform for building, deploying, and operating AI applications. It provides a project-based resource model where each project has its own endpoint, model deployments, role-based access control, and service infrastructure. The Documentation Copilot uses three Foundry capabilities.

A Foundry Hosted Agent is a containerised Python application that the platform runs and manages. You provide source code, a runtime version, and an entry point. Foundry packages the code, provisions the container, and exposes a Responses-protocol endpoint that the `azure-ai-projects` SDK can call. The agent runs as a platform-assigned managed identity, separate from the developer's user identity, which allows it to authenticate to Azure services like Key Vault without storing credentials. The agent's health is monitored through HTTP readiness probes on port 8088. If the agent fails, Foundry restarts it.

The model deployment provides the reasoning capacity for prose generation. `Deepseek-v4-Flash` is deployed as a serverless endpoint within the Foundry project, configured with the `GlobalStandard` SKU for pay-per-token billing. The agent calls this model through the `azure-ai-projects` SDK, using the same `AIProjectClient` that the CLI uses to invoke the agent. The model never sees raw source code. It receives structured metadata — function names, parameter types, return annotations, docstrings — and produces narrative descriptions suitable for a developer audience.

The Foundry project owns the security boundary. Every API call, whether to the model or to the agent, goes through the project's endpoint and is authenticated by `DefaultAzureCredential` using either the caller's Azure CLI session or the agent's managed identity. Role assignment controls which operations each caller can perform. The agent's managed identity has `Key Vault Secrets User` access to read the service principal's client ID and secret, and the developer's identity has `Foundry User` to invoke the agent and the model.

---

## Azure Developer CLI

The Azure Developer CLI, or `azd`, is Microsoft's tool for provisioning and deploying Azure applications from a project template. It reads an `azure.yaml` file and an `infra/` directory to understand the project structure and infrastructure requirements. The Foundry Toolkit extension adds agent-specific commands.

The deployment lifecycle for this project follows five `azd` commands that run in sequence. `azd ai agent init` scaffolds the project with the Foundry agent template. It creates the `documentation-copilot/` directory with a sample `agent.yaml` and sets up the `azure.yaml` manifest. The init command accepts a manifest URL from the Foundry samples repository, a project resource ID, a runtime version, an entry point, and a deployment mode. The deployment mode is `code`, meaning the source is uploaded as a zip rather than packaged in a container image.

`azd provision` creates the Azure infrastructure. It calls the Bicep templates in `infra/main.bicep` to provision the Foundry project, the Cognitive Services account with a custom domain name, the `Deepseek-v4-Flash` model deployment, the Log Analytics workspace, and the Application Insights instance. Provisioning takes about five minutes. The output includes the project endpoint URL that all subsequent commands use.

Environment variables are set after provisioning through `azd env set`. The project endpoint, the DevOps organization URL, the wiki ID, the Key Vault URL and name, and the Azure tenant ID are all stored in the `azd` environment so that `agent.yaml`'s `${VAR}` substitution syntax resolves them at deploy time.

`azd deploy` packages the source code, uploads it to the agent service, and polls until the version reaches `active` status. The deploy output includes the agent's portal link and the responses endpoint URL. When the status changes from `creating` to `active`, the agent is ready to receive requests.

`azd ai agent invoke` sends a prompt to the deployed agent and displays the response. It routes through the Foundry runtime's authentication infrastructure, which is separate from the user-facing REST endpoint. The body format is `{"input": "...", "stream": false}`.

```powershell
azd ai agent init -m "<manifest-url>" --no-prompt --project-id "<id>" --deploy-mode code --runtime python_3_13 --entry-point main.py --agent-name "documentation-copilot"
azd provision
azd env set AZURE_AI_PROJECT_ENDPOINT "<endpoint>"
azd env set AZURE_DEVOPS_ORG_URL "https://dev.azure.com/myorg"
azd env set AZURE_DEVOPS_PROJECT "myproject"
azd env set AZURE_DEVOPS_WIKI_ID "myproject.wiki"
azd env set KEY_VAULT_URL "https://kv-doccopilot-dev1.vault.azure.net/"
azd env set KEY_VAULT_NAME "kv-doccopilot-dev1"
azd env set AZURE_TENANT_ID "<tenant-id>"
azd deploy
```

---

## The Two-Tier Architecture

The Documentation Copilot is not a monolithic agent. It is two systems that communicate across a well-defined interface.

The local tier is `wikicopilot.py`, a 266-line CLI that runs on the developer workstation. It does everything that requires access to the file system: scanning Python files with the `ast` module, extracting function and class metadata, resolving import dependencies, and serialising the results to JSON. This tier has zero network dependencies and completes in milliseconds. The developer does not need a PAT, Key Vault access, or Foundry credentials.

The cloud tier is the Foundry Hosted Agent, a single-container Python HTTP server running in Azure. It does everything that requires network access or secrets: deserialising scan data, calling `Deepseek-v4-Flash` for prose generation, building Mermaid diagrams, and publishing wiki pages through the Azure DevOps REST API. It authenticates to ADO using a two-step service principal flow: the agent's platform-assigned managed identity reads the service principal's client ID and secret from Key Vault, then exchanges them for a Microsoft Entra Bearer token via the OAuth 2.0 client credentials grant.

The data interface between them is JSON. The CLI serialises `ModuleInfo` objects to dicts, the agent deserialises them back, and the round-trip is lossless. No file paths are shared. No repository structure is transmitted. The agent receives structured metadata and returns structured results.

---

## The Agent Modules

The agent's Python code is organised into six modules under `src/`, each with a single responsibility.

**Scanner** (`src/scanner/`) walks the repository and extracts code metadata. `python_parser.py` uses Python's built-in `ast` module to parse each file without executing it. It overrides `visit_FunctionDef`, `visit_ClassDef`, and the import visitors to accumulate `FunctionInfo`, `ClassInfo`, and `ParamInfo` dataclasses. The parser handles type annotations, decorators, default parameter values, and docstrings. It skips files with syntax errors and logs a warning instead of crashing. `repo_walker.py` recurses through a directory tree with `Path.rglob('*.py')`, excluding virtual environments, build directories, and cache folders. It produces a flat list of `ModuleInfo` objects. `dependency_resolver.py` classifies each import as internal or external based on namespace prefix matching, supporting both the internal scan path and the pre-scanned data path.

**RAG** (`src/rag/`) constructs the prompts that drive the LLM. `chat.py` defines `DOCUMENTATION_SYSTEM_PROMPT`, a set of guidelines that tell the model to write clear, technically accurate descriptions without placeholder text. For each function and class, it builds a prompt that includes the name, parameters, return type, decorators, and docstring. The system prompt and the user input are sent to `complete_with_foundry()`, which calls the model deployment through the `azure-ai-projects` SDK.

**Wiki** (`src/wiki/`) builds the markdown that goes into the Azure DevOps Wiki. `generator.py` orchestrates the pipeline: it calls the RAG layer for prose descriptions, formats parameter tables, resolves dependencies, and decides whether to include Mermaid diagrams based on module complexity. `formatter.py` renders `WikiEntry` and `WikiSection` objects into ADO-compatible markdown with correct heading hierarchy. `mermaid_builder.py` generates `classDiagram` and `sequenceDiagram` strings using Azure DevOps Wiki-compatible Mermaid syntax. Diagrams use `graph TD` instead of `flowchart TD`, use `---->` instead of `-->>` for sequence arrows, and avoid HTML tags and Font Awesome icons. Each diagram is wrapped in `::: mermaid` fence blocks.

**ADO** (`src/ado/`) connects to the Azure DevOps Wiki REST API v7.1. `client.py` implements `AdoWikiClient`, which wraps `requests.Session` with typed dataclasses. `get_page()` returns `WikiPage` with an ETag version or `None` if the page does not exist. `create_or_update_page()` sends a PUT request with an `If-Match` header for safe concurrent editing. Every response is validated by content type — HTML responses are treated as authentication failures, logged with context, and returned as typed `WikiPageResult` errors. `wiki_service.py` orchestrates the full lifecycle: it calls `update_wiki_for_target()` for the local-scan path (legacy) or `update_wiki_for_target_from_data()` for the pre-scanned data path (preferred). Both functions call the same `_publish_modules()` core, which iterates matching modules, generates content, ensures ancestor pages exist, and publishes each page. `auth.py` implements the three-tier authentication hierarchy that the agent uses to authenticate to ADO.

The first tier of ADO auth tries service principal authentication backed by Key Vault. The agent's managed identity acquires a Microsoft Entra token for scope `https://app.vssps.visualstudio.com/.default` and uses it to read `AdoServicePrincipalClientId`, `AdoServicePrincipalSecret`, and `AdoServicePrincipalObjectId` from the Key Vault. These credentials are exchanged for a Bearer token through the OAuth 2.0 client credentials flow. The resulting token authenticates all ADO Wiki REST API calls. No long-lived secrets enter the agent's environment variables.

The second tier falls back to managed identity direct authentication if the Key Vault is unreachable. The agent uses its platform-assigned identity to acquire a token for the same ADO scope. This path requires the managed identity to be added as a user in Azure DevOps with Wiki permissions.

The third tier uses a Personal Access Token from the `AZURE_DEVOPS_PAT` environment variable. This is the local development fallback used when the agent runs outside Azure.

[Screenshot: auth.py code showing the three-tier authentication flow]

**Foundry** (`src/foundry/`) connects the agent to the Foundry project. `project_client.py` provides `open_project_client()`, a context manager that creates an `AIProjectClient` with `DefaultAzureCredential`. It exposes `complete_with_foundry()` for single-turn model completions and `list_deployment_names()` for verifying that the configured model deployment exists.

**Module Serializer** (`src/ado/module_serializer.py`) provides the JSON round-trip that bridges the two tiers. `module_info_to_dict()` converts a `ModuleInfo` tree to a JSON-serialisable dict, handling the recursive `FunctionInfo` → `ParamInfo` and `ClassInfo` → method → `FunctionInfo` nesting. `dict_to_module_info()` reconstructs the full tree from a dict. The serialisation is lossless: every field in every dataclass survives the round trip.

**Skills** (`skills/`) are Foundry skill files that are uploaded to the project and attached to the agent at deploy time. `wiki-authoring/SKILL.md` encodes content quality standards: markdown compatibility rules, page path conventions, and Mermaid diagram constraints. `code-analysis/SKILL.md` defines the agent's standards for code extraction, dependency resolution, and metadata completeness. At agent startup, Foundry injects both skill files into the agent's system prompt. Skills are versioned and uploaded via `azd ai skill create`.

---

## How the CLI Works

`wikicopilot.py` at the project root is the developer's entry point. It imports from the same `src/` modules that the agent uses, which means the scanner and the serialiser produce identical results whether they run on the developer's laptop or inside the agent's container.

When invoked with `--target AuthService --mode publish`, the CLI runs four operations.

First, it resolves the project endpoint from the `--project-endpoint` flag, the `AZURE_AI_PROJECT_ENDPOINT` environment variable, or a hardcoded default. Then it creates an `AIProjectClient` with `DefaultAzureCredential`, which acquires a token from the developer's `az login` session. The `allow_preview=True` parameter enables the preview SDK surface that supports agent invocation.

```python
from azure.identity import DefaultAzureCredential
from azure.ai.projects import AIProjectClient

project = AIProjectClient(
    endpoint=project_endpoint,
    credential=DefaultAzureCredential(),
    allow_preview=True,
)
openai_client = project.get_openai_client(agent_name="documentation-copilot")
```

Second, it binds an OpenAI client to the agent via `get_openai_client(agent_name=...)`. This configures the client to route all requests through the Foundry infrastructure to the specific agent's responses endpoint. The SDK handles authentication internally, using the same credential but routing through Foundry's gateway rather than the user-facing REST API.

Third, it serialises the scanned module metadata to JSON and passes it as `extra_body` to `responses.create()`.

```python
response = openai_client.responses.create(
    input=f"update the wiki for {target_name}",
    stream=False,
    extra_body={
        "mode": mode,
        "scan_data": scan_data,
    },
)
```

The JSON body that reaches the agent's `do_POST` handler contains the `input` field, the `scan_data` array of serialised modules, and the `mode` field. The agent extracts all three, deserialises the modules, and proceeds to generation and publishing. No base64 encoding is involved. No gzip compression is needed. No command-line argument length limit applies because the data travels in the HTTP body.

Fourth, it extracts the agent's response from the OpenAI Responses envelope. The Foundry ingress wraps the agent's custom JSON inside the standard OpenAI format before returning it to the SDK. The agent's output lives at `response.output[0].content[0].text`. The `_extract_agent_output()` function navigates this nesting with `getattr` calls and returns the raw JSON string.

The full payload from CLI to agent is:

```json
{
  "input": "update the wiki for AuthService",
  "stream": false,
  "mode": "publish",
  "scan_data": [
    {
      "file_path": "src/auth/service.py",
      "functions": [
        {
          "name": "login",
          "file_path": "src/auth/service.py",
          "line_number": 25,
          "docstring": "Authenticate user with credentials.",
          "decorators": [],
          "parameters": [
            {"name": "self", "type_annotation": null, "default_value": null},
            {"name": "credentials", "type_annotation": "dict", "default_value": null}
          ],
          "return_type": "AuthToken"
        }
      ],
      "classes": [],
      "imports": ["datetime", "src.models.token"]
    }
  ]
}
```

The full response from agent to CLI is:

```json
{"status": "success", "target": "AuthService", "pages_published": 1, "pages": ["API-Reference/AuthService/auth_service"], "correlation_id": "a1b2c3d4-..."}
```

The CLI then prints a human-readable summary or, with the `--json` flag, the raw JSON.

[Screenshot: wikicopilot.py help output showing all CLI flags]

---

## Deployment Walkthrough

The deployment journey from a clean state to a running agent takes about fifteen minutes and follows this sequence.

A Foundry project is created under a Cognitive Services account. The account is provisioned with `az cognitiveservices account create`, specifying a custom subdomain name. The project is created under the account with `az cognitiveservices account project create`. The project name `doccopilot` appears in all subsequent resource IDs and endpoint URLs.

A dedicated service principal is registered in Microsoft Entra ID for ADO authentication. Its client ID and secret are stored in Key Vault under stable names: `AdoServicePrincipalClientId`, `AdoServicePrincipalSecret`, and `AdoServicePrincipalObjectId`. The client secret never enters an environment variable. It is fetched from Key Vault at runtime by the agent's managed identity.

The service principal is added to Azure DevOps as a user by a Project Collection Administrator. It receives a Basic access level and Wiki Read and Write permissions on the target project. This is a one-time operation performed through the Azure DevOps portal or the ServicePrincipalEntitlements REST API.

The agent is initialised with `azd ai agent init`, which scaffolds the project directory and creates the `agent.yaml` configuration. The environment variables in `azd env` are set to point at the project endpoint, the ADO organization and wiki ID, and the Key Vault details. The `agent.yaml` environment variables block must declare these vars with `${VAR}` substitution so the agent's container has them at startup.

```yaml
environment_variables:
    - name: KEY_VAULT_URL
      value: ${KEY_VAULT_URL}
    - name: KEY_VAULT_NAME
      value: ${KEY_VAULT_NAME}
    - name: AZURE_TENANT_ID
      value: ${AZURE_TENANT_ID}
    - name: AZURE_AI_PROJECT_ENDPOINT
      value: ${AZURE_AI_PROJECT_ENDPOINT}
    - name: AZURE_AI_MODEL_DEPLOYMENT_NAME
      value: ${AZURE_AI_MODEL_DEPLOYMENT_NAME}
    - name: AZURE_DEVOPS_ORG_URL
      value: ${AZURE_DEVOPS_ORG_URL}
    - name: AZURE_DEVOPS_PROJECT
      value: ${AZURE_DEVOPS_PROJECT}
    - name: AZURE_DEVOPS_WIKI_ID
      value: ${AZURE_DEVOPS_WIKI_ID}
```

Infrastructure is provisioned with `azd provision`, which creates the Foundry project, model deployment, monitoring resources, and the agent's managed identity. The managed identity is granted `Key Vault Secrets User` RBAC on the Key Vault.

The agent is deployed with `azd deploy`. The tool packages the source into a zip, uploads it to the Foundry Agent Service, and polls until the version reaches `active` status. Each deployment creates a new version number. The agent version, status, and endpoint URL are visible through `azd ai agent show`.

---

## Using the Documentation Copilot

A developer who wants to update wiki documentation runs two commands. The first sets the Python path so the CLI can import the shared scanner modules. The second invokes the CLI with the target function or class name.

```powershell
$env:PYTHONPATH = "C:\Repo\vsCode\project-documentation-copilot\documentation-copilot"
$env:AZURE_AI_PROJECT_ENDPOINT = "https://cog-doccopilot-dev01.services.ai.azure.com/api/projects/doccopilot"
python wikicopilot.py --target AuthService --mode publish
```

The CLI scans the repository, serialises the matching modules, and sends them to the Foundry agent. The agent generates wiki content, publishes the pages, and returns the results. The developer sees a summary of which pages were created or updated.

Scan-only mode shows what the scanner would find without publishing anything.

```powershell
python wikicopilot.py --target AuthService --mode scan-only
```

This exercises the full local pipeline without touching any Azure service. The scanner walks the repository, extracts function and class metadata, and prints a summary of what it found. The scan completes in milliseconds.

Natural-language prompts are supported for target extraction. The CLI uses regex heuristics to identify function and class names in prompts like "update the wiki for walk_repository function" or "scan for AuthService class". If the target cannot be extracted, the CLI asks the user to specify `--target` explicitly.

```powershell
python wikicopilot.py "document the parse_config function"
python wikicopilot.py --repo C:\git\myproject --target AuthService --mode publish
```

The developer does not need a PAT, Key Vault access, or LLM credentials. The SDK uses `DefaultAzureCredential` from the `az login` session. The Foundry agent handles everything beyond the local file scan using its service principal auth chain.

[Screenshot: Azure DevOps Wiki page showing the generated documentation for AuthService with parameter table and class diagram]

### Conclusion

The Documentation Copilot bridges a narrow but painful gap in the developer workflow: the space between a changed function signature and the wiki page that never gets updated because writing documentation by hand feels like overhead, not engineering. The current implementation targets individual functions and classes within a single repository, scanning their AST metadata, generating wiki prose via `Deepseek-v4-Flash`, and publishing the result to Azure DevOps Wiki through a service-principal authenticated REST API.

This is a proof of concept, and its constraints are intentional. The wiki page structure follows a fixed template with sections for Overview, Module Path, Dependencies, Functions, Classes, and Workflow Diagrams. The AI prompt is a single-turn completion with no conversational memory, no retrieval-augmented generation pipeline, and no ability to refine its output based on follow-up requests. The supported documentation scope is limited to what the AST scanner can extract from Python source files — function signatures, class hierarchies, parameter types, decorators, and docstrings. Cross-module relationships, architectural patterns, and design rationale are not captured.

Extending the scope to cover entire code domains, shared libraries, or full project modules requires advancing the target resolution mechanism. The current regex-based approach extracts a single function or class name from the prompt. A hierarchical target resolver could accept paths like `lib/authentication/providers` or `domains/billing` by maintaining a module tree index that maps logical namespaces to their constituent source files. The scanner already produces flat `ModuleInfo` lists; a tree-based filter that selects all modules under a given prefix would let the CLI process a directory or package in a single invocation. The agent would generate one wiki page per matching module and link them through a parent index page that the wiki service creates automatically. For shared libraries published as pip packages, the scanner would need a counterpart that reads from installed wheel metadata rather than a local checkout, or from a documentation manifest that the library maintainer controls.

The base wiki template is designed for extension. The `WikiSection` model in `formatter.py` is a heading-and-body pair that maps cleanly to any markdown structure. Adding a Changelog section that the generator populates from git commit history between two tags requires two changes: a call to `git log` in the scanner layer that produces structured change entries, and a `WikiSection` renderer in the formatter that formats them as a dated list. Adding a Usage Examples section requires the RAG prompt to include the function's call sites, which the scanner can collect by searching `grep -r` across the repository for imports and invocations. Adding cross-reference links between related modules requires the dependency resolver to emit inbound references alongside outbound imports, which the wiki generator can format as a "Referenced By" table. The template can also be swapped entirely: a team that prefers Notion or Confluence would replace `formatter.py` with that platform's markdown dialect and keep every other module unchanged.

Custom documentation formats are handled at the formatter boundary. The `WikiEntry` dataclass and its `WikiSection` children are platform-agnostic. An ADO-specific formatter applies the `::: mermaid` fence style for diagrams. A GitHub Wiki formatter would use triple-backtick fences instead. A MkDocs formatter would emit YAML front matter and page-level navigation configuration. The choice is a single function signature swap. The same pipeline — scan, generate, format, publish — operates against any target with a different formatter and a different API client.

Tailoring outputs to team conventions follows the same pattern. The `DOCUMENTATION_SYSTEM_PROMPT` in `rag/chat.py` controls the model's tone, depth, and structure. A team that wants architecture decision records alongside function documentation would extend the prompt to request them and add a `WikiSection` for ADRs in the generator. A team that wants security-sensitive parameters flagged in red would add a post-processing step in the formatter that detects environment variable names, private key references, or secret patterns and wraps them in inline warning callouts. Every customisation lives in a single module and leaves the rest of the pipeline untouched.

Stay tuned for future updates as I explore more advanced RAG techniques, multi-turn conversations, and support for additional documentation targets beyond Azure DevOps Wiki. 🚀

## References

- Foundry Hosted Agent deployment guide: <https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/deploy-hosted-agent-code>
- Azure DevOps Wiki REST API (Pages): <https://learn.microsoft.com/en-us/rest/api/azure/devops/wiki/pages>
- Azure Developer CLI: <https://learn.microsoft.com/en-us/azure/developer/azure-developer-cli/>
