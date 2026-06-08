# Building an Expanded Identity Security Copilot with Azure AI Foundry

If you hang around identity security teams for a day, you quickly notice that their questions never fit into a single neat box. In the morning, someone needs a deep, grounded answer about which Conditional Access policies are safeguarding break-glass accounts. In the afternoon, a manager asks for a clean executive summary on workload identity baselines. And later that week, an analyst runs a query where the initial search results come back too sparse, meaning the assistant needs to ask follow-up questions or run a narrower lookup before offering advice with any confidence.

This Identity Security Copilot is deliberately constrained to answering questions based only on the static documentation in its knowledge directory (for now...), not live data sources like Microsoft Graph API. The system ingests markdown files into Azure AI Search during setup, creating a fixed knowledge base that the model queries for grounded responses. It cannot access current directory states, active Conditional Access policies, or real-time access review data - this is by design to maintain a tight security boundary.

Standard AI sample templates do a great job of showing how to call an LLM with a single prompt or spin up a basic RAG setup, but they leave out what it takes to build a cohesive, reliable application boundary. If we want a copilot that engineers can actually trust, we need more than a retrieval loop and a folder full of markdown files. We need a system that understands different tasks, queries bounded knowledge sources, and integrates deployment configuration in a logical, automated way while maintaining strict separation from live production data.

That is exactly what this project sets out to build. It is a full reference implementation of an Identity Security Copilot that runs on Azure AI Foundry, handling grounded Q&A against its pre-approved knowledge base, adapting tasks to the right model deployments, and leveraging selective read-only tools to make smarter lookups within its constrained data scope. But rather than stay at the architectural whiteboard level, let's walk through exactly how the code makes this work, from the configuration object that wires everything together to the tool-calling loop that lets the model refine its own evidence.

## The Two Azure Services Powering the Copilot

This project rests on two Azure services that, together, form the spine of every grounded response the copilot produces. Understanding what each one does and why they appear in tandem is essential before diving into the code, because the architecture makes deliberate choices about which responsibility belongs to which service.

**Azure AI Foundry** is a unified platform for building, managing, and consuming AI applications and agents. Think of it as the orchestration layer. It hosts model deployments (the actual inference endpoints), enforces RBAC boundaries around who can call those models, and provides a project-scoped SDK client that handles authentication, endpoint resolution, and response streaming. When this copilot sends a prompt to a model, it does so through the Foundry project client, not by hitting an OpenAI endpoint directly. That indirection matters because it means every model call inherits the access controls, audit logging, and cost tracking configured at the Foundry project level. The project also exposes a management plane the SDK can query, which is how the copilot performs its preflight deployment validation and lists available models through the `list_foundry_deployments` tool.

**Azure AI Search** fills a completely different role. It is a dedicated search service purpose-built for full-text and vector search over indexed content. In this project, it acts as the grounded knowledge store. The markdown files in the `knowledge/` directory get split into sections, projected into typed documents with deterministic IDs, and uploaded to a search index that has semantic ranking configured at the schema level. When a question arrives, the copilot queries this index using `QueryType.SEMANTIC`, which means the search service applies a deep-learning reranker to the initial keyword results, surfaceing the passages most likely to contain relevant evidence. The search service never sees a model call, and Foundry never stores the markdown content. The two services operate at arm's length, connected only by the application layer that calls them in sequence.

The choice to use both services rather than, say, stuffing all the markdown into a model prompt or relying on a single vector database comes down to separation of concerns. Azure AI Search is optimized for retrieval at scale. It handles ranking, filtering, and field-level scoring without consuming any inference tokens. Azure AI Foundry is optimized for model orchestration with security boundaries built in. The copilot routes data between them, but neither service needs to know about the other's existence. That separation is what lets each piece evolve independently.

## From Environment Variables to a Typed Contract

Every copilot session starts with configuration, and this one is no exception. But instead of scattering `os.environ.get()` calls across a dozen files, the project centralizes everything into a single dataclass.

```python
@dataclass(slots=True)
class AppConfig:
    azure_ai_project_endpoint: str
    azure_ai_chat_deployment: str
    azure_ai_summary_deployment: str
    azure_search_endpoint: str
    azure_search_index_name: str
    knowledge_root: Path
```

The classmethod `from_env` reads required variables like `AZURE_AI_PROJECT_ENDPOINT` and `AZURE_SEARCH_ENDPOINT`, fails fast if they are missing, and optionally falls back to the chat deployment for summaries when no separate summary deployment is specified. The `knowledge_root` defaults to `./knowledge`, resolved relative to wherever the app runs. This single object is then passed through every function in the call chain, which means no module ever needs to know where configuration comes from. It just reads the object. That is a small decision that pays dividends the moment you try to test or debug the pipeline, because you can construct an `AppConfig` in memory without touching a single environment variable.

## How Markdown Becomes Grounded Evidence

The knowledge base lives in a repo folder called `knowledge/`, containing three markdown files that cover Conditional Access policies, access review decision guidance, and workload identity security. The contents are not particularly long, which is intentional. It's designed to demonstrate a pattern, not ship a complete identity library. The document set could be expanded to include more detailed internal business information or even external sources like API documentation, but for this example, the focus is on demonstrating how to create a grounded Q&A system.

The real work happens in `markdown_loader.py`. It reads every `.md` file in the knowledge directory, then splits each file at every heading boundary into individual `MarkdownSection` objects. A file like `conditional-access.md` with a `## Baseline expectation` heading and a `## Common weak pattern` heading produces two sections, each with its own title, content block, and file path. These are then projected into `SearchDocument` objects.

```python
def build_search_documents(knowledge_root: Path) -> list[SearchDocument]:
    documents: list[SearchDocument] = []
    for section in load_markdown_sections(knowledge_root):
        document_id = _make_document_id(section.file_path, section.heading)
        tags = _build_tags(section.file_path, section.heading)
        documents.append(
            SearchDocument(
                id=document_id,
                source_type='markdown',
                title=section.title,
                content=section.content,
                file_path=section.file_path.as_posix(),
                heading=section.heading,
                tags=tags,
            )
        )
    return documents
```

The document ID is computed deterministically from the file stem and the heading slug, which means running the ingestion pipeline twice produces the same IDs for the same content. That is critical for idempotent indexing. Push the same documents to Azure AI Search on a second run, and the service simply updates the existing entries rather than creating duplicates.

The search index schema itself is defined in `build_index.py` as a typed `SearchIndex` object with semantic prioritization configured at creation time. The `content` and `title` fields are designated as semantic content fields, while `tags` feeds into keyword fields. This means the moment a query arrives, the search service knows which fields matter most for ranking, without any query-time configuration.

```python
return SearchIndex(
    name=settings.azure_search_index_name,
    fields=[
        SimpleField(name='id', type=SearchFieldDataType.STRING, key=True),
        SearchableField(name='source_type', type=SearchFieldDataType.String, filterable=True),
        SearchableField(name='title', type=SearchFieldDataType.String),
        SearchableField(name='content', type=SearchFieldDataType.String),
        SimpleField(name='file_path', type=SearchFieldDataType.STRING, filterable=True),
        SearchableField(name='heading', type=SearchFieldDataType.String),
        SearchableField(name='tags', type=SearchFieldDataType.String, filterable=True),
    ],
    semantic_search=SemanticSearch(
        configurations=[
            SemanticConfiguration(
                name='default',
                prioritized_fields=SemanticPrioritizedFields(
                    title_field=SemanticField(field_name='title'),
                    content_fields=[SemanticField(field_name='content')],
                    keywords_fields=[SemanticField(field_name='tags')],
                ),
            )
        ]
    ),
)
```

Every search query runs with `QueryType.SEMANTIC` and uses this configuration. The results come back as scored documents, which the app then flattens into plain dictionaries and formats into a grounded context block.

## Routing Requests by Intent, Not by Accident

The chat entry point in `app.py` accepts three arguments: `--prompt` for a question, `--summarize` for a topic to summarize, and `--mode` to override automatic behavior. But the default mode, `auto`, is where the interesting logic lives. It calls `route_request`, which in turn calls `build_copilot_plan`.

```python
def build_copilot_plan(prompt: str) -> CopilotPlan:
    normalized_prompt = ' '.join(prompt.split())
    lowered_prompt = normalized_prompt.lower()
    summary_prefixes = ('summarize', 'summary',
                        'give me a summary', 'provide a summary')
    summary_keywords = ('brief', 'overview', 'executive summary', 'key points')

    if lowered_prompt.startswith(summary_prefixes) or any(keyword in lowered_prompt for keyword in summary_keywords):
        return CopilotPlan(
            operation='summarize',
            retrieval_query=normalized_prompt,
            use_tools=False,
        )

    return CopilotPlan(
        operation='answer',
        retrieval_query=normalized_prompt,
        use_tools=True,
    )
```

The heuristic is deliberately simple. It checks whether the prompt starts with a summary-oriented phrase or contains summary keywords. If it does, the request is routed to `summarize_evidence`, which calls the summary deployment directly. No retrieval, no tool calling, just a compact call to a lighter model. If the request looks like a question, it goes to `answer_question`, which runs the full retrieval pipeline and enables tool calling.

This separation matters because reasoning tokens are not free. Running a 120B-parameter model to produce a one-paragraph recap of workload identity risks is wasteful when a smaller, faster deployment can do the same job at a fraction of the latency and cost. The architecture keeps the expensive model reserved for the cases where it actually needs to reason across multiple evidence documents and potentially call tools.

## The Grounded Q&A Pipeline

When a question reaches `answer_question`, the flow proceeds through four stages: search, completion, citation formatting, and masking.

Search runs against the Azure AI Search index with semantic ranking, pulling back the top five documents. The raw SDK results are normalized into plain dictionaries with a fixed set of fields. This normalization step is worth noting because the Azure Search SDK returns results as a paginated sequence of objects that are not quite dictionaries and not quite records. Normalizing them into a consistent shape means the rest of the pipeline never needs to know about the SDK's response format.

```python
def search_documents(prompt: str, settings: AppConfig, top: int = 5) -> list[dict[str, Any]]:
    client = create_search_client(settings)
    results = client.search(
        search_text=prompt,
        query_type=QueryType.SEMANTIC,
        semantic_configuration_name='default',
        top=top,
        select=['id', 'source_type', 'title', 'content', 'file_path', 'heading', 'tags'],
    )
    documents: list[dict[str, Any]] = []
    for result in results:
        documents.append({
            'id': result.get('id'),
            'source_type': result.get('source_type'),
            'title': result.get('title'),
            'content': result.get('content'),
            'file_path': result.get('file_path'),
            'heading': result.get('heading'),
            'tags': result.get('tags'),
        })
    return documents
```

The completion stage builds a grounded context string from these documents, then validates that the configured deployment actually exists in the Foundry project. This is a preflight check that prevents the silent failure mode where the model name is misspelled or the deployment was removed. If the deployment is missing, the function raises a clear error rather than letting the model call fail with a cryptic SDK message.

When tool calling is enabled, `complete_with_foundry` delegates to `complete_with_tools`, which is the most architecturally interesting part of the system.

## The Tool-Calling Loop

The model receives the original question, the initial grounded context, and a list of two tool definitions. The first is `search_identity_knowledge`, which lets the model issue a new search query against the knowledge base with a configurable result count. The second is `list_foundry_deployments`, which returns the names of all model deployments available in the current Foundry project.

```python
def build_foundry_tools() -> list[dict[str, Any]]:
    return [
        {
            'type': 'function',
            'name': 'search_identity_knowledge',
            'description': 'Search the identity security markdown knowledge base for grounded evidence.',
            'parameters': {
                'type': 'object',
                'properties': {
                    'query': {
                        'type': 'string',
                        'description': 'The identity security question or topic to search for.',
                    },
                    'top': {
                        'type': 'integer',
                        'description': 'How many grounded documents to return.',
                        'minimum': 1,
                        'maximum': 8,
                    },
                },
                'required': ['query'],
                'additionalProperties': False,
            },
        },
        {
            'type': 'function',
            'name': 'list_foundry_deployments',
            'description': 'List model deployments available through the current Foundry project.',
            'parameters': {
                'type': 'object',
                'properties': {},
                'additionalProperties': False,
            },
        },
    ]
```

The tool-calling loop runs for up to three iterations. After each model response, `extract_function_calls` inspects the output for any `function_call` items and normalizes them into plain dictionaries. If function calls are present, the app dispatches each one to `run_tool_call`, which matches the tool name, parses the arguments, and executes the corresponding operation. The results are collected and sent back to the model as `function_call_output` items in a follow-up request that reuses the previous response ID, maintaining conversational continuity.

```python
for _ in range(3):
    function_calls = extract_function_calls(response)
    if not function_calls:
        return response.output_text or 'No response text was returned by the model.', evidence_results

    tool_outputs: list[dict[str, str]] = []
    for call in function_calls:
        tool_result, discovered_results = run_tool_call(call, settings)
        evidence_results.extend(discovered_results)
        tool_outputs.append({
            'type': 'function_call_output',
            'call_id': str(call.get('call_id', '')),
            'output': json.dumps(tool_result),
        })

    response = openai_client.responses.create(
        model=settings.azure_ai_chat_deployment,
        previous_response_id=response.id,
        input=tool_outputs,
    )
```

This three-iteration limit is a deliberate safety constraint. It prevents runaway tool loops where the model keeps calling tools without producing a final answer. In practice, a model that needs more evidence usually calls `search_identity_knowledge` once or twice, gets the additional context, and then answers. The deployment listing tool exists mostly as a demonstration of how to expose live system state to the model without granting it any write authority.

## The Security Boundary That Runs Through Everything

Every tool is read-only. Every search runs against a pre-approved markdown index. Every model call happens through the Foundry project client, which enforces its own RBAC boundary. And after the model produces its answer, the `mask_answer` function runs a final pass.

```python
def mask_answer(answer: str) -> str:
    masked = answer.replace('breakglass@contoso.com', 'breakglass@redacted.example')
    masked = masked.replace('automation-admin', 'automation-admin-redacted')
    return masked
```

The masking logic is intentionally narrow. It covers a few known sensitive strings rather than attempting a broad data-loss-prevention scan. The idea is that the sample patterns demonstrate the approach, and a production deployment would expand this list or replace it with a regex-based or service-backed redaction layer. But the architectural principle is established: the copilot gets exactly one chance to format its answer before it reaches the user, and that final pass is owned by deterministic, auditable code, not by the model.

The infrastructure layer reinforces this philosophy. The Bicep template provisions Azure AI Search with local authentication disabled, Key Vault with RBAC authorization, and App Configuration with local auth turned off. Every resource uses managed identity for authentication. The PowerShell export script reads the deployment outputs and produces ready-to-use environment variable blocks, which means no connection strings or keys ever need to be copied by hand.

```powershell
$variables = [ordered]@{
    AZURE_AI_CHAT_DEPLOYMENT    = $ChatDeployment
    AZURE_AI_PROJECT_ENDPOINT   = $FoundryProjectEndpoint
    AZURE_AI_SUMMARY_DEPLOYMENT = $SummaryDeployment
    AZURE_SEARCH_ENDPOINT       = [string]$outputs.searchEndpoint.value
    AZURE_SEARCH_INDEX_NAME     = $SearchIndexName
    KNOWLEDGE_ROOT              = $resolvedKnowledgeRoot
}
```

The script can output environment blocks for PowerShell, Bash, or both, and it strips the values from any infrastructure outputs that contain secrets. This is the infrastructure equivalent of the `mask_answer` function: a deterministic, automated step that prevents sensitive values from leaking into the wrong context.

## Putting It All Together: The Full Request Lifecycle

It is one thing to read about configuration objects, search indices, and tool-calling loops in isolation. It is another to watch them wire together as a single prompt travels from the terminal through every layer of the system. So let's trace a concrete invocation end to end.

A user runs `python src/app.py --prompt "What Conditional Access policies protect break-glass accounts?"`. The entry script in `app.py` receives this as a string through `argparse`, does nothing clever with it, and immediately hands it to `route_request` in `chat.py`. That function calls `build_copilot_plan`, which normalizes the prompt to lowercase, checks for summary-oriented phrases, finds none, and returns a `CopilotPlan` with `operation='answer'`, `use_tools=True`, and the original prompt as the retrieval query.

Now `answer_question` takes over. Its first real action is to call `search_documents`, which creates a search client through `src/search/service.py` using the endpoint and index name from the shared `AppConfig` instance. That client fires a semantic query at Azure AI Search, asking for the top five documents matching the prompt. The search service returns scored results, which the code normalizes into plain dictionaries. At this point, the copilot has made its first Azure service call of the request lifecycle.

![Screenshot of the Azure AI Search index browser showing indexed documents, fields, and semantic configuration](images/ai-search-index.png)

The retrieved documents are assembled into a grounded context block with document IDs inline. Before anything reaches the model, `complete_with_foundry` runs a preflight validation: it calls the Foundry SDK to confirm that the configured chat deployment name actually exists in the project. If the deployment was removed or the name was misspelled, the pipeline fails here with a clear error, before a single token is consumed.

With validation passed, the full conversation is assembled: the system message, the grounded context, the user's original question, and the tool definitions for `search_identity_knowledge` and `list_foundry_deployments`. This whole structure is sent to the Foundry project client, which routes it to the model deployment configured as the chat model. The model processes the input, produces token-by-token reasoning, and returns a response.

![Screenshot of an Azure AI Foundry model invocation showing the deployed model, request payload, and response](images/ai-foundry-invocation.png)

The tool-calling loop begins its inspection. If the response contains a function call for `search_identity_knowledge` with a refined query, the app dispatches it through `run_tool_call`, which calls `search_documents` again with the new query. The additional evidence is merged into the accumulated result set and sent back to the model in a follow-up request that reuses the previous response ID for conversational continuity. In practice, most questions resolve after zero or one tool calls. The loop caps at three iterations as a safety boundary, not a normal exit path.

When the model produces a text response with no function calls, the loop exits. The final answer and all accumulated evidence move to `mask_answer`, which replaces any known sensitive strings with redacted placeholders. The formatted answer, complete with citations tied to the deterministic document IDs, is printed to stdout.

![Screenshot of the copilot's terminal output showing the grounded answer with citations](images/copilot-output.png)

The same lifecycle plays out in reverse for summary requests, except the routing layer skips retrieval entirely and sends the prompt directly to the summary deployment. No search, no tools, no evidence accumulation. Just a direct, cost-efficient model call.

Every file in the project has a role in this flow. `src/config.py` provides the typed configuration object that every function reads. `src/app.py` owns the CLI boundary. `src/rag/chat.py` holds the orchestration logic for routing, answering, and summarizing. `src/search/service.py` creates search clients. `src/search/build_index.py` and `src/search/load_documents.py` handle the one-time ingestion path. `src/content/markdown_loader.py` turns file trees into search documents. `src/foundry/project_client.py` wraps the Foundry SDK connection and deployment enumeration. And `src/security/masking.py` owns the final output scrub.

The PowerShell scripts mirror these layers at the infrastructure level. `Deploy-Infrastructure.ps1` provisions everything from the Bicep template. `Export-AppEnvironment.ps1` reads deployment outputs and emits environment variable blocks. `Invoke-MarkdownIngestion.ps1` runs the content bootstrapping pipeline. And `Test-Chat.ps1` ties it all together by calling `app.py` against the live deployment, confirming the entire loop works from end to end.

A single test at `tests/test_markdown_loader.py` validates the content parsing and document ID stability offline. Everything else requires live Azure infrastructure, which is by design—the copilot's value proposition is grounded in real services, not local mocks.

## From Demo to Platform

When you put these pieces together, the project stops looking like a simple RAG demo and starts feeling like a production-ready foundation. The configuration is centralized and typed. The knowledge ingestion is idempotent and deterministic. The model selection is automatic and cost-aware. The tool calling is bounded and read-only. The infrastructure deployment is automated and keyless. The output is masked and cited.

None of these properties emerged by accident. They came from a specific set of architectural decisions encoded in a few hundred lines of Python and a Bicep template. The grounded context block is explicitly formatted with document IDs so citations can be appended deterministically rather than left to the model's whim. The preflight deployment check catches configuration errors before any model tokens are spent. The three-iteration tool limit prevents infinite loops without hardcoding a timeout. The stable document IDs make re-indexing safe enough to run in CI.

A copilot's value does not come from raw model capability alone. It comes from the discipline of the boundary you build around it. That boundary is what makes the difference between a demo that impresses for five minutes and a tool that engineers reach for every day. This project draws that boundary in code, infrastructure, and documentation, and it makes every part of that boundary visible, testable, and explainable.

Stay tuned for future phases that will transform this reference implementation into a multi-agent platform. Our next steps include introducing a coordinator agent that routes policy questions, governance evidence requests, and workload identity questions to specialized agents using explicit handoff payloads. We'll expose retrieval capabilities through MCP servers to replace tightly coupled helper code with governed services. And we'll compare synchronous tool calls versus delegated agent workflows for evidence collection and remediation planning. These advancements will extend our architecture rather than replace it - because we built the foundation to scale with agent-based patterns from day one. 🚀

## References

- [Azure AI Foundry documentation](https://learn.microsoft.com/en-us/azure/ai-foundry/)
- [Azure AI Search documentation](https://learn.microsoft.com/en-us/azure/search/)
- [Azure AI Search Python SDK](https://learn.microsoft.com/en-us/python/api/azure-search-documents/)
- [Azure AI Foundry Python SDK](https://learn.microsoft.com/en-us/python/api/azure-ai-projects/azure.ai.projects/)
- [Azure Identity library](https://learn.microsoft.com/en-us/python/api/azure-identity/)
