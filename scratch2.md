# AI-103 and AI-200 Study Plan via Identity Security Blog Projects

Use this list as a code-first study backlog. Every topic is centered on identity security, favors Python and Azure SDK usage, and maps back to the official study guides for AI-103 and AI-200.

## Working approach

- Build each topic as a small repo or subfolder with runnable Python samples.
- Default to managed identity, RBAC, private endpoints, Key Vault, and App Configuration unless a topic intentionally compares alternatives.
- For Python, prioritize hands-on use of Azure SDKs such as `azure-identity`, `azure-keyvault-secrets`, `azure-appconfiguration`, `azure-cosmos`, `azure-servicebus`, `azure-eventgrid`, and the relevant Azure AI SDKs.
- For each post, include: architecture, Python code, security model, operational concerns, and a short "exam criteria covered" section.

## AI-103: Developing AI Apps and Agents on Azure

### 1. Build an Identity Security Copilot in Azure AI Foundry

Scenario: Create a Python assistant that answers questions about Conditional Access, access reviews, workload identities, and privileged access patterns.

What to build:

- A Foundry project with model selection for chat, summarization, and tool use.
- A retrieval layer over security documentation and internal markdown content.
- A deployment pipeline that provisions the project, model deployments, and app configuration.

Exam criteria covered:

- Choose appropriate models, Foundry services, retrieval methods, and memory/tool/knowledge integration services.
- Set up Foundry projects, deployments, and CI/CD integration.
- Design Azure infrastructure for AI apps and agent-based solutions.

### 2. Secure and Govern a Privileged Access Agent

Scenario: Build an agent that can recommend PIM activation steps and access review actions, but only within strict approval and audit boundaries.

What to build:

- Tool access controls for read-only versus remediation actions.
- Approval workflows for high-risk tasks.
- Trace logging, provenance metadata, and evaluation records.

Exam criteria covered:

- Manage, monitor, and secure AI systems with managed identity, private networking, keyless credentials, and role policies.
- Implement responsible AI with safety filters, guardrails, auditing, oversight modes, constraints, and tool-access controls.
- Monitor safety events, grounding quality, and operational behavior.

### 3. Build a RAG App for Entra ID and Identity Governance Knowledge

Scenario: Create a Python RAG application that answers questions from Entra documentation, access review evidence, and your blog content.

What to build:

- Document ingestion and chunking pipeline.
- Semantic, hybrid, and vector retrieval options.
- Prompt flows that cite grounded sources and reject unsupported answers.

Exam criteria covered:

- Build generative applications by using Foundry.
- Implement RAG in an application.
- Integrate generative workflows into applications by using Foundry SDKs and connectors.
- Evaluate relevance, quality, safety, and fabrication risk.

### 4. Build an Identity Triage Agent with Function Calling and Memory

Scenario: Build a Python agent that triages risky sign-in events and can call internal tools for enrichment, ticket creation, and evidence lookup.

What to build:

- Agent roles, goals, memory, and conversation state handling.
- Function calling against Graph-backed or internal APIs.
- Retrieval plus custom tools for policy lookup and remediation suggestions.

Exam criteria covered:

- Define agent roles, goals, conversation-tracking approach, and tool schemas.
- Build agents that integrate retrieval, function-calling, and conversation memory.
- Integrate APIs, knowledge stores, search, content understanding, and custom functions.

### 5. Orchestrate Multi-Agent Identity Investigations

Scenario: Split incident handling into specialist agents such as policy analyst, sign-in investigator, and remediation planner.

What to build:

- A coordinator agent that delegates tasks.
- Safeguards for semiautonomous flows.
- Monitoring and evaluation for agent handoffs.

Exam criteria covered:

- Implement orchestrated multi-agent solutions.
- Build autonomous or semiautonomous workflows with safeguards and approval flow controls.
- Integrate monitoring into deployed agents, evaluate behavior, and perform error analysis.

### 6. Tune and Operationalize a Security Copilot for Production

Scenario: Take one of the earlier agents and harden it for production behavior, cost, and observability.

What to build:

- Prompt and parameter tuning notebooks or scripts.
- Reflection and self-critique evaluation loops.
- Tracing, token analytics, safety signals, and latency metrics.

Exam criteria covered:

- Tune generation behavior with prompt engineering and model parameters.
- Implement reflection, chain-of-thought evaluation patterns, and self-critique loops.
- Set up observability and orchestrate hybrid LLM plus rules-engine flows.
- Manage quotas, scaling, rate limits, and cost footprints.

### 7. Generate Identity Security Training Media with Image and Video Models

Scenario: Produce training visuals for phishing-resistant MFA rollout, risky consent prompts, and secure admin workflows.

What to build:

- Text-to-image and text-to-video examples.
- Inpainting and prompt-driven edits to sanitize screenshots or mockups.
- Guardrails around brand usage and sensitive content.

Exam criteria covered:

- Design and implement image-generation and video-generation solutions.
- Configure image-editing and generated-video editing workflows.
- Select and apply generation and editing controls.

### 8. Build a Multimodal Analyst for Admin Portal Screenshots and Incident Clips

Scenario: Analyze screenshots of Entra portals, access review screens, and short admin walkthrough videos.

What to build:

- Visual captioning and detailed description workflows.
- Question answering grounded in visual evidence.
- Accessibility-focused alt-text generation.

Exam criteria covered:

- Analyze visual context with multimodal models.
- Produce concise and detailed captions.
- Enable question answering grounded in visual evidence.
- Generate alt-text and extended descriptions aligned to accessibility guidance.
- Use Content Understanding and video analysis workflows.
- Identify objects, components, or regions within images or video.

### 9. Defend Against Visual Prompt Injection in Identity Workflows

Scenario: Detect malicious or misleading text embedded inside screenshots, QR codes, diagrams, or uploaded evidence.

What to build:

- Visual safety classification.
- Embedded-text prompt injection detection.
- Watermarking and policy checks for generated media.

Exam criteria covered:

- Implement responsible AI for multimodal content.
- Classify unsafe or disallowed visual content.
- Detect and mitigate indirect prompt injection through embedded text.
- Enforce visual policy rules such as watermarks, prohibited symbols, and brand requirements.

### 10. Build a Text Analysis Pipeline for Identity Governance Evidence

Scenario: Process access review notes, admin justifications, incident summaries, and governance tickets.

What to build:

- Entity extraction for users, groups, apps, and roles.
- Summaries and structured JSON outputs.
- Tone, sentiment, sensitive-content, and risk labeling.

Exam criteria covered:

- Extract entities, topics, summaries, and structured JSON outputs.
- Detect sentiment, tone, safety issues, and sensitive content.
- Customize outputs for domain tasks such as compliance summarization and domain extraction.

### 11. Add Translation and Speech to a Helpdesk Identity Agent

Scenario: Build a multilingual helpdesk assistant for identity troubleshooting and access requests.

What to build:

- Speech-to-text and text-to-speech interactions.
- Speech translation and multilingual responses.
- Audio input handling for spoken incident details.

Exam criteria covered:

- Build translation flows for text.
- Implement speech-to-text and text-to-speech workflows.
- Integrate speech as an agent modality, including custom speech models.
- Enable multimodal reasoning from audio inputs.
- Translate speech into other languages.

### 12. Build a Retrieval Pipeline for Identity Documents, Audio, Images, and Video

Scenario: Ingest policy PDFs, architecture diagrams, training videos, screen captures, and recorded review meetings into one grounded retrieval system.

What to build:

- Unified ingestion and indexing for multimodal content.
- OCR and enrichment during ingestion.
- Direct integration from retrieval to agent tools.

Exam criteria covered:

- Build retrieval and grounding pipelines.
- Ingest and index documents, images, audio, and video.
- Configure semantic, hybrid, and vector search.
- Implement enrichment with built-in or custom skills for text, images, and layout.
- Configure RAG ingestion with OCR.
- Connect retrieval pipelines directly to workflows and agent tools.

### 13. Extract Access Review Packets with Content Understanding

Scenario: Parse entitlement review exports, approval forms, and auditor evidence packets into grounded structured outputs.

What to build:

- OCR plus layout analysis plus field extraction.
- Structured JSON and markdown outputs for downstream agents.
- Clean representations for RAG over audit material.

Exam criteria covered:

- Extract content from documents.
- Combine OCR, layout analysis, and field extraction.
- Produce grounded representations for agents and RAG by using Content Understanding.
- Generate structured or markdown outputs for downstream reasoning.

## AI-200: Developing AI Cloud Solutions on Azure

### 14. Containerize a Python Identity Risk API with Azure Container Registry and App Service

Scenario: Package a Python API that scores sign-in or app-consent risk and expose it as a secure backend service.

What to build:

- Dockerfile and image build pipeline.
- Azure Container Registry with tagging and versioning.
- App Service deployment with environment variables and secrets.

Exam criteria covered:

- Build, store, version, and manage container images in Azure Container Registry.
- Build and run images by using Azure Container Registry Tasks.
- Deploy containers to Azure App Service and configure environment variables and secrets.

### 15. Run Event-Driven Identity Processing on Container Apps and AKS

Scenario: Process access review events, sign-in alerts, or role assignment changes through scalable container workloads.

What to build:

- Container Apps revisions and environment configuration.
- KEDA-based scaling from queue depth or event volume.
- AKS deployment manifests plus basic diagnostics.

Exam criteria covered:

- Deploy applications to Azure Container Apps with environment configuration and revision management.
- Implement event-driven scaling with KEDA.
- Deploy and manage applications to AKS by using manifest files.
- Monitor and troubleshoot AKS and Container Apps with logs, events, and connectivity checks.

### 16. Build a Cosmos DB Vector Store for Identity Security Retrieval

Scenario: Store role definitions, policy statements, and governance evidence in Azure Cosmos DB for NoSQL and query them from Python.

What to build:

- SDK-based reads, writes, and queries.
- Embedding storage and vector similarity search.
- A change feed processor that reacts to new governance records.

Exam criteria covered:

- Connect to Azure Cosmos DB for NoSQL by using the SDK and run queries.
- Optimize query performance and RU consumption with indexing policies and consistency levels.
- Store and retrieve embeddings and execute vector similarity search.
- Implement a change feed processor.

### 17. Build a PostgreSQL pgvector Store for Privileged Access Workflows

Scenario: Use Azure Database for PostgreSQL as the retrieval and metadata store for privileged access reasoning.

What to build:

- Schema design for identity entities, approvals, and evidence.
- pgvector indexing and metadata filters.
- Connection pooling and throughput optimization.

Exam criteria covered:

- Connect and query Azure Database for PostgreSQL by using SDKs.
- Model schemas, choose data types, and implement indexing strategies.
- Optimize latency and reduce pgvector compute overhead.
- Configure compute, memory, and storage for vector workloads.
- Run vector similarity search and RAG patterns with metadata filters.
- Implement connection optimization to improve throughput and minimize latency.

### 18. Cache Identity Authorization Context with Azure Managed Redis

Scenario: Cache expensive lookups such as app-to-role mappings, access-review state, and vectorized policy snippets.

What to build:

- Python caching layer with expiration and invalidation.
- Hot-path retrieval for policy guidance.
- Vector indexing for low-latency similarity lookups.

Exam criteria covered:

- Implement Azure Managed Redis data operations including caching, expiration, and invalidation.
- Implement vector indexing to enable similarity search.

### 19. Build a Service Bus and Event Grid Backbone for Identity Automation

Scenario: Connect identity lifecycle events to asynchronous AI processing and remediation workflows.

What to build:

- Service Bus queues, topics, subscriptions, and DLQ handling.
- Event Grid custom events and subscription filters.
- Retry behavior and failure handling patterns.

Exam criteria covered:

- Queue and process backend operations by using Azure Service Bus, including DLQ handling, messages, topics, and subscriptions.
- Implement event-driven workflows by using Azure Event Grid, including filters, custom events, and retries.

### 20. Build Serverless Python APIs for Identity Governance Workflows

Scenario: Create Azure Functions that expose secure endpoints for retrieval, summarization, evidence extraction, and remediation requests.

What to build:

- HTTP, timer, and queue-triggered functions.
- Input and output bindings.
- Deployment automation for function apps.

Exam criteria covered:

- Build serverless APIs, including implementing triggers and bindings.
- Configure and deploy function apps.

### 21. Build a Secretless and Observable AI Backend for Identity Security

Scenario: Harden the earlier projects with managed identity, Key Vault, App Configuration, distributed tracing, and KQL-based troubleshooting.

What to build:

- Secret retrieval and rotation through Key Vault.
- Centralized non-secret configuration with App Configuration.
- OpenTelemetry traces and KQL investigations.

Exam criteria covered:

- Secure secrets by using Azure Key Vault, including rotation and retrieval.
- Store and retrieve app configuration information by using Azure App Configuration.
- Trace distributed systems by using OpenTelemetry SDKs.
- Write KQL queries to analyze logs and metrics.

## Coverage summary

If you want the most efficient sequence, do the topics in this order:

1. Topic 1 to establish Foundry, model selection, and retrieval design.
2. Topic 3 to get direct RAG practice.
3. Topic 4 and Topic 5 for agent implementation and operational maturity.
4. Topic 14, Topic 16, Topic 19, and Topic 21 for the most developer-heavy AI-200 coverage.
5. Topic 12 and Topic 13 to cover information extraction and multimodal grounding.
6. Topic 8, Topic 9, Topic 10, and Topic 11 to close computer vision, text, and speech gaps.

## Suggested post template

For every blog post, keep the same structure so the study effort compounds:

1. Problem statement in an identity security scenario.
2. Azure architecture and threat model.
3. Python SDK implementation walkthrough.
4. Authentication and authorization model.
5. Observability, cost, and failure modes.
6. "Exam criteria covered" checklist copied from the study guide.
7. Extension ideas for a follow-up post.
