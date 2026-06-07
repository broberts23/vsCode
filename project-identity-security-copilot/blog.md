# Building an Expanded Identity Security Copilot with Azure AI Foundry

If you hang around identity security teams for a day, you quickly notice that their questions never fit into a single neat box.

In the morning, someone might need a deep, grounded answer about which Conditional Access policies are safeguarding break-glass accounts. In the afternoon, a manager might ask for a clean executive summary on our workload identity baselines. And later that week, an analyst might run a query where the initial search results are too sparse, meaning the assistant actually needs to ask some follow-up questions—or run a narrower lookup—before offering advice with any confidence.

This is where standard AI sample templates often fall short. They do a great job of showing how to call an LLM with a single prompt or spin up a basic RAG setup, but they often leave out what it takes to build a cohesive, reliable application boundary. If we want a copilot that engineers can actually trust, we need more than a simple RAG loop and a folder full of markdown files. We need a system that understands different tasks, queries bounded knowledge sources, and integrates deployment configuration in a logical, automated way.

That is exactly what we have set out to build in this project. It is a full reference implementation of an Identity Security Copilot that runs on Azure AI Foundry. It handles grounded Q&A, adapts tasks to the right model deployments, and leverages selective, read-only tools to make smarter lookups, all anchored to verified engineering practices.

The application is structured around three core architectural patterns: grounded retrieval, task-based model routing, and tool integration. Together, these patterns ensure the copilot can handle the diverse range of questions identity teams face while maintaining strict security boundaries.

## Setting Up the Foundry Control Plane

Instead of treating model endpoints as isolated resources, we want to treat Azure AI Foundry as our primary control plane.

The Python application resolves this by wrapping model and project-level interactions in `AIProjectClient`. This shifts our code away from the classic "endpoint and key shuffling" model to a structure where the project configuration itself dictates which models we can talk to and what capabilities are enabled.

Inside this project template, we tackle three distinct architectural concerns.

First, there is grounded chat. Copilots are only as good as the content they reason over. When a team member queries the app about Conditional Access or access reviews, we query an Azure AI Search index populated by our local, approved markdown documentation. This keeps the assistant focused strictly on our internal standards and prevents it from hallucinating generic advice.

Second, we are thinking about task-based model selection. The reality of any production workload is that reasoning is expensive. You don't want to burn your highest-end reasoning model on basic classification or structural summaries. Our setup separates a primary chat model deployment from a lightweight summary deployment. If the user's intent is clearly a simple recap, the request is automatically routed to a cheaper, faster model, preserving the heavier reasoning models for complex, multi-step tasks.

Third, we introduced tool calling. We have exposed a small, highly restricted set of read-only function definitions to the chat interface. If the model determines that the search results in the initial prompt are missing crucial context (or if it needs to inspect the current state of our deployments), it can dynamically trigger a local helper search to find more evidence. This stays perfectly secure: we aren't granting write access to Graph, Entra, or active remediation pipelines. We are simply demonstrating how tool integration should work: tightly bounded, audit-logged, and easy to monitor.

Retrieval remains markdown-first on purpose. The repo-hosted knowledge base is made up of internal identity-security documents, parsed into stable search documents and loaded into Azure AI Search. That keeps the lab highly teachable. You can understand the content flow from file system to search index to grounded prompt without needing to reverse-engineer a large ingestion platform.

## Moving Beyond Simple Infrastructure

The infrastructure story has to match the application's maturity.

Our Bicep template provisions the entire backing architecture—Azure AI Search, standard Storage, Key Vault, and App Configuration, plus Log Analytics and Application Insights for detailed tracing. Additionally, a user-assigned managed identity handles keyless authentication throughout.

But rather than leaving the developer to manually stitch the infrastructure outputs back to the Python configuration, the companion PowerShell scripts do the heavy lifting. The scripts read the active Bicep deployment, export the environment settings, and can optionally publish them straight into Azure App Configuration. This sets up a "one-click" pipeline that connects fresh infrastructure to a ready-to-run local or hosted app instance.

To complement this, we kept a strong focus on secure defaults. Since this is a security application, we enforce strict RBAC, default to keyless authentication, and run a final masking pass on the way out to ensure sensitive strings like administrator email addresses or specific credentials are automatically redacted before reaching the user.

## Shifting From a Demo to a Real Platform

When you put these pieces together, the project stops looking like a simple RAG demo and starts feeling like a production-ready blueprint.

We can now map every capability back to a clean, architectural decision:

- **Control plane integration:** The AI Foundry project manages our identity boundary and model access.
- **Task routing:** The app smoothly divides workloads between cheaper summary pathways and deeper reasoning models.
- **Dynamic grounding:** Read-only local tools let the model take routing or lookup actions inside the system state.
- **Automated setup:** PowerShell and Bicep handle the shift from infrastructure provisioning to application state publication.

This approach gives generative AI code the structure and security reviewability that identity engineering requires. We aren't pretending that the copilot has free rein to touch production directory systems. Instead, we are establishing a pattern where the AI retrieves documents carefully, formats citations cleanly, uses specific helper functions safely, and operates entirely within a secure infrastructure envelope.

From here, the next sensible progression is clear. You can transition our semantic search into a hybrid-vector pipeline, write specialized evaluations for grounding accuracy, or expose these specialized lookups as secured, modular tools via MCP endpoints or API endpoints. This setup ensures that when you choose to scale, you are starting from a clean, hardened foundation.

The value of a copilot does not come from raw model capability alone. It comes from the discipline of the boundary you build around it.
