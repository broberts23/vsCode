# Building an Expanded Identity Security Copilot with Azure AI Foundry

## Problem statement

Identity security teams rarely ask one kind of question.

Sometimes they need a grounded answer about which Conditional Access policies matter for privileged administrators. Sometimes they need a concise summary for a leadership briefing. Sometimes the first retrieval pass is not enough, and the assistant needs a narrow, read-only lookup before it can answer with any confidence.

That is the real problem with many AI sample apps: they prove that a model can answer one prompt, but they do not show how to shape an actual application boundary. If we want a serious identity security copilot, we need more than one completion call and a folder full of markdown files. We need a project-aware application that understands task differences, respects a bounded knowledge source, and carries its deployment configuration in a disciplined way.

That is the shape of this project. We are building an Identity Security Copilot in Azure AI Foundry that can answer grounded questions, summarize identity-security topics, and selectively use read-only tools, all while staying anchored to approved documentation and predictable infrastructure.

## Solution

The first design choice is to treat Azure AI Foundry as the control plane, not just as a model endpoint registry.

The Python app is configured around a Foundry project endpoint and uses `AIProjectClient` as the entry point for deployment-aware operations. That matters because the lab is no longer framed as "call one model and hope for the best." Instead, the project now reflects three distinct application concerns.

The first concern is grounded chat. When a user asks a question about access reviews, workload identities, or Conditional Access, the app queries Azure AI Search over a curated markdown corpus and builds an evidence block for the model. This keeps the copilot anchored to approved identity-security content rather than generic internet-shaped reasoning.

The second concern is task-based model selection. The repo still supports a primary chat deployment and a secondary summary deployment, but that distinction is now part of the application flow rather than a passing configuration detail. Requests that are clearly asking for an overview or executive summary can be routed to the summary deployment, while grounded question answering stays on the retrieval-first chat path. That is a small pattern, but it maps directly to how production AI apps control cost, latency, and reasoning depth.

The third concern is tool use. The chat workflow now exposes a tiny, read-only function surface to the model. If the first evidence block is not enough, the model can request another knowledge search or inspect the Foundry deployment list before answering. This is intentionally narrow. We are not giving the assistant direct write access to Graph, Entra, or any remediation workflow. We are simply showing how tool use fits into a secure copilot pattern: bounded, inspectable, and easy to reason about.

Retrieval remains markdown-first on purpose. The repo-hosted knowledge base is made up of internal identity-security documents, parsed into stable search documents and loaded into Azure AI Search. That keeps the lab highly teachable. You can understand the content flow from file system to search index to grounded prompt without needing to reverse-engineer a large ingestion platform.

The infrastructure story also needed to expand.

The Bicep template already provisions the supporting application foundation: Azure AI Search, Storage, Key Vault, App Configuration, Log Analytics, Application Insights, and a user-assigned managed identity. What changes in this version of the project is that the deployment story no longer ends at resource creation. The PowerShell scripts now export the operational values the app actually depends on and can publish those settings into Azure App Configuration. That gives the lab a more realistic "problem to platform" flow. The Foundry project endpoint and deployment names remain explicit inputs, but they are now carried forward as first-class configuration rather than tribal knowledge in a terminal window.

Security defaults stay deliberately conservative throughout the design.

The app uses `DefaultAzureCredential` instead of checked-in secrets. Search and Foundry both stay behind RBAC. Tool use is read-only. A masking pass still runs at the end of the response path so we do not depend entirely on prompt wording to avoid obvious sensitive strings. In an identity security project, those choices are not polish. They are part of the architecture.

## Resolution

With those changes, the project stops looking like a baseline RAG sample and starts behaving more like a small Azure AI application.

You can now explain the solution in a cleaner end-to-end story:

- The Foundry project acts as the application control plane.
- The app distinguishes between chat and summary tasks.
- Retrieval supplies grounded evidence from approved markdown content.
- Read-only tools let the model ask for one more lookup when it needs it.
- Deployment scripts carry infra outputs and application settings into a usable runtime shape.

That matters for exam preparation, but it also matters for engineering credibility. When someone asks how model selection works, there is a concrete answer. When someone asks where the knowledge comes from, there is a concrete answer. When someone asks how the app would move from local execution to hosted configuration, there is a concrete answer.

Just as important, the project still avoids pretending to be more autonomous than it really is. There is no hidden write path. There is no fake governance story. There is no giant abstraction layer obscuring a simple retrieval-plus-generation application. The implementation stays narrow enough to learn from while still reflecting the broader scope of a real Azure AI Foundry solution.

## Conclusion

The expanded Identity Security Copilot is a better fit for the original project goal because it reflects how AI applications are actually assembled on Azure: around a Foundry project, with multiple task paths, governed knowledge retrieval, bounded tool use, and configuration that survives beyond one interactive shell session.

From here, the next sensible evolutions are clear. We could add hybrid or vector retrieval, introduce evaluation workflows for groundedness and answer quality, or split the read-only tool surface into separate specialist agents or MCP-backed endpoints. Those would be natural follow-ons.

For now, this version of the project demonstrates the right core lesson: in identity security, the value of a copilot does not come from raw model capability alone. It comes from the discipline of the boundary you build around it.
