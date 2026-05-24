# Building a Grounded Identity Security Copilot with Azure AI Foundry

Identity security is a high-stakes environment. When platform administrators, access reviewers, or security engineers need to determine which Conditional Access controls apply to a privileged role, or what operational risks are associated with an unmanaged workload identity, they usually have to pause and dig through disparate documentation. Building an AI assistant to answer these questions seems like an obvious win.

However, doing so safely introduces an immediate challenge: you cannot simply connect a large language model to live Microsoft Graph data or raw directory telemetry without creating a massive, unpredictable security boundary.

Instead, we need an assistant that reasons strictly over an approved, read-only set of identity-security content. In this post, we are going to build a standalone Identity Security Copilot that does exactly that. We will use Azure AI Foundry to manage our model connections and Azure AI Search to ground our answers against a curated collection of internal markdown documentation.

It is also worth being clear about what this is not. Security Copilot in Microsoft Entra is a Microsoft-managed product experience with deep product integration, built-in workflows, and a user experience designed around operating Entra itself. This solution is different: it is a developer-built, code-first copilot pattern that you own end to end. That gives you flexibility to define the corpus, control the grounding data and behavior, shape the security boundary, and extend the application however you want, but it also means you are responsible for the application design, deployment, observability, and governance choices.

## Making the App Project-Aware

One of the first design choices in this solution is how we interact with our cloud AI resources. In the past, it was common to wire up individual endpoints for Azure OpenAI, storing raw keys and disparate connection strings.

Instead, our application uses the Azure AI Foundry SDK. By configuring the app around a single Foundry project endpoint, we can use the AIProjectClient as the central entry point for all our model and project-wide operations. This reflects how modern generative AI applications are built on Azure—treating the Foundry project as the control plane. From there, we can dynamically retrieve an OpenAI-compatible client to generate our chat responses without shuffling endpoints around in code.

## Grounding with a Local Knowledge Base

To keep our assistant focused on approved security patterns rather than hallucinating generic answers, we need a solid retrieval-augmented generation (RAG) foundation.

The repository includes a curated local knowledge base filled with markdown files covering topics like access review guidelines and workload identity baselines. Rather than relying on complicated real-time ingestion pipelines for this initial build, we use a custom Python markdown loader that reads these files, splits them into logical sections based on headings, and converts them into structured search documents. Those documents are then uploaded to Azure AI Search. When a user asks a question, the application queries that Search index first and builds a tightly scoped evidence block for the model.

## Selecting Models by Task

In a real-world scenario, you rarely use your most expensive reasoning model for every minor task. To reflect this, the copilot distinguishes between a primary chat deployment and a secondary summary deployment.

Right now, you might decide to point both configuration values to the same GPT-4o-mini deployment to keep the lab simple. Programmatically defining task-specific model deployments builds in the flexibility to swap in a smaller, cheaper and faster summarization or classification model down the road.

## Defensible Security Defaults

Because this is an identity security copilot, the architecture itself needs to reflect good security hygiene.

First, there are no API keys checked in or loaded into the app. We rely entirely on DefaultAzureCredential to authenticate to both Azure AI Foundry and Azure AI Search. This means the application can seamlessly use your logged-in developer identity during local testing and switch to a locked-down Azure Managed Identity when deployed to the cloud.

Second, we include a final masking pass on the way out. Before the model's text is ever returned to the user, the application scrubs the response to redact predictable sensitive patterns (like break-glass email addresses). This creates an explicit defense-in-depth layer, ensuring we do not rely entirely on the LLM's system prompt to keep our data safe.

## The Infrastructure Foundation

Everything supporting this application is defined in declarative Bicep templates. When deployed, it provisions Azure AI Search for our grounding layer, a Storage Account for staging artifacts, and operational resources like Azure Key Vault, App Configuration, and Log Analytics. By separating the Azure AI Foundry project creation from the supporting application infrastructure, we ensure our app can plug into an existing enterprise Foundry environment without stepping on toes or attempting to over-provision.

## Conclusion

By combining a secure, local-first markdown retrieval pipeline with Azure AI Foundry, we have created a baseline Identity Security Copilot that genuinely helps engineers without exposing the tenant to unnecessary risk.

This architecture gives us a fantastic starting point. The natural next steps will be to evolve our semantic search into a hybrid vector retrieval model, introduce read-only tool calling so the copilot can independently look up access review telemetry, and implement formal tracing and evaluations to quantitatively prove the assistant's accuracy over time.
