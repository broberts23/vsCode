# Building an Identity Security Copilot v2: From Single-Process RAG to Coordinator + Specialists + MCP

> This is a placeholder for the v2 narrative walk-through. It will be filled in once the implementation phases in [`OUTLINE.md`](./OUTLINE.md) are complete. The structure below mirrors the v1 `blog.md` so the v2 post can be reviewed section by section.

## Why v2 exists

v1 answered identity-security questions with a single Python process: load config, query the search index, call a Foundry model, mask the answer, print the result. It hit every AI-103 criterion in `scratch.md` for topic 1 ("Build an Identity Security Copilot in Azure AI Foundry"), and it did so on purpose without becoming a multi-agent platform. The v1 closing paragraph even teed up the next phase:

> Stay tuned for future phases that will transform this reference implementation into a multi-agent platform. Our next steps include introducing a coordinator agent that routes policy questions, governance evidence requests, and workload identity questions to specialized agents using explicit handoff payloads. We'll expose retrieval capabilities through MCP servers to replace tightly coupled helper code with governed services. And we'll compare synchronous tool calls versus delegated agent workflows for evidence collection and remediation planning.

v2 is that next phase.

## The two Azure services powering the copilot (v2 view)

## From environment variables to a typed contract (v2 view)

## How markdown becomes grounded evidence (v2 view)

## Routing requests by intent, not by accident (v2 view)

## The grounded Q&A pipeline (v2 view)

## The MCP boundary (v2 NEW)

## The A2A handoff envelope (v2 NEW)

## The sync vs delegated comparison harness (v2 NEW)

## The security boundary that runs through everything (v2 view)

## Putting it all together: the full request lifecycle (v2 view)

## From demo to platform (v2)

## References

- [OUTLINE.md](./OUTLINE.md) — the v2 design contract.
- [Azure AI Foundry documentation](https://learn.microsoft.com/en-us/azure/ai-foundry/)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- [Azure AI Search documentation](https://learn.microsoft.com/en-us/azure/search/)
- [Azure AI Search Python SDK](https://learn.python.org/api/azure-search-documents/)
