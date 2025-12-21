# infra

This folder contains infrastructure-as-code (Bicep) for the Event Grid partner integration.

What’s in scope for this scaffold:
- Create/maintain an **Event Grid partner configuration**
- (Optional) Create an **event subscription** on an existing partner topic to route Entra events to an Azure Function

Notes:
- Partner topics are typically created/appear as part of the partner publishing flow and may require an activation/approval step.
- The Bicep in this folder is intentionally minimal and parameterized to avoid baking environment-specific assumptions.
