# scripts

Helper scripts will live here.

Typical scripts (planned):

- Create/configure Entra ID app registration for Microsoft Graph
- Grant/admin-consent required Graph permissions
- Create a minimal ServiceNow integration user (dev instance)
- Smoke test: call Graph, then create/update a ServiceNow record

Security note:

- Never commit secrets to the repo.
- Prefer Key Vault and managed identity for Azure deployments.
