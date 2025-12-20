# src

This folder is intended for the Azure Functions implementation.

Minimum planned functions:

- `GovernanceSignalPoller` (Timer Trigger)
  - Reads privileged drift, orphaned privileged assignments, and access review status via Microsoft Graph
  - Upserts ServiceNow records using correlation fields

Optional functions:

- `RunNow` (HTTP Trigger)
  - Protected by Entra ID OAuth (App Service Authentication)
  - Manually kicks a poll run for troubleshooting

Configuration is expected to be provided via Function App settings (Key Vault-backed where possible).
