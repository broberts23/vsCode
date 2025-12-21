# src

This folder contains the Azure Functions implementation.

## Current scaffold

- PowerShell-based Function App skeleton under `src/FunctionApp/`
- Minimal Event Grid-triggered handler: `GovernanceEventHandler`
- Policy + allowlist stub stored as JSON under `src/FunctionApp/policy/policy.json`

## Design goals

- Idempotent event processing
- Explicit allowlists / break-glass exclusions
- Safe-by-default remediation (switchable per rule)
- Minimal dependencies (Graph calls can be implemented via raw REST + OAuth tokens)
