# Microsoft Graph permissions (suggested)

This project uses **application permissions** (client credentials) from an Entra ID App Registration.

> Important: The exact permission set depends on which Graph endpoints you use and which governance features are enabled in your tenant. Start with the smallest set that works for your chosen APIs, then tighten further.

## Baseline (often required)

- `Directory.Read.All` — read directory objects for correlation (users, groups, service principals)

## Access reviews status

Common choices:
- `AccessReview.Read.All` (read review definitions/instances/decisions)

If you also want to write back / programmatically update reviews (not required for this pattern):
- `AccessReview.ReadWrite.All`

## Privileged drift / orphaned privileged assignments

Common choices:
- `RoleManagement.Read.Directory` — read directory role definitions and assignments

If you use audit log queries to detect changes:
- `AuditLog.Read.All`

## Notes

- Some privileged access / PIM scenarios may require additional permissions depending on whether you read **eligible schedules** vs **active assignments**.
- Always prefer **read-only** permissions for a monitoring-and-ticketing automation.
- Ensure admin consent is granted for application permissions.
