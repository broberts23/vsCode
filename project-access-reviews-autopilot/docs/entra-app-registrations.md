# Entra app registration notes (manual for the lab)

## API (resource)

Operators call the simulate API with a bearer token. There is no product SPA.

- Expose an API: Application ID URI `api://{api-app-id}` (use the API app's Application (client) ID — bare strings like `api://access-reviews-autopilot` are rejected by the default tenant identifier-URI policy)
- Scope: `access_as_user` (Admins and users)
- Authorized client applications: add whichever public/native client you use to obtain tokens for demos (Azure CLI, a small test client, etc.)
- Optional: app roles for who may call `/api/simulate`
- Align deploy/config: Bicep/`Deploy-Infrastructure.ps1` default `ENTRA_API_AUDIENCE` to `api://{api-app-id}`

## What not to do

- Do not use Easy Auth as the primary SSO drill for this blog
- Do not grant Graph `AccessReview.ReadWrite.All` — reviews are simulated
- Slack workspace login SSO is SAML/paid — Slack here is an OAuth app only
