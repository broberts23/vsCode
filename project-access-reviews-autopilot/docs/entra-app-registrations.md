# Entra app registration notes (manual for the lab)

## API (resource)

Operators call the simulate API with a bearer token. There is no product SPA and no pending-queue UI. Slack is the Inbox; Entra OIDC protects Operator inject only.

- Expose an API: Application ID URI `api://{api-app-id}` (use the API app's Application (client) ID — bare strings like `api://access-reviews-autopilot` are rejected by the default tenant identifier-URI policy)
- Scope: `access_as_user` (Admins and users)
- Authorized client applications: add whichever public/native client you use to obtain tokens for demos (Azure CLI, a small test client, etc.)
- Optional: app roles for who may call `/api/simulate`
- Align deploy/config: Bicep/`Deploy-Infrastructure.ps1` default `ENTRA_API_AUDIENCE` to `api://{api-app-id}`

## Identity notes

- **Lab Identity Map** resolves every Entra Reviewer to one configured Slack user id (`LAB_IDENTITY_MAP_SLACK_USER_ID`). It is a sandbox stub for delivery correlation, not authorization for Graph Apply.
- **SSO Identity** (Slack SSO'd to Entra so Decider ≡ Reviewer) is the production end-state. The Slack developer sandbox cannot do workspace SAML SSO.
- Do **not** grant application `AccessReview.ReadWrite.All` for Apply. Graph Decision Item PATCH is delegated and Reviewer-only (see ADR 0003).

## What not to do

- Do not use Easy Auth as the primary SSO drill for this blog
- Do not grant Graph `AccessReview.ReadWrite.All` on managed identity for Apply — reviews are simulated in the lab
- Do not treat Lab Identity Map as production identity
