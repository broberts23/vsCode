# Entra app registration notes (manual for the lab)

## SPA (public client, PKCE)

- Platform: Single-page application
- Redirect URIs:
  - `http://localhost:5500` (or your static file server)
  - `http://localhost:8080` if serving spa from the API later
  - `https://<api-fqdn>/` if hosting spa behind the same origin
- Front-channel logout URL: optional
- Implicit grant: **off** (use auth code + PKCE via MSAL.js)
- API permissions: delegated `api://{api-app-id}/access_as_user`

## API (resource)

- Expose an API: Application ID URI `api://{api-app-id}` (use the API app's Application (client) ID — bare strings like `api://access-reviews-autopilot` are rejected by the default tenant identifier-URI policy)
- Scope: `access_as_user` (Admins and users)
- Authorized client applications: add the SPA client ID
- Optional: app roles for who may call `/api/simulate`
- Align deploy/config: Bicep/`Deploy-Infrastructure.ps1` default `ENTRA_API_AUDIENCE` to `api://{api-app-id}`; SPA `apiScope` must match this URI

## What not to do

- Do not use Easy Auth as the primary SSO drill for this blog
- Do not grant Graph `AccessReview.ReadWrite.All` — reviews are simulated
- Slack workspace login SSO is SAML/paid — Slack here is an OAuth app only
