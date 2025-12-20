# Building a Secure Password Reset API with Azure Functions, Easy Auth, and LDAPS

## Introduction

In my previous infrastructure blog, we built a disposable Active Directory lab: a domain controller in its own subnet, a function app in another, Key Vault for secrets, and just enough networking glue to make it feel like a real hybrid environment.

This post is the other half of the story: the **PowerShell 7.4 Azure Function** that accepts authenticated requests, authorizes them with role claims, and resets passwords in on-prem AD over **LDAPS**.

The goal is intentionally boring: one HTTP POST, a strong password comes back, and the AD change happens safely and repeatably.

## Architecture at a Glance

Here’s the moving parts that matter for the function app itself:

```mermaid
flowchart TB
      subgraph Azure["Azure Resource Group"]
            FA["Function App (Windows)
PowerShell 7.4"]
            KV["Key Vault
Secrets"]
            LA["App Insights / Log Analytics"]
      end

      subgraph VNet["VNet"]
            DC["Domain Controller
LDAPS :636"]
      end

      Caller["Calling App
(Entra client credentials)"] -->|Bearer token| FA
      FA -->|Managed Identity| KV
      FA -->|LDAPS (pinned cert + hostname validation)| DC
      FA --> LA
```

Two design choices shape almost everything:

1. **Authentication is delegated to the platform** (App Service Authentication aka “Easy Auth”).
2. **Directory operations are done via LDAPS** using .NET LDAP APIs, with strict TLS validation.

## Prerequisites

To follow along end-to-end you’ll need:

- An Entra ID app registration for the API, with role assignments for callers.
- App Service Authentication enabled for the Function App (configured in IaC).
- A domain controller reachable from the Function App via VNet integration.
- Two Key Vault secrets: - `ENTRA-PWDRESET-RW` (JSON containing username/password)
  - `LDAPS-Certificate-CER` (the domain controller’s public cert, base64)

## The Request Walkthrough

Let’s walk the request the same way the runtime sees it.

### Step 1: The request arrives (but your code doesn’t validate the JWT)

The caller sends `Authorization: Bearer ...`.

Before PowerShell starts, **Easy Auth** validates the token:

- Signature + issuer via OIDC metadata (`.../{tenantId}/v2.0`).
- `exp` / `nbf` timing.
- Audience (`aud`). In this project the allowed audiences include both:
  - the plain client id, and
  - `api://{clientId}`

If validation fails, Easy Auth returns **401** and the function never runs.

### Step 2: Easy Auth injects the principal

On success, Easy Auth injects `X-MS-CLIENT-PRINCIPAL` (base64 JSON). The function decodes it with:

```powershell
$principal = Get-ClientPrincipal -HeaderValue $Request.Headers['X-MS-CLIENT-PRINCIPAL']
```

That gives us a consistent claim set without having to do token cryptography in PowerShell.

### Step 3: Authorization is a role claim check

The function enforces a single rule: the caller must have the required role (from `REQUIRED_ROLE`).

```powershell
$hasRole = Test-RoleClaim -Principal $principal -RequiredRole $env:REQUIRED_ROLE
```

No role claim → **403**.

### Step 4: Parse the body and choose the target user

The request body is intentionally small:

```json
{ "samAccountName": "jdoe" }
```

If `samAccountName` is missing → **400**.

### Step 5: Fetch secrets with Managed Identity

At this point we have an authorized request, but we still need two things:

- **AD service account credential** (from Key Vault)
- **LDAPS certificate pinning material** (from Key Vault)

The function app uses its **system-assigned managed identity** to call Key Vault. Secrets are cached per runspace inside the helper module, so normal traffic doesn’t hammer Key Vault.

If the LDAPS certificate secret is missing or empty, the function fails fast with **500** (that’s a misconfiguration we don’t want to “best-effort” our way through).

## The LDAPS Story (Strict, No Hostname Bypass)

Resetting passwords over LDAP is the part that tends to get hand-waved with “just trust the cert.” This project goes the other direction.

The function resets passwords over **LDAPS** using `System.DirectoryServices.Protocols.LdapConnection`, and validates the server certificate in two ways:

1. **Certificate pinning**: the presented server cert thumbprint must match the pinned cert retrieved from Key Vault.
2. **Hostname validation**: the cert must match the domain controller hostname (SAN/CN checks).

This keeps TLS strict without requiring the Function App sandbox to write to any certificate store. (On Windows-hosted Functions, opening cert stores for write is commonly blocked.)

Before attempting the TLS handshake, the code also performs a quick TCP preflight to port 636. That makes “network unreachable” failures look different from “TLS validation failed” failures, which is invaluable when debugging.

## Generating and Returning the Password

The function generates a password with `New-SecurePassword` (length default 16, with required character classes), converts it to `SecureString` for the directory operation, and returns the plain text password in the response body.

The important operational rule is: **no password is written to logs**. The only place the generated password exists is in memory during that request and in the HTTPS response to an authorized caller.

## Hosting and Scaling Notes

This function app runs on **Elastic Premium (EP1) on Windows**, because VNet integration is a core requirement for reaching the domain controller.

Concurrency is tuned with:

- `FUNCTIONS_WORKER_PROCESS_COUNT=2`
- `PSWorkerInProcConcurrencyUpperBound=10`

Those settings let a single app instance handle multiple requests in parallel while keeping directory operations responsive.

## Where the Logic Lives

The entrypoint is intentionally small: it validates the request shape, checks role claims, and orchestrates calls into a helper module.

The heavy lifting lives in `PasswordResetHelpers`:

- `Get-ClientPrincipal` and `Test-RoleClaim` (authorization)
- `Get-FunctionAdServiceCredential` (Key Vault + MI)
- `Get-FunctionLdapsCertificateBase64` (pinned cert from Key Vault)
- `Set-ADUserPassword` (LDAPS user lookup + unicodePwd modify)

Keeping the LDAPS plumbing in one place made it much easier to iterate on TLS validation without turning `run.ps1` into a wall of LDAP code.

## How the Pieces Fit Together in the Repo

The function app is intentionally small: one HTTP-triggered endpoint, one helper module, and a profile script for worker initialization.

Here’s the layout under `project-functionapp-roles/FunctionApp`:

```text
FunctionApp/
      host.json
      local.settings.json               # local-only settings (not deployed)
      profile.ps1                       # runs once per worker instance
      requirements.psd1                 # managed dependencies
      ResetUserPassword/
            function.json                   # httpTrigger + http output binding
            run.ps1                         # endpoint handler
            PasswordResetHelpers.psm1       # core logic (auth parsing, Key Vault, LDAPS)
            PasswordResetHelpers.psd1       # module manifest
```

One detail that’s easy to miss: `function.json` uses `"authLevel": "anonymous"` because authentication is handled by Easy Auth _before_ PowerShell runs.

## The Startup Hook: profile.ps1

Azure Functions loads `profile.ps1` **once per PowerShell worker instance** (think “once per worker process,” not once per request). In this project it does three things:

1. Sets strict error behavior (`Set-StrictMode -Version Latest`, `$ErrorActionPreference = 'Stop'`).
2. Detects the Managed Identity endpoint variables (`IDENTITY_ENDPOINT/IDENTITY_HEADER`, with fallback to legacy `MSI_*`).
3. Optionally “warms” secrets by retrieving:
   - the AD service account secret (currently `ENTRA-PWDRESET-RW`), and
   - the LDAPS public cert (`LDAPS-Certificate-CER`).

The request path in `run.ps1` **does not depend** on these global variables; it retrieves secrets on-demand through the helper module and caches per runspace. You can think of `profile.ps1` as a worker-initialization script and (optionally) an early warning system if Managed Identity / Key Vault access is broken.

## The Helper Module: PasswordResetHelpers.psm1

`PasswordResetHelpers.psm1` is where the “real work” lives. Each function is small on purpose, so you can test and reason about the behavior in isolation.

- `Get-ManagedIdentityAccessToken` - Calls the App Service / Functions Managed Identity endpoint (new `IDENTITY_*` or legacy `MSI_*`) and returns an access token for a given resource.

- `Get-KeyVaultSecretValue` - Uses Managed Identity to fetch a secret value from Key Vault via the REST API.

- `Get-FunctionAdServiceCredential` - Builds a `PSCredential` either from local env vars (`AD_SERVICE_USERNAME`/`AD_SERVICE_PASSWORD`) or from Key Vault (`ENTRA-PWDRESET-RW`). It also fixes the common JSON-backslash issue (`DOMAIN\svc`) before parsing.

- `Get-FunctionLdapsCertificateBase64` - Retrieves and caches `LDAPS-Certificate-CER` (base64). This is the pinning material used to validate the DC’s LDAPS certificate.

- `Get-ClientPrincipal` - Decodes the `X-MS-CLIENT-PRINCIPAL` header (base64 JSON) injected by Easy Auth, returning a PowerShell object with the caller’s claims.

- `Test-RoleClaim` - Scans the decoded principal for the required role (handles both `roles` and `role` claim types).

- `New-SecurePassword` - Generates a random password (default length 16) with required character classes.

- `Test-LdapsTcpConnectivity` - Performs a quick TCP connect check to `host:636` so network problems are easier to distinguish from TLS/cert validation problems.

- `ConvertFrom-LdapsCertificateBase64` - Parses the pinned certificate from base64, accepting either DER bytes or PEM text.

- `Get-CertificateDnsNames` - Extracts DNS names from the certificate (SANs first, with CN as fallback).

- `Test-CertificateMatchesHostName` - Validates that the certificate names match the domain controller hostname, including wildcard handling.

- `New-LdapsConnection` - Creates an LDAPS `LdapConnection`, enables SSL, and attaches a strict `VerifyServerCertificate` callback that enforces: 1) thumbprint pinning to the Key Vault cert, and 2) hostname validation.

- `Get-ADUserDistinguishedName` - Searches AD over LDAPS to find the user DN by `sAMAccountName`.

- `Set-ADUserPassword` - Uses LDAPS to modify `unicodePwd` for the target user (via `ModifyRequest`). This is the core “reset” operation.

## The Endpoint: run.ps1

`run.ps1` is intentionally written as a single guided flow (not a pile of helper functions). Conceptually, it’s a pipeline:

1. **Validate request envelope**

   - Requires `X-MS-CLIENT-PRINCIPAL` and checks required env vars (`REQUIRED_ROLE`, `DOMAIN_CONTROLLER_FQDN`, `DOMAIN_NAME`).

2. **Decode principal + authorize**

   - `Get-ClientPrincipal` → `Test-RoleClaim` → return `401/403` early if needed.

3. **Parse and validate request body**

   - Handles both string JSON and already-deserialized bodies, then requires `samAccountName`.

4. **Load secrets needed for the operation**

   - `Get-FunctionAdServiceCredential` for the bind credential.
   - `Get-FunctionLdapsCertificateBase64` for the pinned cert (required).

5. **Generate a password and apply it over LDAPS**

   - `New-SecurePassword` generates the value returned to the caller.
   - `Set-ADUserPassword` performs the reset over LDAPS.

6. **Return the response (with security headers)**
   - Responds `200` with `{ samAccountName, password, resetTime, message }` and `Cache-Control: no-store` to reduce accidental caching.

## The Test Driver: Test-FunctionAppWithToken.ps1

The `scripts/Test-FunctionAppWithToken.ps1` script is designed to **simulate a real calling application**. It uses the same client credentials flow your automation, portal, or service would use in production.

What it does:

1. Requests an access token from the Entra v2 token endpoint:
   - `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token`
2. Uses the `.default` scope for your API:
   - `scope=api://{ApiAppId}/.default`
3. Calls the function endpoint with `Authorization: Bearer {token}`.
4. Sends a JSON body that includes `samAccountName` (derived from `UserPrincipalName`). The current function only requires `samAccountName`; extra fields in the test payload are ignored.

Example usage:

```powershell
./scripts/Test-FunctionAppWithToken.ps1 \
      -ClientId "<client-app-id>" \
      -ClientSecret "<client-secret>" \
      -TenantId "<tenant-id>" \
      -ApiAppId "<api-app-id>" \
      -FunctionAppUrl "https://<functionapp>.azurewebsites.net" \
      -UserPrincipalName "testuser1@contoso.com" \
      -NewPassword "IgnoredByCurrentAPI123!"
```

It also prints key token claims (`aud`, `iss`, roles) so when auth breaks you can quickly see whether you’re dealing with an audience mismatch, issuer mismatch, or missing role assignment.

To generate a app registration and secret for the calling app the `scripts/Create-ClientAppRegistration.ps1` script can help.

## Conclusion

This project looks small on the surface—one endpoint that resets a password—but it only stays “boring” because the hard parts are handled deliberately.

- **Easy Auth** takes care of token validation so the function can focus on business logic.
- **Authorization** is reduced to a single, auditable decision: “does the caller have the role?”
- **Key Vault + Managed Identity** keeps credentials and pinning material out of code and out of deployment scripts.
- **LDAPS with strict certificate pinning and hostname validation** makes the directory operation secure without relying on fragile trust-store customization.

The result is an API you can demo, redeploy, and troubleshoot confidently: when it fails, it fails for reasons you can explain—and when it succeeds, it does exactly one thing, safely.

## Quick Reference

- Endpoint: `POST /api/ResetUserPassword`
- Auth: Easy Auth (Entra ID v2 issuer) + role claim check
- Required request body: `{ "samAccountName": "..." }`
- Key Vault secrets: `ENTRA-PWDRESET-RW`, `LDAPS-Certificate-CER`
- Directory transport: LDAPS on `:636` with certificate pinning + hostname validation

---

**Built with**: PowerShell 7.4 • Azure Functions • Easy Auth • Key Vault (Managed Identity) • LDAPS
