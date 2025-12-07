# Building a Secure Password Reset API with Azure Functions and JWT Authentication

## The Challenge

Picture this: you're managing an on-premises Active Directory environment, and you need to expose password reset capabilities to external systems or web applications. The password needs to be reset in AD, but you want to do it securely, with proper authentication and authorization. You also need it to handle dozens of requests per second without breaking a sweat.

This is exactly what we're building today - a production-ready Azure Function App that bridges the gap between modern cloud authentication and traditional on-premises Active Directory.

## The Architecture: PowerShell Meets Modern Auth

At its core, this is an Azure Function running PowerShell 7.4, but what makes it interesting is how it handles authentication. We're not relying on Azure's built-in authentication features. Instead, we've implemented full JWT Bearer token validation right in the code, giving us complete control over who can reset passwords and when.

The function exposes a simple HTTP POST endpoint, but don't let that simplicity fool you. Behind the scenes, every request goes through a rigorous authentication and authorization pipeline before a single character of a password is changed.

## The Authentication Story

Let's walk through what happens when a request comes in. Imagine you're an external application that needs to reset a user's password. You've already obtained a JWT token from your identity provider (Entra ID), and you're ready to make the call.

### Step 1: The Bearer Token

Your application sends an HTTP POST request with an Authorization header: `Bearer eyJhbGciOiJSUzI1Ni...` (one of those incredibly long JWT tokens). But here's the key difference from traditional implementations: **your function code never sees this raw token**.

### Step 2: Platform Authentication—Delegation at Work

Before your PowerShell code even starts executing, Azure's App Service Authentication middleware (also known as "Easy Auth") intercepts the request. This is where all the heavy lifting happens:

**Signature Validation**: The platform fetches the issuer's signing keys from the OpenID Connect metadata endpoint and validates the token's cryptographic signature. No manual key management, no custom JWKS caching—it's all handled automatically.

**Timing Checks**: The middleware validates `exp` (expiration) and `nbf` (not before) claims. Expired or not-yet-valid tokens are rejected immediately with a 401.

**Issuer Verification**: The token's `iss` claim must match the configured issuer (`https://login.microsoftonline.com/{tenant-id}/v2.0`). Tokens from other tenants or identity providers are rejected.

**Audience Validation**: The token's `aud` claim must match `api://{clientId}`. This prevents token reuse across different APIs.

If any of these checks fail, the request never reaches your function. The middleware returns a 401 Unauthorized, and you see it in Application Insights as a failed authentication attempt—no function execution, no billing for that request.

### Step 3: Principal Injection

When authentication succeeds, something elegant happens: the middleware injects an `X-MS-CLIENT-PRINCIPAL` header into the request. This header contains a base64-encoded JSON object with all the user's claims, pre-validated and ready to use.

Your function's first task is simple: decode this header. The `Get-ClientPrincipal` function handles this:

```powershell
$principal = Get-ClientPrincipal -HeaderValue $Request.Headers['X-MS-CLIENT-PRINCIPAL']
```

You get a clean PowerShell object with properties like `auth_typ` (authentication type), `name_typ` (name claim type), and most importantly, a `claims` array containing every claim from the original token.

### Step 4: Role-Based Authorization

Now comes the business logic: is this authenticated caller actually allowed to reset passwords?

This is where role-based access control (RBAC) comes in. We look for a specific claim—`Role.PasswordReset`—in the decoded principal. This claim can appear in either the `roles` claim type (for application tokens) or the `role` claim type (for user tokens). The `Test-RoleClaim` function handles both cases:

```powershell
$hasRole = Test-RoleClaim -Principal $principal -RequiredRole 'Role.PasswordReset'
```

If the claim isn't present, the caller gets a 403 Forbidden response. You might have a valid token (you made it past the middleware), but if you don't have the right role, you're not resetting any passwords today.

### Why Delegation Matters

By delegating authentication to the platform, we gain several advantages:

1. **Security**: Microsoft's authentication team maintains the validation logic. When new threats emerge or signing algorithms change, updates happen at the platform level—no code changes needed.

2. **Key Rotation**: When Azure AD rotates signing keys, the middleware automatically fetches updated keys from the OpenID Connect metadata endpoint. Zero downtime, zero configuration drift.

3. **Simplicity**: Our function code has no dependencies on cryptography libraries. No `System.IdentityModel.Tokens.Jwt`, no manual signature verification, no clock skew handling.

4. **Performance**: The middleware is optimized at the platform level. Validation happens in native code before the PowerShell runspace even initializes, shaving milliseconds off cold starts.

5. **Consistency**: The same authentication pattern works across all App Service and Azure Functions apps. Learn it once, use it everywhere.

### OAuth 2.0 and Zero Trust Architecture

This function app is a textbook implementation of modern security principles, specifically OAuth 2.0 resource server patterns and Zero Trust architecture.

**OAuth 2.0 Resource Server**: Our function acts as an OAuth 2.0 protected resource. It doesn't issue tokens or handle user login flows—that's the authorization server's job (Entra ID). Instead, it validates access tokens and enforces authorization policies. This clean separation of concerns is fundamental to OAuth 2.0:

- **Authorization Server** (Entra ID): Issues access tokens after authenticating users and obtaining consent
- **Resource Server** (our function): Validates tokens and protects the password reset resource
- **Client** (calling application): Obtains tokens from the authorization server and presents them to our API

This design means we never see user credentials, never handle authentication UI, and never manage token issuance—all high-risk activities handled by Microsoft's hardened identity platform.

**Zero Trust Principles**: The function embodies the core tenets of Zero Trust security:

1. **Verify Explicitly**: Every request is authenticated via cryptographic proof (JWT signature). No implicit trust based on network location or IP address. Even if a request comes from inside Azure's network, it still requires a valid, signed token.

2. **Use Least Privilege Access**: The function checks not just _who_ you are (authentication), but _what you're allowed to do_ (authorization). The `Role.PasswordReset` claim represents fine-grained, just-enough permission. The AD service account follows the same principle—delegated permissions for password resets only, nothing more.

3. **Assume Breach**: Security is layered. Even if an attacker compromises one layer (say, they steal a valid token), they're limited by:
   - Token expiration (time-bound access)
   - Audience restriction (token works only for this API)
   - Role requirements (token must have the specific role claim)
   - AD delegation limits (service account can't elevate privileges or modify admins)
   - Network segmentation (VNet integration limits lateral movement)

**Defense in Depth**: Notice how security isn't a single gate—it's a series of checkpoints:

- TLS ensures confidentiality in transit
- App Service Authentication validates token integrity
- Role claims enforce authorization
- Key Vault protects secrets at rest
- Managed Identity eliminates credential sprawl
- Audit logs track every action in Application Insights

If any single control fails or is bypassed, others remain in place. This is defense in depth, and it's why Zero Trust architectures are resilient against sophisticated attacks.

**Token Scoping and Least Privilege**: The OAuth 2.0 model shines here. Tokens are scoped to specific resources (via the `aud` claim) and carry only the permissions needed (via role claims). A token valid for our password reset API can't be reused against other APIs, even within the same tenant. This containment is critical in preventing token replay attacks and limiting blast radius during incidents.

## The Password Reset Flow

Once we've verified that the caller is authenticated and authorized, we move into the actual business logic. The request body contains a simple JSON payload with the `samAccountName` of the user whose password needs to be reset.

### Generating a Secure Password

We don't let callers specify the new password. Instead, we generate one using `New-SecurePassword`. This function uses .NET's `RNGCryptoServiceProvider` to create cryptographically secure random passwords. Each password is 12 characters by default (configurable up to 256) and includes uppercase letters, lowercase letters, digits, and special characters.

The implementation uses a Fisher-Yates shuffle algorithm to ensure truly random distribution of character types. This isn't your grandfather's `Get-Random`—this is production-grade password generation.

### Connecting to Active Directory

Here's where cloud meets on-premises. The function uses the ActiveDirectory PowerShell module's `Set-ADAccountPassword` cmdlet to actually reset the password in your domain. But how do we authenticate to AD from a cloud function?

During initialization (in `profile.ps1`), the function retrieves AD service account credentials from Azure Key Vault using its Managed Identity. These credentials are cached in memory for the lifetime of the function app, so we're not hitting Key Vault on every request.

The beauty of this approach is that the AD service account can be delegated minimal permissions—just enough to reset passwords and nothing more. We're following the principle of least privilege all the way down.

### The Response

If everything succeeds, the caller gets back a JSON response containing:

- The `samAccountName` they requested
- The newly generated `password`
- A `resetTime` timestamp
- A `status` message

The password is returned in the response body (over HTTPS, of course), and it's up to the caller to deliver it to the end user through their preferred channel—email, SMS, a web portal, whatever makes sense for their use case.

## Security: Defense in Depth and Zero Trust in Practice

Security wasn't an afterthought here—it's baked into every layer, implementing Zero Trust principles throughout the architecture.

**Identity-Centric Security**: Unlike traditional perimeter-based security models that trust everything inside a network boundary, this function treats every request as potentially hostile until proven otherwise. Authentication and authorization happen at the application layer, not just at the network edge. This aligns with the Zero Trust mandate: "never trust, always verify."

**Security Headers**: Every response includes strict security headers. `Cache-Control: no-store` ensures no caching of sensitive data. `X-Content-Type-Options: nosniff` prevents MIME-sniffing attacks. And `Strict-Transport-Security` enforces HTTPS for an entire year, preventing protocol downgrade attacks.

**Secrets Management**: That AD service account credential? It lives in Azure Key Vault, not in environment variables or configuration files. The function accesses it using a Managed Identity, so there are no credentials to rotate or leak. This eliminates an entire class of vulnerabilities around credential storage and management—no secrets in source control, no environment variables to exfiltrate, no configuration files to mishandle.

**Managed Identity and Credential-less Authentication**: The function's Managed Identity represents another Zero Trust win. Traditional approaches would require storing credentials to access Key Vault, creating a chicken-and-egg problem. Managed Identity uses Azure AD's token service to authenticate the function app itself, establishing trust based on cryptographically verifiable identity rather than shared secrets. It's passwordless authentication at the infrastructure level.

**No Logging of Passwords**: The generated passwords never touch Application Insights or any logging system. We've been careful to ensure that sensitive data stays out of telemetry. This is data protection by design—sensitive information has minimal exposure time (exists only in memory for the duration of the request) and minimal exposure scope (returned only to the authenticated caller over TLS).

**Continuous Verification**: In a Zero Trust model, trust is never permanent—it's continuously evaluated. While our JWT tokens have expiration times that enforce re-verification, the principle extends throughout the stack. Managed Identity tokens are short-lived. Key Vault access requires valid identity tokens. Every layer independently verifies identity and authorization, refusing to simply trust upstream assertions.

## Performance: Built for Scale

This function is designed to handle real workload—we're talking tens of requests per second without breaking a sweat. How?

**Concurrency**: PowerShell 7.4 introduces in-process concurrency with runspaces. We've configured the function to handle up to 10 concurrent requests per worker process (`PSWorkerInProcConcurrencyUpperBound=10`).

**Multiple Workers**: The function app can spin up multiple worker processes (`FUNCTIONS_WORKER_PROCESS_COUNT=2`), giving us even more parallelism.

**Scale-Out**: Being on the Consumption plan, the function can automatically scale out to 200 instances if traffic demands it. With 10 concurrent requests per worker and 2 workers per instance, that's up to 4,000 concurrent password resets if needed.

**Optimized Cold Starts**: We're using managed dependencies and keeping module imports minimal to ensure fast cold starts when new instances spin up.

## The Module: PasswordResetHelpers

All of this functionality lives in a reusable PowerShell module called `PasswordResetHelpers`. It exports four functions, each with a specific responsibility:

`Get-ClientPrincipal` decodes the `X-MS-CLIENT-PRINCIPAL` header injected by App Service Authentication. Give it the base64-encoded header value, and it returns a clean PowerShell object with all the authenticated user's claims.

`Test-RoleClaim` checks for the presence of a specific role in the decoded principal's claims array. It's flexible enough to handle both `roles` and `role` claim types.

`New-SecurePassword` generates cryptographically secure passwords with configurable length and guaranteed complexity.

`Set-ADUserPassword` wraps the AD cmdlets with proper error handling and even supports `-WhatIf` for testing.

The module follows PowerShell best practices religiously—`[CmdletBinding()]` on every function, proper parameter validation, comprehensive error handling with `$ErrorActionPreference = 'Stop'`, and Microsoft Learn references in comments for every cmdlet used.

## The Result

What we've built is a function that's both simple and sophisticated. Simple in its API (HTTP POST with a JWT and a username), but sophisticated in how it handles authentication, authorization, password generation, and on-premises integration.

It's production-ready out of the box, with comprehensive test coverage (95.1% of the core module code), thorough error handling, and security best practices throughout. Whether you're integrating it into a custom web portal, exposing it to third-party systems, or building automation around it, this function provides a secure, scalable, and reliable way to reset Active Directory passwords from the cloud.

## Technical Reference

For those who want the quick facts, here's what makes up this solution:

**Core Technologies:**

- PowerShell 7.4 on Azure Functions v4
- App Service Authentication (Easy Auth) for JWT validation
- ActiveDirectory PowerShell module for AD integration
- Azure Key Vault for secrets management with Managed Identity
- Application Insights for monitoring

**The Request Pipeline:**

1. Platform authentication → JWT validation (signature, timing, issuer, audience)
2. Principal injection → X-MS-CLIENT-PRINCIPAL header with decoded claims
3. Principal decoding → Get-ClientPrincipal extracts claims
4. Role authorization → Test-RoleClaim verifies Role.PasswordReset
5. Password generation → Cryptographically secure, 12+ characters
6. AD password reset → Set-ADAccountPassword with service account
7. Response → JSON with new password and metadata

**HTTP Status Codes:**

- 200: Password reset successful
- 400: Missing or invalid request body
- 401: Invalid, expired, or missing JWT (rejected by platform)
- 403: Valid token but missing required role
- 404: User not found in Active Directory
- 500: AD connection or permission errors

**Performance Configuration:**

- 10 concurrent runspaces per worker process
- 2 worker processes per instance
- Up to 200 instances on Consumption plan
- Theoretical maximum: 4,000 concurrent requests

**Testing:**

- 40 unit tests with Pester 5.x
- 92.9% code coverage on PasswordResetHelpers module
- All external dependencies properly mocked
- Test reports in NUnit XML, JaCoCo, and HTML formats

The complete source code includes infrastructure as code (Bicep), deployment scripts, comprehensive documentation, and everything needed to run this in production. Check out the README and QUICKSTART guides in the repository for deployment instructions.

---

**Built with**: PowerShell 7.4 • Azure Functions • Platform Authentication • Active Directory  
**Test Coverage**: 92.9% • 40 passing tests  
**Ready for**: Production deployment in hybrid cloud environments
