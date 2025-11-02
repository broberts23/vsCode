# Just‑In‑Time DevOps Admins: PIM + GitHub Actions for JIT role elevation

## Introduction

This post demonstrates a practical, secure pattern for integrating Microsoft Entra Privileged Identity Management (PIM) into a CI/CD pipeline so that automation — for example, a GitHub Actions runner — can request, use, and then release elevated privileges in a repeatable, auditable way.

Traditional portal-driven PIM activations are useful for ad-hoc human tasks, but they don't map well to automated delivery: manual clicks are hard to reproduce, difficult to attach to a pull request or build, and they provide limited machine-readable evidence. By contrast, a programmatic PIM activation flow using Microsoft Graph and identity-first automation brings several tangible benefits:

- Repeatability and reproducibility: the activation → perform → revoke sequence is defined as code and can be replayed across tenants and environments.
- CI/CD integration: pipelines can request just‑in‑time privileges for a specific deployment run and attach PR/build metadata for clear traceability.
- Principle of least privilege: request the smallest role and shortest duration necessary for the job instead of maintaining standing privileges.
- Policy-as-code and testability: activation flows can be reviewed in pull requests, linted, and run through CI tests before applying changes to production.
- Audit and compliance: workflows produce machine-readable activation records that can be stored with build artifacts or forwarded to SIEM for longer retention.
- Faster recovery and consistent rollback: automation can detect activation failures and run deterministic rollback or remediation flows.

This repository contains a working scaffold that illustrates the pattern: Bicep templates for demo infrastructure, a PowerShell module that uses Graph authentication patterns, a small wrapper script to request activations from a runner, Pester tests, and a GitHub Actions workflow that demonstrates a dry-run activation.

Key references:

- Microsoft Entra Privileged Identity Management: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure
- PIM Microsoft Graph APIs: https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview?view=graph-rest-1.0

What changed in this drop

- Implemented a programmatic JIT pattern for automation identities (managed identity / service principal). Managed identities cannot be PIM-eligible; instead, the workflow creates a temporary RBAC role assignment, performs the privileged action, and then removes the assignment immediately after.
- Added a reusable GitHub Actions workflow that collects requested role/resource pairs, generates a human-readable approval table, requires a GitHub Environment approval gate, and only then performs the privileged action.
- Hardened the workflow’s approval table generation (Markdown escaping, one-to-one / one-to-many pairing logic, and robust requestId capture).
- Updated the demo Bicep to provision a user-assigned managed identity, an RBAC-enabled Key Vault, and expose the identity’s clientId/principalId via outputs. Added a Key Vault–scoped role assignment example.
- Refactored the PowerShell module: non-interactive testability, Graph wrapper with v1.0/beta fallback, and a new lifecycle function that runs the temporary RBAC create → rotate secret → RBAC delete sequence.

## Repository structure

Top-level folders and files and how they fit together:

- `infra/`
	- `infra/main.bicep` — Demo infrastructure. Provisions a user-assigned managed identity (UAMI), an RBAC-enabled Key Vault, and a Key Vault–scoped role assignment example. Exposes outputs for `clientId`, `principalId`, and resource IDs so CI steps don’t need to call Graph to discover them.

- `scripts/`
	- `scripts/PimAutomation.psm1` — PowerShell 7.4 module that encapsulates Graph and RBAC logic. Key functions:
		- `Get-GraphAccessToken` — prefers Az CLI token when available; supports interactive Graph login in dev.
		- `Connect-PimGraph` — normalizes Graph connection with the token.
		- `Invoke-PimGraphRequest` — Graph v1.0/beta compatibility wrapper for GET/POST/PATCH/DELETE.
		- `New-PimActivationRequest` — creates an activation request (stubbed for non-interactive tests) and returns a normalized object with a `requestId`.
		- `Get-PimRequest` — reads request status; stubbed to Approved for demo tests.
		- `Connect-AzManagedIdentity` — helper to connect to Azure via managed identity or fallback to interactive in dev.
		- `Set-PimKeyVaultSecret` — rotates a Key Vault secret using Az.KeyVault.
		- `New-TemporaryKeyVaultRoleAssignment` / `Remove-TemporaryKeyVaultRoleAssignment` — creates/removes a scoped RBAC assignment on the Key Vault.
		- `Invoke-TempKeyVaultRotationLifecycle` — orchestrates create → rotate secret → delete, and validates removal; used by CI.
	- `scripts/run-activation.ps1` — Entry point for the workflow. Calls `Connect-PimGraph`, `New-PimActivationRequest`, and then runs `Invoke-TempKeyVaultRotationLifecycle` when vault/secret inputs are provided. Emits structured JSON for the pipeline.

- `.github/workflows/`
	- `.github/workflows/pim-elevate.yml` — Reusable workflow that collects role/resource inputs, builds an approval table, blocks on a GitHub Environment gate, then runs the privileged step via `scripts/run-activation.ps1`.
	- `.github/workflows/pim-elevate-demo-use.yml` — Example caller that demonstrates how to invoke the reusable workflow (uses `secrets: inherit`).
	- `.github/workflows/test_table_generation.ps1` — Local-only helper to validate Markdown table escaping for the approval step (not used by CI runs).

- `tests/`
	- `tests/PimAutomation.Tests.ps1` — Pester tests designed to run non-interactively (Graph calls skipped via environment flag). Validates exports and basic behavior.

- `blog.md` — This document.
	- `bicepconfig.json` — Optional Bicep configuration to enable experimental extensibility for Microsoft Graph resources when authoring with Graph Bicep templates.

## Scenarios / use cases

Below are practical scenarios where a CI runner (or other automation) would request a PIM activation via Microsoft Graph. Each example explains why a JIT activation is preferable to a permanent role assignment.

1. Privileged infrastructure deployments
	- Pipelines that need to modify RBAC, create or update management groups or subscriptions, or perform owner-level deployments. A JIT activation grants only the needed privileges for the deployment window and records the build/PR that requested it.

2. Emergency or hotfix changes in production
	- Automated runbooks that apply urgent network or configuration changes during incidents. JIT allows automation to act quickly while keeping the elevated window short and auditable.

3. Secrets, certificate, or key rotation tasks
	- Workflows that rotate Key Vault secrets, service principal certificates or subscription keys. Because these operations are high-sensitivity, they should run with time-limited elevation rather than a long-lived owner/service principal.

4. High-impact configuration changes
	- Actions like scaling a managed database, changing VM scale set properties, or upgrading infrastructure control-plane settings. These are low-frequency but risky operations — a JIT window reduces blast radius.

5. Onboard/offboard flows that require temporary promotion
	- Lifecycle workflows that temporarily promote a user or test identity to verify on‑boarding or off‑boarding steps (for example: run verification tests as an eligible admin then remove privileges automatically).

6. Incident-response diagnostics and remediation
	- Automated IR playbooks that need to query sensitive logs, alter firewall rules, or apply containment steps. JIT activations enable automation to remediate rapidly while ensuring short-lived privileges and full audit trails.

7. Governance and testing of access‑review flows
	- CI jobs that exercise access reviews, entitlement-management or PIM workflows in a test tenant by temporarily elevating a test identity. Useful for continuous verification of governance automation.

8. Multi-tenant or partner delegated operations
	- Managed services that perform privileged operations across customer tenants or external environments can request scoped JIT activations per-customer rather than holding standing privileges across all tenants.

9. Identity configuration changes
	- Deployments that create or update app registrations, add federated credentials, or change conditional access policies should run under a temporary, audited elevation rather than a permanent global admin assignment.

10. Scheduled maintenance and controlled windows
	- Scheduled jobs that perform approved maintenance during a defined window can programmatically request elevation (including ticket/maintenance ID justification) so the run is traceable and constrained to the maintenance period.

Each scenario benefits from: scoped, time-limited access; machine-readable justification and metadata (PR/build IDs); and an auditable activation lifecycle that can be retained in CI artifacts or forwarded to SIEM and compliance tooling.

## Benefits vs Permanent assignments

- Minimized attack surface (short TTL)
- Tighter auditability (attach PR/build/ticket metadata)
- Easier compliance evidence (machine readable)
- Predictable rollback & revoke patterns


## Background and motivation

Traditional automation patterns often rely on a broadly privileged service principal with a long-lived secret. That’s convenient but risky: secrets leak, and standing privileges widen blast radius. PIM shifts that posture to “trust, but timebound”: elevation requires a specific reason, duration, and an approver. For non-human actors (CI/CD), the right approximation is to programmatically create a temporary role assignment guarded by an approval gate, then remove it. This keeps privileges short-lived and auditable while still enabling fully automated flows (no portal clicks).

Compared with static service principals:
- No long-lived secret material is required when you use OIDC or managed identity.
- Privileges are granted just-in-time and automatically revoked.
- Every activation is traceable to a PR or run — easier audits and incident reconstruction.

## Architecture overview

Actors

- CI runner (GitHub Actions): requests elevation, renders an approval table, waits for approval (GitHub Environment), and executes privileged operations once approved.
- Automation identity: either a user-assigned managed identity (UAMI) deployed by Bicep for demos, or an OIDC-federated workload identity for production pipelines.
- Microsoft Graph (optional): used to create/read PIM activation requests where applicable to user principals. For managed identities, the pattern uses temporary Azure RBAC role assignments.
- Azure Resource Manager (ARM): enforces role assignments and scopes; Key Vault is configured with RBAC data-plane permissions.
- Approver(s): GitHub Environment approvers; optionally, an automated approver (Function/Logic App) can be integrated later.

Flow (high level)

1) CI job starts, logs into Azure via OIDC, and gathers requested role/resource pairs.
2) CI builds a Markdown approval table (role names, resource names, requestIds) and posts it to the run; job waits for GitHub Environment approval.
3) On approval, CI executes a lifecycle function that:
	- Creates a temporary Key Vault–scoped role assignment for the automation identity (for example, Key Vault Secrets Officer),
	- Performs the privileged action (e.g., rotate a secret),
	- Removes the temporary role assignment and validates removal.
4) CI records structured output (requestId, timestamps, secret version) as artifacts.

## Implementation plan

This section will be expanded into subpages. For now, the top-level plan:

- Infra: Bicep template provisions a demo Key Vault with RBAC, a user-assigned managed identity, and emits helpful outputs (clientId, principalId, resource ids). See `infra/main.bicep`.
- Auth: prefer OIDC in GitHub Actions for the workflow; for local tests, you can log in interactively. Avoid long-lived secrets.
- PowerShell automation: module `scripts/PimAutomation.psm1` implements a Graph wrapper (v1.0/beta compatibility) and the lifecycle for temporary RBAC assignments and secret rotation.
- CI/CD workflow: reusable workflow `.github/workflows/pim-elevate.yml` accepts roleIds/resourceIds, builds an approval table, blocks on environment approval, then runs `scripts/run-activation.ps1` to execute the lifecycle.
- Approval automation (optional): future enhancement — an Azure Function approver for certain low-risk policies.

Planned docs: step-by-step command pages, payload examples, and troubleshooting for common errors (RBAC propagation, throttling, approvals). To be added as separate docs in a later update.

## Using Microsoft Graph resources in Bicep (beta)

You can author Entra resources (applications / service principals) directly from Bicep using the Microsoft Graph Bicep templates. This is a preview extensibility feature in Bicep and requires two things:

- enabling Bicep extensibility in your repo-level `bicepconfig.json`, and
- importing the Microsoft Graph extension in any Bicep file that declares `Microsoft.Graph/*` resources.

What you need
- A recent Bicep CLI (or Azure CLI with the Bicep command) and the VS Code Bicep extension.
- A repo-level `bicepconfig.json` that enables the extensibility feature and (optionally) maps extension aliases to the registry artifacts. Our repo includes a `bicepconfig.json` that looks like this:

```json
{
	"experimentalFeaturesEnabled": {},
	"extensions": {
		"graphV1": "br:mcr.microsoft.com/bicep/extensions/microsoftgraph/v1.0:1.0.0",
		"graphBeta": "br:mcr.microsoft.com/bicep/extensions/microsoftgraph/beta:1.0.0"
	}
}
```

See the Bicep configuration docs for details: https://learn.microsoft.com/azure/azure-resource-manager/bicep/bicep-config
and the experimental features overview: https://github.com/Azure/bicep/blob/main/docs/experimental-features.md

Importing the Graph extension

Once `bicepconfig.json` is present and extensibility is enabled, you can import the Graph extension at the top of your Bicep file. You can import by the full module reference (the "br:" path) or by the alias you defined in `bicepconfig.json`:

```bicep
// import by alias (preferred when you've mapped the extension in bicepconfig.json)
extension 'graphV1'

After the extension import, you can declare Microsoft Graph types in Bicep. Example (beta) — consult the Graph Bicep reference for available properties and schema:

```bicep
resource ghApp 'Microsoft.Graph/applications@beta' = {
	name: 'my-graph-app'
	displayName: 'my-graph-app'
	signInAudience: 'AzureADMyOrg'
}

resource ghSp 'Microsoft.Graph/servicePrincipals@beta' = {
	name: 'my-graph-sp'
	appId: ghApp.appId
}
```

Reference: Microsoft Graph Bicep templates — https://learn.microsoft.com/graph/templates/bicep/reference/serviceprincipals?view=graph-bicep-beta

Validate and deploy

Update your local Bicep tooling and then build/validate the template before deploying:

```bash
az bicep upgrade
az bicep build --file infra/main.bicep

# Dry-run a resource group deployment
az deployment group validate \
	--resource-group MyDemoRG \
	--template-file infra/main.bicep \
	--parameters location='eastus'
```

Troubleshooting and fallback strategy

- If you get "resource type is not valid" or similar validation errors, ensure:
	- Bicep CLI and the VS Code Bicep extension are up to date.
	- `bicepconfig.json` is in the repository root (or a parent folder) and contains `"experimentalFeaturesEnabled": { "extensibility": true }`.
	- The `extension` import line appears before any `Microsoft.Graph/*` resource declarations.

- Some developer or CI environments may still lack the provider metadata required to author Graph types (the extensibility path is still evolving). For portability, this repo's `infra/main.bicep` includes a safe fallback pattern: instead of creating the app/servicePrincipal inline, accept `githubAppId` and `githubServicePrincipalId` as parameters and conditionally create the role assignment only when the service principal id is supplied. This lets teams either:
	1. Create the app/service principal ahead of time (via CLI or Graph APIs) and pass the returned `appId`/`principalId` into the Bicep deployment, or
	2. Enable Bicep extensibility in their dev/CI images and let the template create the app/SP directly.

Related discussion and issues: https://github.com/Azure/bicep/issues/16447


## GitHub Actions workflow: `pim-elevate.yml`

Purpose: provide a generic, approval-gated JIT elevation workflow reusable across repos and branches.

Inputs (from the caller):
- `roleIds` — JSON array of role definition GUIDs to request (e.g., Key Vault Secrets Officer).
- `resourceIds` — JSON array of Azure resource IDs to scope the request/assignment (e.g., Key Vault resource ID).
- `vaultName`, `secretName` — Optional; if provided, the workflow will perform a secret rotation using the lifecycle function after approval.

Jobs and flow:
1) request-elevation
	- Auth: Logs into Azure using OIDC (federated credentials) so az lookups can run without secrets.
	- Pairing logic: Builds pairs of roleId/resourceId with the following rules:
	  - If arrays are equal length → zip items by index.
	  - If one array has length 1 and the other >1 → pair the single item across all items of the other array.
	  - Otherwise → produce a Cartesian product (all combinations).
	- Reverse lookups: Uses `az role definition show --id` and `az resource show --ids` to fetch human-readable names/types.
	- Approval table: Renders a Markdown table (IDs and names wrapped in inline code; pipes/backticks/newlines escaped). Posts the table as a workflow comment via `github-script` and exposes table content as a job output.
	- Gate: The job emits metadata and ends; the next job is gated by a GitHub Environment (for example, `pim-rotation-approval`).

2) approve-and-rotate
	- Gate: Requires the GitHub Environment approval. Approvers can review the comment table before proceeding.
	- Auth: Logs into Azure using OIDC for RBAC operations.
	- Action: Runs `scripts/run-activation.ps1` which creates a traceable request, then calls `Invoke-TempKeyVaultRotationLifecycle` to create the temporary Key Vault assignment → rotate the secret → remove the assignment → validate removal.
	- Outputs: Emits structured JSON and can publish artifacts with activation and rotation details.

Requirements:
- A GitHub Environment configured with approvers (e.g., `pim-rotation-approval`).
- Federated identity (OIDC) configured in Azure with minimal RBAC to create/delete role assignments at the scopes you target.
- The target Key Vault must be RBAC-enabled (`enableRbacAuthorization: true`).

Notes:
- The workflow is designed to be reusable; use the demo caller as a reference for input wiring.
- For managed identities, PIM eligibility is not applicable; the workflow still records a requestId for traceability and relies on temporary RBAC during the approved window.

## PowerShell module: `PimAutomation.psm1`

Design goals:
- PowerShell 7.4, cross-platform, non-interactive by default in CI.
- Testability: Supports an environment flag to skip live Graph calls during Pester runs.
- Clear separation between Graph (request/trace) and Azure RBAC (enforcement at resource scope).

Key functions and behavior:
- `Get-GraphAccessToken` and `Connect-PimGraph`: establish Graph access using an Az CLI token when present; fall back to Connect-MgGraph in dev.
- `Invoke-PimGraphRequest`: sends requests to v1.0 or beta, with a predictable return shape and error handling.
- `New-PimActivationRequest` and `Get-PimRequest`: create and query activation requests; in non-interactive mode, return a stub with a generated `requestId` and Approved status to allow tests to proceed.
- `Connect-AzManagedIdentity`: convenient helper for connecting to Azure using a managed identity or dev login.
- `New-TemporaryKeyVaultRoleAssignment` and `Remove-TemporaryKeyVaultRoleAssignment`: create/delete RBAC assignments at the Key Vault scope for a specific principal (the automation identity). Deterministic GUID names are used to make cleanup reliable.
- `Set-PimKeyVaultSecret`: sets or rotates a secret using Az.KeyVault under the short-lived RBAC assignment.
- `Invoke-TempKeyVaultRotationLifecycle`: orchestrates the full sequence, validates removal, and returns a structured object suitable for CI logs and artifacts.

Contract (high level):
- Inputs: role definition ID, target resource ID (Key Vault), principal object ID/client ID, vault and secret names, and optional justification/metadata.
- Error modes: Graph unavailability (handled via stub/test mode), RBAC propagation delays (should be retried with backoff), and Azure API transient failures (retryable).
- Outputs: activation request info (`requestId`, timestamps), RBAC assignment details (id, scope), and the new secret version/id where applicable.

## Security and governance considerations

- Licensing: Some PIM features require Entra ID P2. Verify tenant licensing for your scenario.
- Permissions: Use least-privilege scopes and roles; prefer RBAC scopes at the minimal resource level required.
- Authentication: Prefer OIDC for CI runners and managed identities for Azure-hosted automation; avoid long-lived client secrets.
- Approval: Require human approval (GitHub Environment) for production; optionally add policy-based automated approvals for low-risk cases.
- TTLs: Keep elevation windows as short as practical. Validate that RBAC propagation is complete before proceeding.
- Audit: Persist machine-readable activation artifacts for retention and SIEM ingestion.

## Testing and validation

- Unit tests: Pester tests run non-interactively by default (Graph calls are skipped via an environment flag). Add mocks for Az/Graph calls to validate logic paths.
- Integration tests: Use a test subscription and a disposable Key Vault. Ensure cleanup of temporary role assignments.
- Failure modes: Validate behavior for denied approvals, RBAC propagation delays, and transient Azure API errors (add retries with backoff where appropriate).

## Demo / walkthrough — Secret / Key Rotation

This walkthrough focuses on a concrete, high-value scenario: rotating a Key Vault secret (for example, a service principal client secret or an application key) under a just-in-time privileged activation requested by the CI runner. Rotating secrets is a common operational task that requires elevated privileges and benefits from short-lived, auditable elevation.

High-level steps for the demo

1. Prerequisites
	- An Azure Key Vault configured to use the Azure RBAC permission model (`enableRbacAuthorization: true` is set in `infra/main.bicep`). This allows data-plane permissions via RBAC.
	- A CI runner identity: GitHub OIDC for the workflow, or a user-assigned managed identity for Azure-hosted runs.
	- Appropriate PIM licensing for your tenant (some features require Entra ID P2).

2. CI job starts and validates context
	- The GitHub Action runner verifies branch/ticket/PR metadata and ensures the job is allowed to request elevation (demo mode may allow auto-approvals).

3. Create a PIM activation request programmatically
	- The workflow calls a wrapper `New-PimActivationRequest`. For automation identities (managed identities), PIM eligibility does not apply; the workflow still records a requestId for traceability.
	- The Graph call path is implemented with a v1.0/beta compatibility wrapper; a local stub is available for non-interactive test runs.

4. Approval and activation
	- The reusable workflow posts an approval table and pauses at a GitHub Environment gate. Approvers can review the requested role/resource pairs before proceeding.
	- A future enhancement may add an optional automated approver (Function/Logic App) for specific policies.

5. Rotate the secret (performed under the JIT activation)
	- The automation generates a new secret value and calls `Set-AzKeyVaultSecret` under a temporary, Key Vault–scoped RBAC assignment. The flow implemented here is:
		1. Create a traceable requestId (via Graph when applicable, or stub).
		2. Wait for approval at the GitHub Environment gate.
		3. Create a temporary Key Vault data-plane RBAC assignment (e.g., Key Vault Secrets Officer) for the automation identity.
		4. Perform the secret write while the assignment is active.
		5. Remove the temporary assignment and validate removal.

	- The repository includes `scripts/PimAutomation.psm1` with helper functions and a lifecycle function `Invoke-TempKeyVaultRotationLifecycle` that orchestrates the create → rotate → delete sequence.
	- Optionally rotate dependent credentials and notify consumers in a follow-up step (future enhancement with a safe consumer-rotation harness).

6. Revoke/expire and audit
	- After the rotation completes, the activation ends (either automatically by PIM TTL or by an explicit revocation step). The pipeline records a machine-readable artifact containing the requestId, activatedAt, completedAt, rotatedSecretVersion (Key Vault secret version or id), and build/PR metadata.
	- Upload that artifact to the run's artifacts and forward structured events to SIEM or a compliance store.

7. Post-rotation validation
	- Run integration smoke tests that verify the rotated secret works for consumers (use a test consumer identity and avoid printing secrets to logs).
	- If validation fails, run an automated rollback plan (store previous secret version reference and use it to restore if necessary).

## Implementation plan (detailed TODOs)

Below is a prioritized checklist that reflects current progress and what’s next.

### High priority
- [ ] Replace stub with real Microsoft Graph PIM integration
	- Implement `New-PimActivationRequest` and `Get-PimRequest` against privilegedAccess/azureResources (v1.0 or beta as required) with robust error handling and retries.
- [ ] CI wiring and automated tests
	- Extend `.github/workflows/pim-elevate.yml` to run PSScriptAnalyzer and Pester on PRs; add a separate, opt-in integration job that uses OIDC against a test subscription.
- [ ] Security & auth docs
	- Document required Graph scopes and approvals, and the minimal Azure RBAC roles for the GitHub OIDC principal. Provide a federated credential example.

### Medium priority
- [ ] Module hygiene
	- Add `scripts/PimAutomation.psd1` with `PowerShellVersion = '7.4'` and explicit `FunctionsToExport`. Add a PSScriptAnalyzer configuration and lint step.
- [ ] Tests and mocks
	- Pester unit tests that mock Az and Graph calls (Connect-MgGraph, Invoke-RestMethod, Set-AzKeyVaultSecret, New/Remove-AzRoleAssignment). Cover failure paths and timeouts.
- [ ] Operational docs
	- Add runbooks for emergency activation, manual revoke, and escalation. Add a developer README with local test steps and environment variables.

### Low priority / extras
- [ ] Notifications and observability
	- Optional Slack/Teams notifications from the workflow; structured logs to Azure Monitor or a SIEM.
- [ ] Automated approver
	- Azure Function/Logic App to approve specific low-risk requests based on policy. Add safeguards and audit logging.
- [ ] Dashboarding
	- Simple dashboard (e.g., Static Web App + JS) to surface activation metrics from artifacts or a data store.

## Operational runbook

To be added: standard playbooks for emergency activation, manual revoke, and approval escalation, plus how to audit activations in Entra and Graph for compliance investigations.

## Next steps and roadmap

- Replace PowerShell stubs with real Graph PIM API calls (privilegedAccess/azureResources).
- Add GitHub OIDC federated credential example and minimal RBAC guidance.
- Implement optional automated approver with conditional policy.
- Create a dashboard to surface activation metrics and audit summaries.

## Conclusion

JIT elevation for automation brings the control and auditability of PIM into your delivery pipelines. By replacing standing privileges with an approval-gated, short-lived role assignment, you reduce risk without sacrificing speed. The patterns here give you a pragmatic starting point you can adapt — start with the reusable workflow and lifecycle helper, then layer in Graph-backed requests and richer approvals as you mature.

## References

- Microsoft Entra PIM docs: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure
- Microsoft Graph PIM APIs: https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview?view=graph-rest-1.0
- Azure RBAC for Key Vault: https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
- Az PowerShell: Connect-AzAccount — https://learn.microsoft.com/powershell/module/az.accounts/connect-azaccount?view=azps-latest
- Az PowerShell: Set-AzKeyVaultSecret — https://learn.microsoft.com/powershell/module/az.keyvault/set-azkeyvaultsecret?view=azps-latest
- Az PowerShell: New-AzRoleAssignment — https://learn.microsoft.com/powershell/module/az.resources/new-azroleassignment?view=azps-latest
