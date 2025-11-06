# Just‑In‑Time RBAC for Workload Identities: GitHub Actions + PowerShell

## Introduction

This post was born from the idea of, "gee I wonder if you could create a Just-In-Time (JIT) privileged access flow using GitHub Actions?" After some experimentation, the answer is yes — and the resulting pattern is a powerful way to give automation identities just‑enough, just‑in‑time access to perform high‑value, sensitive tasks (for example, rotating Key Vault secrets) while preserving auditability and minimizing standing privilege.

This post demonstrates a practical, secure pattern for integrating PIM-like (Privileged Identity Management) functionality into a CI/CD pipeline so that automation — for example, a GitHub Actions runner — can request, use, and then release elevated privileges in a repeatable, auditable way.

Traditional Entra ID Privilidged Identity Manged (PIM) activations are useful for ad-hoc human tasks, but they arent supported for Workload Identities (at the time of writing). A programmatic PIM activation flow using Microsoft Graph and identity-first automation brings several tangible benefits:

- Repeatability and reproducibility: the activation → perform → revoke sequence is defined as code and can be replayed across tenants and environments.
- CI/CD integration: pipelines can request just‑in‑time privileges for a specific deployment run and attach PR/build metadata for clear traceability.
- Principle of least privilege: request the smallest role and shortest duration necessary for the job instead of maintaining standing privileges.
- Policy-as-code and testability: activation flows can be reviewed in pull requests, linted, and run through CI tests before applying changes to production.
- Audit and compliance: workflows produce machine-readable activation records that can be stored with build artifacts or forwarded to SIEM for longer retention.
- Faster recovery and consistent rollback: automation can detect activation failures and run deterministic rollback or remediation flows.

This repository contains a working scaffold that illustrates the pattern: PowerShell modules that uses Graph/Azure authentication patterns, a small wrapper script to request activations from a runner, and a GitHub Actions workflow that demonstrates an approval-gated activation.

Key references:

- PIM Microsoft Graph APIs: https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview?view=graph-rest-1.0

## Project summary

The implementation in this repository is geared toward CI-driven automation (GitHub Actions) and contains a few pragmatic decisions you'll see reflected throughout the module and workflow:

- Automation-first JIT: for non-human actors (managed identities or OIDC workload identities) the flow creates a temporary, scoped Azure RBAC assignment, performs the privileged operation, then removes the assignment immediately—capturing structured metadata (vault, rotated secrets, timestamps) for audit and traceability.
- Vault‑wide secret rotation: secret rotation is implemented at the vault level. `Set-PimKeyVaultSecret` enumerates all secrets in a vault with `Get-AzKeyVaultSecret -VaultName`, rotates each secret with `Set-AzKeyVaultSecret` and returns an array of rotation result objects (vault, secret, rotatedAt, secretVersion) so CI can act on and report every change.
- Clear CI reporting: the module includes `Write-PimSecretSummary`, which appends a compact Markdown table of rotated secrets to the file indicated by `GITHUB_STEP_SUMMARY` so runs that perform rotations display a readable summary in the Actions UI.
- Robust RBAC cleanup: removal code was hardened to use supported `Remove-AzRoleAssignment` parameter sets (preferring `-InputObject` and falling back to the objectId+roleDefinitionId+scope set) and to defensively handle differences in PSRoleAssignment object shapes across Az versions.
- Quiet, predictable CI logs: module imports of `Az.*` are performed with verbose output suppressed (temporary `$VerbosePreference` change plus `-Verbose:$false`) so the Actions log focuses on the steps and results rather than import chatter.
- Caller ergonomics: lifecycle functions and the run script return machine‑friendly objects and were updated to accept the multi‑secret rotation return shape so downstream jobs and artifact writers can consume rotation metadata programmatically.

Read on for how the pieces fit together and how to validate the flow in a test subscription.

## Repository structure

Key folders and files and how they fit together (paths relative to the repository root):

- `project-jit-pim/scripts/`
  - `project-jit-pim/scripts/PimAutomation.psm1` — PowerShell 7.4 module that encapsulates Graph and RBAC logic. Key functions:
    - `Get-GraphAccessToken` — prefers Azure CLI token when available; supports interactive Graph login in dev.
    - `Connect-PimGraph` — normalizes Graph connection with the token.
    - `Invoke-PimGraphRequest` — Graph v1.0/beta compatibility wrapper for GET/POST/PATCH/DELETE.
		- `Set-PimAzContext` — establishes Az PowerShell context using OIDC federated token or managed identity; required for RBAC and Key Vault operations. Imports of `Az.*` modules are intentionally performed with verbose output suppressed to keep CI logs clean.
	- `Resolve-PimRoleResourcePairs` — robust pairing of roleIds/resourceIds (zip, one-to-many, or Cartesian product).
	- `Set-PimKeyVaultSecret` — enumerates all secrets in a vault using `Get-AzKeyVaultSecret -VaultName` and rotates each secret using `Set-AzKeyVaultSecret`. The function includes Forbidden-aware retry/backoff to tolerate short RBAC propagation delays and returns an array of rotation result objects for reporting.
	- `Write-PimSecretSummary` — new helper that appends a Markdown table of rotated secrets to the `GITHUB_STEP_SUMMARY` file (when the environment variable is present), making a concise summary visible in GitHub Actions UI.
	- `New-TemporaryKeyVaultRoleAssignment` / `Remove-TemporaryKeyVaultRoleAssignment` — creates/removes a scoped RBAC assignment on the Key Vault. `Remove-TemporaryKeyVaultRoleAssignment` was hardened to use supported `Remove-AzRoleAssignment` parameter sets and defensively handle different property shapes returned by `Get-AzRoleAssignment` across Az versions.
    - `Invoke-TempKeyVaultRotationLifecycle` — orchestrates create → rotate secret → delete, and validates removal; used by CI.
	- `project-jit-pim/scripts/run-activation.ps1` — Entry point for the workflow. Imports the module, determines whether the target is a Key Vault, and runs `Invoke-TempKeyVaultRotationLifecycle` when appropriate. Emits structured JSON for the pipeline and relies on `ASSIGNEE_OBJECT_ID` from the workflow environment.

- `.github/workflows/`
  - `.github/workflows/pim-elevate.yml` — Reusable workflow that collects role/resource inputs, builds an approval table (via `project-jit-pim/scripts/build-approval.ps1`), blocks on a GitHub Environment gate, then runs the privileged step via `project-jit-pim/scripts/run-activation.ps1`.

- `project-jit-pim/infra/`
	- `project-jit-pim/infra/main.bicep` — Demo infrastructure to support the JIT scenario: provisions a user-assigned managed identity (UAMI), an RBAC-enabled Key Vault, a Microsoft Entra application and service principal using the Microsoft Graph Bicep extension, and a resource group–scoped role assignment that grants the service principal User Access Administrator at the RG scope. Emits outputs (vault name/id, identity clientId/principalId/id, Graph appId/SP id, storage account id/name) for wiring into CI.

## Scenarios / use cases

Below are practical scenarios where a CI runner (or other automation) would request a PIM-like activation via Microsoft Graph. Each example explains why a JIT activation is preferable to a permanent role assignment.

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
- Azure Resource Manager (ARM): enforces role assignments and scopes; Key Vault is configured with RBAC data-plane permissions.
- Approver(s): GitHub Environment approvers; optionally, an automated approver (Function/Logic App) or notification to external systems like Teams/Slack can be integrated later.

Flow (high level)

1) CI job starts, logs into Azure via OIDC, and gathers requested role/resource pairs.
2) CI builds a Markdown approval table (role names, resource names) and posts it to the run; job waits for GitHub Environment approval.
3) On approval, CI executes a lifecycle function that:
	- Creates a temporary Key Vault–scoped role assignment for the automation identity (for example, Key Vault Secrets Officer),
	- Performs the privileged action (e.g., rotate a secret),
	- Removes the temporary role assignment and validates removal.
4) CI records structured output (vault, rotated secrets, timestamps, secret version) as artifacts.

## Implementation

- Infrastructure: A Bicep template provisions a demo Key Vault with RBAC, a user-assigned managed identity, and emits helpful outputs (clientId, principalId, resource ids). See `infra/main.bicep`.
- Authentication: OIDC in GitHub Actions for the workflow; for local tests, you can log in interactively. Avoid long-lived secrets.
- PowerShell automation: module `scripts/PimAutomation.psm1` implements a Graph wrapper (v1.0/beta compatibility) and the lifecycle for temporary RBAC assignments and secret rotation.
- CI/CD workflow: reusable workflow `.github/workflows/pim-elevate.yml` accepts roleIds/resourceIds, builds an approval table, blocks on environment approval, then runs `scripts/run-activation.ps1` to execute the lifecycle.
- Approval automation (optional): future enhancement — an Azure Function approver for certain low-risk policies.

## Demo infrastructure: `project-jit-pim/infra/main.bicep`

What it deploys
- Storage account (for a simple demo resource)
- User-assigned managed identity (UAMI) for automation
- Azure Key Vault configured with the RBAC permission model (`enableRbacAuthorization: true`)
- Microsoft Entra application and service principal via the Microsoft Graph Bicep extension
- A role assignment at the resource group scope that grants the service principal the built-in User Access Administrator role (roleDefinitionId GUID `18d7d88d-d35e-4fb5-a5c3-7773c20a72d9`) to create/remove role assignments within the RG

Key details reflected in the template
- Graph extension imports at top of file:
	- `extension graphV1`
	- `extension graphBeta`
- Graph resources declared using `Microsoft.Graph/*@beta` types for `applications` and `servicePrincipals`.
- Role assignment uses deterministic name via `guid(...)`, `principalId: ghSp.id`, and subscription-scoped roleDefinitionId built with `subscriptionResourceId('Microsoft.Authorization/roleDefinitions', userAccessAdminRoleId)`.
- Key Vault enables RBAC model for data-plane operations to align with this JIT pattern.

Outputs (used by CI/workflows)
- Key Vault: `keyVaultName`, `keyVaultId`
- UAMI: `userIdentityClientId`, `userIdentityPrincipalId`, `userIdentityResourceId`
- Graph: `githubAppId`, `githubServicePrincipalId`, `githubServicePrincipalResourceId`
- Storage: `storageAccountId`, `storageAccountName`

Quick deploy and validate
- Ensure your Bicep CLI is up to date and the Graph Bicep extensions are enabled via `bicepconfig.json` (see next section).

```bash
az bicep upgrade

# Create a demo resource group (choose a location)
az group create --name MyDemoRG --location eastus

# Validate the template
az deployment group validate \
	--resource-group MyDemoRG \
	--template-file project-jit-pim/infra/main.bicep \
	--parameters location=eastus

# Deploy
az deployment group create \
	--resource-group MyDemoRG \
	--template-file project-jit-pim/infra/main.bicep \
	--parameters location=eastus
```

Note: The role used in the demo (`User Access Administrator`) is convenient for a JIT RBAC demo because it can create/delete role assignments. In production, choose the least-privileged role and scope that fits your policy. Built-in roles reference: https://learn.microsoft.com/azure/role-based-access-control/built-in-roles

## Using Microsoft Graph resources in Bicep (beta)

You can author Entra resources (applications / service principals) directly from Bicep using the Microsoft Graph Bicep templates. This is a preview extensibility feature in Bicep and requires two things:

- enabling Bicep extensibility in your repo-level `bicepconfig.json`, and
- importing the Microsoft Graph extension in any Bicep file that declares `Microsoft.Graph/*` resources.

What you need
- A recent Bicep CLI (or Azure CLI with the Bicep command) and the VS Code Bicep extension.
- A repo-level `bicepconfig.json` that enables the extensibility feature and maps extension aliases to the registry artifacts. Ensure `extensibility` is enabled. Example:

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

Once `bicepconfig.json` is present and extensibility is enabled, import the Graph extensions at the top of your Bicep file using the aliases defined in `bicepconfig.json`:

```bicep
// imports by alias (preferred when you've mapped the extension in bicepconfig.json)
extension graphV1
extension graphBeta

After the extension import, you can declare Microsoft Graph types in Bicep. Example (beta) — consult the Graph Bicep reference for available properties and schema:

```bicep
resource ghApp 'Microsoft.Graph/applications@beta' = {
  uniqueName: toLower('pim-github-app-${uniqueString(resourceGroup().id)}')
  displayName: 'pim-github-oidc-app-${uniqueString(resourceGroup().id)}'
  signInAudience: 'AzureADMyOrg'
}

resource ghSp 'Microsoft.Graph/servicePrincipals@beta' = {
  appId: ghApp.appId
  displayName: ghApp.displayName
}
```

Reference: Microsoft Graph Bicep templates — https://learn.microsoft.com/graph/templates/bicep/reference/serviceprincipals?view=graph-bicep-beta

Validate and deploy

See the quick commands in the previous section for validation and deployment to a resource group.

Troubleshooting and fallback strategy

- If you get "resource type is not valid" or similar validation errors, ensure:
	- Bicep CLI and the VS Code Bicep extension are up to date.
	- `bicepconfig.json` is in the repository root (or a parent folder) and contains `"experimentalFeaturesEnabled": { "extensibility": true }`.
	- The `extension` import line appears before any `Microsoft.Graph/*` resource declarations.

- Some developer or CI environments may still lack the provider metadata required to author Graph types (the extensibility path is still evolving). If your environment cannot use the Graph Bicep extension, you can adapt the template to accept `githubAppId` and `githubServicePrincipalId` as parameters and only create the role assignment when the service principal id is supplied. This lets teams either:
	1. Create the app/service principal ahead of time (via CLI or Graph APIs) and pass the returned `appId`/`principalId` into the Bicep deployment, or
	2. Enable Bicep extensibility in their dev/CI images and let the template create the app/SP directly.

Related discussion and issues: https://github.com/Azure/bicep/issues/16447


## GitHub Actions workflow: `.github/workflows/pim-elevate.yml`

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
	- Reverse lookups + approval table: Implemented by `project-jit-pim/scripts/build-approval.ps1` — resolves human-readable names/types and renders a Markdown table (IDs and names wrapped in inline code; pipes/backticks/newlines escaped). The table is posted as a comment (for PRs) or added to the job summary.
	- Gate: The job emits metadata and ends; the next job is gated by a GitHub Environment (for example, `pim-rotation-approval`).

2) approve-and-rotate
	- Gate: Requires the GitHub Environment approval. Approvers can review the comment table before proceeding.
		- Another option is to implement approval in the pull request itself (for example, require a specific label or review) and skip the Environment gate. This is left as an exercise for the reader.
	- Auth: Logs into Azure using OIDC for RBAC operations.
	- Action: Resolves role/resource pairs via the module, selects the first pair for the demo, and runs `project-jit-pim/scripts/run-activation.ps1` which orchestrates `Invoke-TempKeyVaultRotationLifecycle` to create the temporary Key Vault assignment → rotate the secret → remove the assignment → validate removal.
	- Outputs: Emits structured JSON and can publish artifacts with rotation details.

Requirements:
- A GitHub Environment configured with approvers (e.g., `pim-rotation-approval`).
- Federated identity (OIDC) configured in Azure with minimal RBAC to create/delete role assignments at the scopes you target.
- The target Key Vault must be RBAC-enabled (`enableRbacAuthorization: true`).

Notes:
- The workflow is designed to be reusable; use the demo caller as a reference for input wiring.
- For managed identities, PIM eligibility is not applicable; the workflow relies on temporary RBAC during the approved window and records rotation metadata for traceability.

## PowerShell module: `project-jit-pim/scripts/PimAutomation.psm1`

Design goals:
- PowerShell 7.4, cross-platform, non-interactive by default in CI.
- Testability: Supports an environment flag to skip live Graph calls during Pester runs.
- Clear separation between Graph (request/trace) and Azure RBAC (enforcement at resource scope).

Key functions and behavior:
- `Get-GraphAccessToken` and `Connect-PimGraph`: establish Graph access using an Azure CLI token when present; fall back to Connect-MgGraph in dev.
- `Invoke-PimGraphRequest`: sends requests to v1.0 or beta, with a predictable return shape and error handling for future Graph integrations.
- `Set-PimAzContext`: establishes Az PowerShell context using OIDC federated token or managed identity for non-interactive CI runs.
- `Resolve-PimRoleResourcePairs`: flexible pairing logic used by the workflow to map roleIds to resourceIds.
- `New-TemporaryKeyVaultRoleAssignment` and `Remove-TemporaryKeyVaultRoleAssignment`: create/delete RBAC assignments at the Key Vault scope for a specific principal (the automation identity). Output uses `RoleAssignmentId`/`RoleAssignmentName` (per Az.Resources).
- `Set-PimKeyVaultSecret`: sets or rotates a secret using Az.KeyVault under the short-lived RBAC assignment, with Forbidden-aware retry to handle eventual consistency of new role assignments.
- `Invoke-TempKeyVaultRotationLifecycle`: orchestrates the full sequence, validates removal, and returns a structured object suitable for CI logs and artifacts.

Contract (high level):
- Inputs: role definition ID, target resource ID (Key Vault), principal object ID, vault and secret names, and optional justification/metadata.
- Error modes: Graph unavailability (handled via stub/test mode), RBAC propagation delays (should be retried with backoff), and Azure API transient failures (retryable).
- Outputs: rotation metadata (vault, secret name, secret version, timestamps), RBAC assignment details (id, scope), and any contextual lifecycle information surfaced by the helper.

## Security and governance considerations

- Permissions: Use least-privilege scopes and roles; prefer RBAC scopes at the minimal resource level required.
- Authentication: Prefer OIDC for CI runners and managed identities for Azure-hosted automation; avoid long-lived client secrets.
- Approval: Require human approval (GitHub Environment) for production; optionally add policy-based automated approvals for low-risk cases.
- TTLs: Keep elevation windows as short as practical. Validate that RBAC propagation is complete before proceeding.
- Audit: Persist machine-readable activation artifacts for retention and SIEM ingestion.

## Testing and validation

- Unit tests: When you add tests, prefer Pester with Graph calls disabled via an environment flag; mock Az/Graph cmdlets to validate logic paths.
- Integration tests: Use a test subscription and a disposable Key Vault. Ensure cleanup of temporary role assignments.
- Failure modes: Validate behavior for denied approvals, RBAC propagation delays (Forbidden), and transient Azure API errors (retries with backoff).

## Demo / walkthrough — Secret / Key Rotation

This walkthrough focuses on a concrete, high-value scenario: rotating a Key Vault secret (for example, a service principal client secret or an application key) under a just-in-time privileged activation requested by the CI runner. Rotating secrets is a common operational task that requires elevated privileges and benefits from short-lived, auditable elevation.

High-level steps for the demo

1. Prerequisites
	- An Azure Key Vault configured to use the Azure RBAC permission model (`enableRbacAuthorization: true`). This allows data-plane permissions via RBAC.
	- A CI runner identity: GitHub OIDC for the workflow, or a user-assigned managed identity for Azure-hosted runs.

2. CI job starts and validates context
	- The GitHub Action runner verifies branch/ticket/PR metadata and ensures the job is allowed to request elevation (demo mode may allow auto-approvals).

3. Prepare activation context programmatically
	- The workflow calls `Resolve-PimRoleResourcePairs` to expand role/resource combinations into discrete activation targets.
	- For automation identities (managed identities), the flow focuses on short-lived RBAC assignments rather than PIM request objects, keeping the footprint minimal for CI.

4. Approval and activation
	- The reusable workflow posts an approval table and pauses at a GitHub Environment gate. Approvers can review the requested role/resource pairs before proceeding.
	- A future enhancement may add an optional automated approver (Function/Logic App) for specific policies or send notifications to Teams/Slack.

5. Rotate the secret (performed under the JIT activation)
	- The automation generates a new secret value and calls `Set-AzKeyVaultSecret` under a temporary, Key Vault–scoped RBAC assignment. The flow implemented here is:
		1. Wait for approval at the GitHub Environment gate.
		2. Create a temporary Key Vault data-plane RBAC assignment (e.g., Key Vault Secrets Officer) for the automation identity. New assignments may take a short time to propagate; the module retries on Forbidden.
		3. Perform the secret write while the assignment is active.
		4. Remove the temporary assignment and validate removal.
		5. Return rotation metadata (vault name, secret name, version, timestamps) to the caller.

	- The repository includes `scripts/PimAutomation.psm1` with helper functions and a lifecycle function `Invoke-TempKeyVaultRotationLifecycle` that orchestrates the create → rotate → delete sequence.
	- Optionally rotate dependent credentials and notify consumers in a follow-up step (future enhancement with a safe consumer-rotation harness).

6. Revoke/expire and audit
	- After the rotation completes, the activation ends (either automatically by PIM TTL or by an explicit revocation step). The pipeline records a machine-readable artifact containing activation timing, rotated secret versions, and build/PR metadata.
	- Upload that artifact to the run's artifacts and forward structured events to SIEM or a compliance store.

7. Post-rotation validation
	- Run integration smoke tests that verify the rotated secret works for consumers (use a test consumer identity and avoid printing secrets to logs).
	- If validation fails, run an automated rollback plan (store previous secret version reference and use it to restore if necessary).

## Implementation plan (detailed TODOs)

Below is a prioritized checklist that reflects current progress and what’s next.

### High priority
- [ ] Security & auth docs
	- Document required Graph scopes and approvals, and the minimal Azure RBAC roles for the GitHub OIDC principal. Provide a federated credential example.

## Conclusion

JIT elevation for automation brings the control and auditability of PIM into your delivery pipelines. By replacing standing privileges with an approval-gated, short-lived role assignment, you reduce risk without sacrificing speed. The patterns here give you a pragmatic starting point you can adapt — start with the reusable workflow and lifecycle helper, then layer in Graph-backed requests and richer approvals as you mature.

## References

- Microsoft Entra PIM docs: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure
- Microsoft Graph PIM APIs: https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview?view=graph-rest-1.0
- Azure RBAC for Key Vault: https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
- Az PowerShell: Connect-AzAccount — https://learn.microsoft.com/powershell/module/az.accounts/connect-azaccount?view=azps-latest
- Az PowerShell: Set-AzKeyVaultSecret — https://learn.microsoft.com/powershell/module/az.keyvault/set-azkeyvaultsecret?view=azps-latest
- Az PowerShell: New-AzRoleAssignment — https://learn.microsoft.com/powershell/module/az.resources/new-azroleassignment?view=azps-latest
