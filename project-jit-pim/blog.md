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

TODO: Expand with a short narrative about identity governance, least-privilege, and why JIT for automation matters. Include examples from real operations teams and a brief comparison to alternate approaches (service principal with secrets, long-lived Contributor roles, etc.).

## Architecture overview

TODO: Add architecture diagram and narrative describing the actors: GitHub Actions runner (or other CI), automation app registration (Graph), PIM service, approver roles, and optional Azure Function approver. Describe data flows for interactive vs non-interactive auth (delegated vs app-only) and where logs & artifacts are stored.

## Implementation plan

This section will be expanded into subpages. For now, the top-level plan:

- Infra: Bicep templates to create demo resources (resource group, storage account, assignable groups). See `infra/main.bicep`.
- App registration & auth: register an app with minimal Graph scopes (document required scopes), prefer OIDC/managed identity for CI to avoid secrets.
- PowerShell automation: implement a module (scripts/PimAutomation.psm1) with functions to create activation requests, poll status, and activate roles.
- CI/CD workflow: GitHub Actions workflow that requests elevation, waits for approval (or calls an automated approver), runs the privileged job, then uploads activation record as an artifact.
- Approval automation (optional): lightweight Azure Function to auto-approve low-risk requests based on policy.

TODO: Expand each sub-item with step-by-step commands, sample payloads, and troubleshooting tips.

## Security and governance considerations

TODO: Document license requirements (Entra P1/P2), required Graph scopes and consent steps, least-privilege recommendations, approval policies (auto vs manual), TTL recommendations, telemetry/retention, and SIEM integration patterns.

## Testing and validation

TODO: Add concrete Pester tests, integration test harness examples, and a plan for staging vs production testing. Include tests for throttling, failure/retry behavior, and TTL enforcement.

## Demo / walkthrough — Secret / Key Rotation

This walkthrough focuses on a concrete, high-value scenario: rotating a Key Vault secret (for example, a service principal client secret or an application key) under a just-in-time privileged activation requested by the CI runner. Rotating secrets is a common operational task that requires elevated privileges and benefits from short-lived, auditable elevation.

High-level steps for the demo

1. Prerequisites
	- An Azure Key Vault configured to use the Azure RBAC permission model (the demo `infra/main.bicep` now sets `enableRbacAuthorization: true`). This lets us manage Key Vault data-plane permissions via role assignments and PIM.
	- An automation app or runner identity capable of requesting PIM activations (register an app and grant the minimal Graph scopes, or set up GitHub OIDC federation). TODO: document exact Graph scopes and consent steps.
	- Appropriate PIM licensing for your tenant (Entra P1/P2 may be required for some features).

2. CI job starts and validates context
	- The GitHub Action runner verifies branch/ticket/PR metadata and ensures the job is allowed to request elevation (demo mode may allow auto-approvals).

3. Create a PIM activation request programmatically
	- The pipeline calls `New-PimActivationRequest` (or a wrapper) including: roleId (the privileged role required to update Key Vault access policy or perform secret write), resourceId (the subscription/resource scope), justification (PR/issue id), and requested duration.
	- TODO: Replace the module stub with real Microsoft Graph PIM API calls in `scripts/PimAutomation.psm1`.

4. Approval and activation
	- For the demo, we run in `Demo` mode which simulates immediate approval. In production, the workflow should poll the request status or receive an approval webhook (Azure Function) before proceeding.
	- TODO: Add an Azure Function approver stub and instructions for configuring approver users/groups.

5. Rotate the secret (performed under the JIT activation)
	- The automation generates a new secret value (the demo code generates a random token but does not emit it to logs).
	- The automation updates the secret in Key Vault (production: use `Set-AzKeyVaultSecret` or the REST API). The demo implements a JIT pattern where the pipeline:
		1. Creates a PIM activation request via Microsoft Graph (stubbed in the repo).
		2. Waits for the request to be approved/activated.
		3. Creates a temporary Azure RBAC role assignment on the Key Vault (for example `Key Vault Secrets Officer`), scoped to the Key Vault resource.
		4. Performs the secret write using the automation principal while the role assignment is active.
		5. Removes the temporary role assignment.

	- The repository includes `scripts/PimAutomation.psm1` with helper functions to create and remove role assignments and an orchestration function `Rotate-KeyVaultSecretWithPim` that demonstrates the full flow. This keeps no standing data-plane permissions for the automation principal.
	- The pipeline optionally rotates dependent credentials (for example, update app registrations or notify consumers). TODO: provide a safe consumer-rotation pattern and test harness.

6. Revoke/expire and audit
	- After the rotation completes, the activation ends (either automatically by PIM TTL or by an explicit revocation step). The pipeline records a machine-readable artifact containing the requestId, activatedAt, completedAt, rotatedSecretVersion (Key Vault secret version or id), and build/PR metadata.
	- Upload that artifact to the run's artifacts and forward structured events to SIEM or a compliance store.

7. Post-rotation validation
	- Run integration smoke tests that verify the rotated secret works for consumers (use a test consumer identity and avoid printing secrets to logs).
	- If validation fails, run an automated rollback plan (store previous secret version reference and use it to restore if necessary).


Guidance and TODOs

- Done: `infra/main.bicep` now creates a Key Vault with `enableRbacAuthorization: true` (RBAC model).
- TODO: Implement Microsoft Graph PIM calls in `scripts/PimAutomation.psm1` to create activation requests, poll status, and (when available) programmatically activate roles. These APIs live in Microsoft Graph under the privilegedAccess/azureResources surface (may require beta APIs for some operations). See: https://learn.microsoft.com/graph/api/resources/privilegedaccess?view=graph-rest-1.0
- TODO: Replace the interactive Graph auth with non-interactive CI patterns — prefer GitHub Actions OIDC federation to a service principal or use an Azure-hosted runner with managed identity. Document required Graph scopes and admin consent steps.
- Done: The PowerShell module now attempts to call Microsoft Graph PIM endpoints (beta) when a Graph access token is available. The module obtains tokens from the Azure CLI (which the workflow gets by logging in via Azure OIDC) or falls back to interactive Connect-MgGraph.

- Required Graph permissions (examples):
	- Role Management: "RoleManagement.ReadWrite.Directory" (application or delegated depending on flow). See: https://learn.microsoft.com/graph/permissions-reference
	- Privileged Access / PIM surfaces: may require the PrivilegedAccess Graph permissions which are often under beta and require admin consent.

- GitHub Actions OIDC: the example workflow shows use of `azure/login` with OIDC; in production you should configure a federated credential on your Azure AD app registration and avoid long-lived client secrets. See: https://learn.microsoft.com/azure/developer/github/connect-from-azure

- Quick CI wiring example (what to set in your repo secrets or pipeline):
	- `ASSIGNEE_OBJECT_ID` — objectId of the automation principal (the service principal / managed identity performing the rotation)
	- `VAULT_RESOURCE_ID` — full resource id of the Key Vault (e.g. `/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<name>`)

Notes on stability: Microsoft Graph PIM APIs often live in the beta surface and may change; test in a non-production tenant and consider mocking for unit tests. See: https://learn.microsoft.com/graph/overview
- TODO: Add robust error handling and retry logic around role assignment creation and removal to handle propagation delays.
- TODO: Add Pester integration tests that mock Graph and Az role assignment calls, plus an integration test that runs against a disposable test subscription and cleans up role assignments.

Notes on Key Vault RBAC and role IDs

- The demo uses the built-in "Key Vault Secrets Officer" role for data-plane secret writes. Its role definition id is: `b86a8fe4-44ce-4948-aee5-eccb2c155cd7` (see https://learn.microsoft.com/azure/key-vault/general/rbac-guide).
- To create/remove role assignments programmatically the caller needs `Microsoft.Authorization/roleAssignments/write` and `Microsoft.Authorization/roleAssignments/delete` (for example Owner, User Access Administrator, or Key Vault Data Access Administrator).

Security note

- Switching the Key Vault to the RBAC model invalidates access policies defined on the vault. Don't enable RBAC without ensuring equivalent role assignments exist for required actors; otherwise you can cause outages.

The repository includes a demo stub for the rotation flow (see `scripts/run-activation.ps1` and `scripts/PimAutomation.psm1`) which the following CI workflow can exercise in demo mode. Replace the stubs with real Graph/Key Vault calls according to your environment before using in production.

## Operational runbook

TODO: Add playbooks for common operational tasks: emergency activation, manual revoke, escalation, and how to audit activations in Entra and Graph.

## Next steps and roadmap

TODO: List incremental improvements and stretch goals such as:
- Replace PowerShell stubs with real Graph PIM API calls
- Add GitHub OIDC federated credential example
- Implement automated approver with conditional logic
- Create a dashboard to surface activation metrics and audit summaries

## References

- Microsoft Entra PIM docs: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure
- Microsoft Graph PIM APIs: https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview?view=graph-rest-1.0
