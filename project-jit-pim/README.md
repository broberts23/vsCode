# Just‑In‑Time RBAC for Workload Identities — GitHub Actions + PowerShell

Summary
-------
A working reference implementation that demonstrates just-in-time (JIT), just-enough privilege access for automation identities in Azure CI/CD pipelines. The project focuses on practical, production-ready patterns: temporary, scoped RBAC assignments guarded by approval gates, with machine-readable audit trails. It integrates GitHub Actions, Azure RBAC, Key Vault, and PowerShell 7.4 for a secure, auditable automation workflow.

This is not traditional Entra PIM (which does not yet support workload identities at time of writing), but rather a programmatic alternative using RBAC lifecycle automation that achieves the same goals: time-limited privileges, approval gating, and full auditability.

Key Entra & Azure docs
------
- Azure RBAC for Key Vault: https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
- Azure role assignments: https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments
- Entra Workload Identity Protection: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust
- PIM Microsoft Graph APIs (for future enhancement): https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview?view=graph-rest-1.0

Technologies
------------
- **PowerShell 7.4** for cross-platform automation logic
- **Bicep** for demo infrastructure (Key Vault, managed identity, RBAC)
- **GitHub Actions** for approval-gated CI/CD workflows
- **Azure CLI** and **Az PowerShell modules** for RBAC and Key Vault operations
- **OIDC** for federated identity (no secrets required)
- **Pester 5.x** for unit testing

Project contents
----------------
- **blog.md** — Comprehensive blog post explaining the JIT architecture, scenarios, implementation details, and security considerations. Start here for context.
- **infra/main.bicep** — Bicep template provisioning a demo Key Vault (RBAC-enabled), user-assigned managed identity, and service principal via Microsoft Graph Bicep extension.
- **scripts/PimAutomation.psm1** — PowerShell 7.4 module encapsulating RBAC and Key Vault lifecycle logic:
  - `Set-PimAzContext` — Azure authentication via OIDC or managed identity
  - `Resolve-PimRoleResourcePairs` — Pairing logic (zip, one-to-many, or Cartesian product)
  - `New-TemporaryKeyVaultRoleAssignment` / `Remove-TemporaryKeyVaultRoleAssignment` — RBAC create/delete lifecycle
  - `Set-PimKeyVaultSecret` — Secret rotation with Forbidden-aware retry
  - `Invoke-TempKeyVaultRotationLifecycle` — Full orchestration: create → rotate → delete
  - `Write-PimSecretSummary` — Markdown table writer for GitHub Actions summaries
- **scripts/run-activation.ps1** — Entry point for the workflow. Parses environment, imports the module, and orchestrates the rotation lifecycle.
- **scripts/build-approval.ps1** — Builds a Markdown approval table from role/resource pairs.
- **scripts/debug_invoke.ps1** — Demonstration helper showing `Resolve-PimRoleResourcePairs` in action.
- **tests/PimAutomation.Tests.ps1** — Pester unit tests covering role/resource pairing logic.
- **.github/workflows/pim-elevate.yml** — Reusable GitHub Actions workflow (request-elevation + approve-and-rotate jobs)

Architecture & workflow
-----------------------
The workflow follows a simple, auditable pattern:

1. **CI/CD trigger**: GitHub Actions job starts and gathers role/resource pairs (e.g., Key Vault Secrets Officer + Key Vault resource ID).
2. **Pairing & approval table**: `Resolve-PimRoleResourcePairs` expands the pairs, and `build-approval.ps1` renders a Markdown table showing exactly what will be elevated.
3. **GitHub Environment gate**: Job pauses; approvers review the table and approve or deny.
4. **Elevation phase** (on approval):
   - Create a temporary Key Vault–scoped RBAC assignment for the automation identity.
   - Wait briefly for RBAC propagation (retries on Forbidden).
   - Perform the privileged action (e.g., rotate a secret).
   - Remove the assignment and validate removal.
5. **Audit & reporting**: Structured output (vault name, secret name, version, timestamps) is emitted as JSON and can be published to artifacts.

Key design principles:
- **No long-lived secrets**: OIDC for GitHub Actions; managed identity for Azure-hosted workloads.
- **Time-bounded access**: RBAC assignments created just-in-time and removed immediately.
- **Approval-gated**: GitHub Environments provide human oversight; future enhanceable with policy-based auto-approval for low-risk cases.
- **Auditable**: Every step is logged; rotation metadata can be forwarded to SIEM or compliance stores.
- **Testable**: PowerShell functions return rich objects; Pester tests validate logic paths.
