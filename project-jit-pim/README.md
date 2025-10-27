# Just‑In‑Time DevOps Admins — PIM + GitHub Actions for JIT role elevation

Summary
-------
Build an automated, auditable workflow that gives engineers time-bound privileged Azure access using Microsoft Entra Privileged Identity Management (PIM). The project demonstrates how to request, approve, use, and automatically revoke elevated access as part of a CI/CD run — integrating GitHub Actions, Microsoft Graph, and Azure native tooling for a secure DevOps path.

Key Entra docs
-------------
- Privileged Identity Management (PIM): https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure
- PIM Microsoft Graph APIs: https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview?view=graph-rest-1.0

Technologies
------------
- Bicep for demo infra
- GitHub Actions for CI/CD workflows
- PowerShell (Graph PowerShell module) to call Entra Graph APIs
- Azure Functions (optional) for approval webhooks
- Azure Key Vault and Microsoft.PowerShell.SecretManagement for any secrets in development

Deliverables
------------
- `infra/` Bicep templates to create demo resources (resource group, role assignable groups, app registrations)
- `scripts/` PowerShell module to request and activate PIM roles and to query audit logs
- `ci/` GitHub Actions workflow demonstrating an elevate-for-deploy run
- `docs/` step-by-step README with deployment and demo instructions
- Pester unit tests for critical PowerShell functions

Implementation steps (expanded)
-------------------------------
1. Design the demo topology
   - Identify the minimal set of Azure resources to demonstrate a privileged operation (for example: a resource group with a small role-based task such as updating a storage account or running an ARM/Bicep deployment).
   - Create a role-assignable security group that PIM will manage (this group will be the container for eligible admin membership).

2. Bicep infrastructure (infra/)
   - Write Bicep to deploy the resource group, the demo resources, an assignable group, and an app registration that will be used by automation.
   - Keep outputs: resource IDs, group objectId, and App Registration id/secret (if used only for initial provisioning; prefer federated identities later).
   - Provide a `parameters.sample.json` for local runs and CI.

3. Register Graph app and permissions
   - Register a minimal app with delegated and application permissions required to call PIM APIs (document which Graph scopes are needed). Use least-privilege and admin consent steps in the README.

4. PowerShell automation (scripts/)
   - Implement functions to: Request-PimActivation, Get-PimRequests, Approve-PimRequest (for delegated approvers), Activate-PimRole, and Monitor-PimAudit.
   - Use the Graph PowerShell module (Connect-MgGraph) with clear instructions for auth flows: interactive for dev, managed identity for automation. See https://learn.microsoft.com/powershell/microsoftgraph/authentication/connect-mggraph?view=graph-powershell-1.0
   - Return rich objects from each function (do not write formatted strings) so they are testable and consumable by CI steps.

5. GitHub Actions workflow (ci/)
   - Build a workflow that runs the following steps during a privileged deployment job:
     a. Create a PIM activation request for the runner's actor (or the service principal) with the required role and duration.
     b. Optionally wait for an approval step. Approval can be manual (approver clicks in PIM portal) or automated by calling an Approver service (Azure Function) for demo purposes.
     c. Once approved/activated, perform the privileged deployment action (example: deploy a Bicep change that modifies the target resource).
     d. Confirm role is active and record auditing metadata back to the build logs/artifacts.

6. Approval automation (optional)
   - Implement a simple Azure Function that receives a webhook from GitHub Actions or reads pending PIM requests and auto-approves them only when preconditions are met (for a demo use-case: only for a test approver group and limited hours).

7. Revoke and audit
   - Show automatic expiration by setting a short activation window in the demo and demonstrate the role becoming inactive after expiry.
   - Implement a script to pull PIM audit logs and summarize activations in a machine-readable report.

8. Tests and CI
   - Add Pester tests for the PowerShell module covering happy path and error handling (invalid request, already active, permission denied).
   - Add GitHub Actions that run the tests on push and validate Bicep with a linter (arm-ttk or Bicep lint).

Demo / validation
-----------------
- Walkthrough: create a PR that triggers the 'request elevated deploy' workflow, a reviewer approves, the workflow activates the PIM role, runs a deployment, and the role expires automatically. Capture screenshots and a recorded log.

Estimated effort
----------------
- MVP: 3–5 days. Add approval automation and tests: 1–2 weeks.

Why this fits your portfolio
---------------------------
This project aligns with your existing posts on GitHub Actions, Bicep, and managed identities. It neatly showcases identity governance applied to DevOps scenarios — a high-value, practical demonstration of least-privilege in action.

Next steps
----------
- I can scaffold the `infra/`, `scripts/`, and `ci/` subfolders with starter files and a GitHub Actions workflow next. Tell me to proceed and I will create the initial Bicep and PowerShell stubs.
