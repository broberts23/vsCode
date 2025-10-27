# Workload Identity Automation — federated workload IDs + CI/CD integration

Summary
-------
Replace long-lived service principal secrets with federated workload identities for GitHub Actions and AKS workloads. Show how to create federated credentials, configure OIDC flows from GitHub and Kubernetes workloads, and validate secretless access patterns across CI/CD and runtime.

Key Entra docs
-------------
- Workload Identity Federation overview: https://learn.microsoft.com/en-us/azure/active-directory/workload-identities/workload-identity-federation-overview

Technologies
------------
- Bicep for app registrations and federated credentials
- GitHub Actions OIDC provider configuration
- AKS Workload Identity (aad-pod-identity replacement) or Azure AD Workload Identity integration
- PowerShell or bash scripts for validation

Deliverables
------------
- `infra/` Bicep templates that create app registrations and federated credentials
- `ci/` GitHub Actions example using OIDC to obtain tokens
- `k8s/` example manifests for AKS workload identity and demo pod
- `scripts/` validation scripts that confirm tokens and permissions

Implementation steps (expanded)
-------------------------------
1. Plan target trust relationships
   - Decide which actors will be trusted: GitHub repositories (repo-level OIDC), a GitHub organization, and AKS service accounts.
   - Define required app roles or resource scopes the workloads will need.

2. Bicep to create App Registration and Federated Credential (infra/)
   - Create an App Registration for the demo application and add federated credentials using the Microsoft Graph or Bicep resource types.
   - Emit values that the CI and AKS manifests will consume (clientId, tenantId, federated credential IDs).

3. GitHub Actions OIDC login (ci/)
   - Create a sample workflow that uses the `azure/login` action with `client-id` and `tenant-id` replaced by federated app values to obtain tokens via OIDC — no secrets stored.
   - Demonstrate using the token to run az CLI commands or to call Azure REST APIs.

4. AKS workload integration (k8s/)
   - Provide manifests showing how to create a Kubernetes ServiceAccount bound to an Azure federated credential and a sample pod that requests a token to access Key Vault or Storage.

5. Validation scripts (scripts/)
   - Add scripts that verify the token is valid, review claims (iss/aud/exp), and call Microsoft Graph or Azure Resource Manager to perform a read/write action.

6. Documentation and migration guidance
   - Include migration notes showing how to transition from service principals to workload identity, how to remove secrets, and how to audit and roll back if needed.

7. Tests and CI
   - Unit-test any helper scripts and create an end-to-end GitHub Action that runs the OIDC login and performs a simple ARM read operation.

Demo / validation
-----------------
- Show a GitHub Action that performs an ARM deployment using OIDC without secrets and an AKS pod that reads a secret from Key Vault using workload identity.

Estimated effort
----------------
- MVP: 3–6 days.

Why this fits your portfolio
---------------------------
This project directly extends your API Authentication and AKS posts and demonstrates modern, secretless authentication techniques that are highly sought after.

Next steps
----------
- I can scaffold `infra/`, `ci/`, `k8s/` and `scripts/` with stub files and a working sample GitHub Actions workflow.
