# project-workload-identity-conditional-access-guardrails

Guardrails-as-code for **Microsoft Entra Conditional Access for workload identities** (service principals). This project is intended to be a repeatable, reviewable way to **deploy, validate, and drift-detect** Conditional Access policies that target workload identities.

This specifically showcases **Conditional Access for workload identities** and (optionally) **service principal risk** conditions.

- Reference: https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity

## Goals

- Treat workload identity Conditional Access policies as **version-controlled configuration**.
- Add **pre-merge / pre-deploy validation** so unsafe policy changes are caught before they reach a tenant.
- Provide a **safe deployment path**: `report-only` → validate → enforce.
- Detect and remediate **policy drift**.
- Keep permissions and blast radius small (least privilege, scoped identities).

## Non-goals

- End-user Conditional Access policy management.
- Full “policy DSL” for every CA feature; start with the workload identity surface area.

## Suggested repo layout

```text
project-workload-identity-conditional-access-guardrails/
├── README.md
├── docs/
│   ├── DESIGN.md                    # deeper design notes (optional)
│   └── RUNBOOK.md                   # ops runbook: rollout, rollback
├── ci/
│   ├── policy-lint/                  # local + pipeline linting rules
│   └── testdata/                     # fixtures for unit tests
├── policies/
│   ├── guardrails.json              # desired state (source of truth)
│   ├── examples/                    # sample policies for common patterns
│   └── schema/                      # optional JSON schema + validation helpers
├── scripts/
│   ├── Install-Dependencies.ps1
│   ├── Export-WorkloadIdCaPolicies.ps1
│   ├── Test-WorkloadIdCaPolicies.ps1
│   ├── Invoke-WorkloadIdCaPolicyLint.ps1
│   ├── Invoke-WorkloadIdCaDryRun.ps1
│   ├── Set-WorkloadIdCaPolicies.ps1
│   └── Invoke-WorkloadIdCaDriftRemediation.ps1
├── src/
│   └── WorkloadIdCAGuardrails/
│       ├── WorkloadIdCAGuardrails.psd1
│       ├── WorkloadIdCAGuardrails.psm1
│       ├── Public/
│       │   ├── Get-WicagDesiredState.ps1
│       │   ├── Get-WicagCurrentState.ps1
│       │   ├── Compare-WicagState.ps1
│       │   └── Set-WicagState.ps1
│       └── Private/
│           ├── Invoke-GraphBeta.ps1
│           ├── Normalize-PolicyObject.ps1
│           └── Test-PolicyInvariant.ps1
├── infra/
│   ├── main.bicep                   # optional: storage/logs, identity, function/job runner
│   └── parameters.dev.json
├── tests/
│   └── Unit/
│       ├── Compare-WicagState.Tests.ps1
│       └── Test-WorkloadIdCaPolicies.Tests.ps1
└── workflows/
    ├── ci.yml                       # lint + unit tests
    └── deploy.yml                   # gated deploy to tenant
```

You can keep this “scripts-only” to start; `infra/` becomes useful if you want an Azure-hosted drift detector (Function App / Container Apps job).

## High-level design

### Pre-merge / pre-deploy validation (gatekeeper features)

In addition to continuously reconciling desired state, this project includes a “gatekeeper” layer to prevent unsafe changes from being merged or deployed.

Typical validation stages:

1. **Schema + shape validation**

- Validate `policies/guardrails.json` structure, required fields, and supported workload identity CA properties.
- Normalize and validate deterministic keys (`policyKey`) and naming conventions.

2. **Safety lint rules** (fail fast)

- Block overly broad targeting (for example: “all service principals” unless explicitly allowed).
- Flag risky exclusions/allowlists.
- Require at least one “escape hatch” operational plan (break-glass runbook link / disable procedure).
- Require `report-only` for new or materially-changed policies unless explicitly overridden.

3. **Coverage checks for targeted workloads**

- Ensure each in-scope service principal (or “workload tier”) is covered by at least one guardrail policy.
- Ensure each policy’s include/exclude lists resolve to valid service principal IDs.

4. **Dry-run against a non-production tenant (optional but recommended)**

- Fetch current state from a dev/test tenant.
- Compute the diff that would be applied.
- Enforce guardrails like “no deletes by default” and “destructive changes require allowlist”.

5. Integrate with sign-in simulation (optional)

- Build a small harness that simulates sign-in attempts using different client types and signals to validate the effect of a policy before applying it.

6. Tests and CI
   - Unit tests for the validator and integration tests that assert the scripts can fetch policy state and detect changes.

These checks are designed to run both locally (`./scripts`) and in a pipeline (`workflows/ci.yml`), so policy changes get reviewed like code.

### Desired state model

- `policies/guardrails.json` is the source of truth.
- Each policy is identified by a stable key (recommended):
  - `displayName` + a `metadata` object containing a deterministic `policyKey`.
- The module normalizes “desired” and “current” into a canonical shape before diffing.

### Deployment workflow

1. **Read desired state** (`guardrails.json`).
2. **Fetch current state** from Microsoft Graph.
3. **Diff** (create/update/delete) with guardrails:
   - never delete by default unless explicitly enabled
   - require an explicit allowlist of policy keys for destructive changes
4. **Apply** changes:
   - stage as `enabledForReportingButNotEnforced`
   - validate via sign-in logs / expected evaluation
   - flip to `enabled` (enforced) when ready

### Drift detection

- Scheduled job (GitHub Actions or Azure-hosted) re-runs the diff:
  - if drift is detected, create an issue / alert
  - optionally auto-remediate in report-only mode first

### Graph API usage

Microsoft’s workload identity CA documentation includes sample JSON using the **Microsoft Graph beta endpoint**.

Recommended approach:

- Use `Connect-MgGraph` for auth.
- Use `Invoke-MgGraphRequest` to call the beta endpoints when required.

Microsoft Learn:

- Connect-MgGraph: https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0
- Invoke-MgGraphRequest: https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/invoke-mggraphrequest?view=graph-powershell-1.0

### Identity + permissions

Recommended identities:

- **CI/CD**: service principal using federated credentials (OIDC).
- **Azure-hosted drift detector**: managed identity.

Minimum Graph permissions depend on operations performed. For Conditional Access policy management, expect to need Graph permissions in the **Conditional Access policy** area (for example, a `Policy.ReadWrite.*` permission related to Conditional Access).

Operationally:

- Scope execution to a dedicated “automation” app registration.
- Keep a break-glass process to disable policies quickly.

## Configuration example (concept)

Your `policies/guardrails.json` typically expresses:

- workload identity targets (service principal object IDs)
- allowed named locations
- conditions (including service principal risk levels)
- grant controls: currently **Block** is the key enforcement control for workload identity policies

See the workload identity Conditional Access reference JSON:

- https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity#microsoft-graph

## Local dev loop

- Install PowerShell modules and run unit tests.
- Dry-run a diff against your tenant.
- Apply in report-only.

Typical commands:

- `pwsh ./scripts/Install-Dependencies.ps1`
- `pwsh ./scripts/Test-WorkloadIdCaPolicies.ps1`
- `pwsh ./scripts/Set-WorkloadIdCaPolicies.ps1 -Mode ReportOnly`

## Security notes

- Never store secrets in repo; prefer OIDC federated credentials.
- Treat `guardrails.json` as sensitive configuration (it can reveal internal IP ranges / named locations).
- Use least-privileged roles and separate dev/test tenants where possible.
