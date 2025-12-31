# project-access-reviews-autopilot

An “autopilot” pattern for **Microsoft Entra access reviews** that keeps privileged access continuously recertified with minimal manual overhead. This project focuses on:

- defining access reviews as code
- automating reminders and decision collection workflows
- applying decisions (where appropriate)
- exporting auditable history

Access reviews cover principals including **users and service principals**, and resources including **groups, applications (service principals), access packages, and privileged roles**.

- API overview: https://learn.microsoft.com/en-us/graph/api/resources/accessreviewsv2-overview?view=graph-rest-1.0

## Goals

- Make privileged access recertification **repeatable** and **auditable**.
- Provide “day-2” automation:
  - start reviews on schedule
  - send reminders
  - apply decisions
  - export review history for compliance
- Keep the automation deterministic and idempotent.

This project assumes the “autopilot” runs as an **Azure Functions** app (Timer trigger for scheduled runs, HTTP trigger for manual runs), using Microsoft Graph to manage Access Reviews.

## Non-goals

- Replacing human reviewers. This automates orchestration and evidence handling.
- Building a UI for review decisions (use Entra portal / established reviewer flows).

## Suggested repo layout

```text
project-access-reviews-autopilot/
├── README.md
├── docs/
│   ├── DESIGN.md                      # deeper design notes (optional)
│   ├── CONTROLS.md                    # audit controls mapping
│   └── RUNBOOK.md                     # ops runbook
├── config/
│   ├── reviews.json                   # source-of-truth review definitions
│   ├── reviewers.json                 # reviewer routing rules (optional)
│   └── scopes.json                    # what to review (roles/groups/apps)
├── FunctionApp/
│   ├── host.json
│   ├── local.settings.json             # local-only (do not commit secrets)
│   ├── profile.ps1                     # PowerShell worker profile
│   ├── requirements.psd1               # module dependencies
│   ├── AccessReviewsAutopilotTimer/
│   │   ├── function.json               # TimerTrigger schedule
│   │   └── run.ps1                     # scheduled autopilot run
│   ├── AccessReviewsAutopilotHttp/
│   │   ├── function.json               # HttpTrigger (manual run)
│   │   └── run.ps1
│   └── Shared/
│       ├── Invoke-Graph.ps1
│       ├── Normalize-Definition.ps1
│       └── New-CorrelationKey.ps1
├── infra/
│   ├── main.bicep                     # optional: storage/logs, function/job runner
│   └── parameters.dev.json
├── scripts/
│   ├── Deploy-Infrastructure.ps1       # provisions infra + function app
│   └── Deploy-FunctionCode.ps1         # publishes function code
├── tests/
│   └── Unit/
│       ├── Compare-AraState.Tests.ps1
│       └── New-CorrelationKey.Tests.ps1
```

## High-level design

## How this differs from Entra Access Reviews (MyAccess)

This project does not replace the Entra Access Reviews feature or the MyAccess decisioning experience. It’s an automation layer that helps you run Access Reviews like a continuous control with code, scheduling, drift detection, and evidence packaging.

- Source of truth

  - Entra/MyAccess: reviews are configured primarily via portal workflows.
  - Autopilot: review definitions live as code (for example `config/reviews.json`) so they can be PR-reviewed, versioned, and recreated consistently.

- Provisioning + drift control

  - Entra/MyAccess: doesn’t provide a general “desired state vs current state” drift loop across all your review definitions.
  - Autopilot: periodically compares “what should exist” vs “what exists”, reports drift, and can optionally remediate by creating/updating definitions.

- Orchestration at scale (beyond built-in reminders)

  - Entra/MyAccess: sends reminders within each review; reviewers act in the portal.
  - Autopilot: orchestrates across many reviews/instances in bulk (for example scheduled runs that ensure required privileged reviews exist and are active).

- Evidence packaging (audit-ready outputs)

  - Entra/MyAccess: audit history and exports are available, but evidence collection is usually manual when auditors ask.
  - Autopilot: automatically exports/archives review history (plus run summaries) on a schedule into controlled storage/artifacts.

- Guardrails on automation risk

  - Entra/MyAccess: supports applying decisions/recommendations where configured.
  - Autopilot: treats any “auto-apply” as an explicit policy decision (ideally gated/approved) and keeps it off by default.

- Integration points
  - Entra/MyAccess: portal-centric workflow.
  - Autopilot: integrates with CI/CD and operational workflows (issues/tickets/alerts) while still routing humans to MyAccess for decisions.

### Desired state and idempotency

- `config/reviews.json` is the source of truth.
- Each review definition is tracked using a **correlation key** (for example, `reviewKey`) stored in:
  - `displayName` convention (prefix) and/or
  - `description` metadata block (JSON)

The automation must be able to run repeatedly without creating duplicates:

- if a definition exists → update it
- if it doesn’t exist → create it

### What the autopilot actually automates

1. **Provision review definitions** (policy-as-code).
2. **Operational loop**:
   - find active instances
   - send reminders (`sendReminder`)
   - optionally accept/apply recommendations where your governance policy allows
   - generate audit artifacts (history exports)

In an Azure Functions deployment this loop typically runs from:

- a **Timer trigger** for scheduled orchestration
- an **HTTP trigger** for manual/operational runs (for example, “run now” or “export evidence now”)

### Recommended operating model

- Reviewers are still humans.
- Autopilot reduces toil:
  - ensures reviews exist for the right privileged surfaces
  - ensures reviewers get nudged
  - ensures decisions are applied on time
  - produces evidence exports for auditors

### Graph API usage

The access reviews API provides endpoints to:

- create/update/delete review definitions
- list instances
- send reminders
- reset decisions
- apply decisions
- bulk record decisions
- export history via download URIs

Start with `v1.0` endpoints where possible.

References:

- Access reviews API overview: https://learn.microsoft.com/en-us/graph/api/resources/accessreviewsv2-overview?view=graph-rest-1.0

PowerShell auth + raw calls:

- Connect-MgGraph: https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0
- Invoke-MgGraphRequest: https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/invoke-mggraphrequest?view=graph-powershell-1.0

### Permissions and roles

Access reviews require tenant licensing and appropriate permissions.
At a minimum, expect:

- Graph application permission in the Access Reviews space (for example `AccessReview.ReadWrite.All` for create/update/delete).
- If using delegated auth for operators, Entra directory roles may be required (per the API docs).

See “Role and application permission authorization checks”:

- https://learn.microsoft.com/en-us/graph/api/resources/accessreviewsv2-overview?view=graph-rest-1.0#role-and-application-permission-authorization-checks

### Evidence and audit artifacts

Outputs (recommended):

- JSON summary per run (counts, review IDs, status)
- exported access review history download URIs
- optional storage of exported CSV/JSON in blob storage

### Failure handling

- Treat Graph calls as retriable for transient failures.
- Keep a dead-letter list of review IDs that need manual attention.
- Never auto-apply decisions unless your policy explicitly allows it.

## Local dev loop

Typical commands:

- `pwsh ./scripts/Deploy-Infrastructure.ps1`
- `pwsh ./scripts/Deploy-FunctionCode.ps1`
- `func start`

## Security notes

- Prefer workload identity (OIDC) for CI.
- Avoid storing privileged identifiers (role IDs, group IDs) outside the repo unless required; treat config as sensitive.
- Keep a clear approval step for any automation that applies decisions.
