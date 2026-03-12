# Unified Tenant Configuration Management (UTCM) APIs (Microsoft Graph) — drift detection that feels like IaC

## Introduction

Tenant configuration drift is rarely dramatic when it happens.

It’s usually one toggle flipped “temporarily”, one policy paused “until the incident is over”, one exception granted “just for this project”. The dangerous part is what comes next: nobody remembers the change, and months later you’re debugging symptoms instead of controlling intent.

Unified Tenant Configuration Management (UTCM) is a Microsoft Graph capability designed to make this problem feel like modern infrastructure-as-code:

- Declare a **desired configuration** (a *baseline*).
- Create a periodic **monitor** that checks for **drift**.
- Use the results to drive alerts, dashboards, and CI/CD gates.

This project is a practical, PowerShell-first walk-through of that pattern.

> Important: UTCM is currently exposed through **Microsoft Graph `/beta`** APIs. `/beta` APIs are subject to breaking changes, and **use of `/beta` APIs in production applications is not supported**.
> See <https://learn.microsoft.com/en-us/graph/versioning-and-support#beta-version>

## Prerequisites

This repo’s scripts assume:

- PowerShell 7.4+
- Microsoft Graph PowerShell SDK
  - Install guide: <https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0>
  - `Connect-MgGraph`: <https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0>
  - Auth patterns and `Invoke-MgGraphRequest`: <https://learn.microsoft.com/en-us/powershell/microsoftgraph/authentication-commands?view=graph-powershell-1.0>

Permissions note:

- Microsoft Graph permissions are required for the caller (delegated or application) depending on the operation.
- The permission model is explained here: <https://learn.microsoft.com/en-us/graph/permissions-overview>

## What UTCM is (the mental model)

UTCM’s core objects are:

- `configurationMonitor`: “run this check every $N$ hours” + an embedded desired state
  - Resource type reference: <https://learn.microsoft.com/en-us/graph/api/resources/configurationmonitor?view=graph-rest-beta>
- `configurationBaseline`: “this is what the configuration should look like”
  - Resource type reference: <https://learn.microsoft.com/en-us/graph/api/resources/configurationbaseline?view=graph-rest-beta>
- `configurationMonitoringResult`: “here’s how the last run went” (including drift counts)
  - Resource type reference: <https://learn.microsoft.com/en-us/graph/api/resources/configurationmonitoringresult?view=graph-rest-beta>
- `configurationDrift`: “here are the properties that drifted”
  - Resource type reference: <https://learn.microsoft.com/en-us/graph/api/resources/configurationdrift?view=graph-rest-beta>

You can treat those like you treat deployment objects in IaC:

- The baseline is your “spec”.
- The monitor is your “controller loop”.
- Drifts/results are your “telemetry and gates”.

## The two-layer authorization model (why your monitor can exist but still fail)

There are two distinct permission layers in most real UTCM deployments:

1) **The caller** (human or automation) must be authorized to create/update monitors, create snapshot jobs, and read results.

2) The **UTCM service** itself must be able to read (and sometimes write) the underlying workload configuration. In practice, this typically means the UTCM service principal in your tenant must be granted workload permissions/roles.

When layer #1 is correct but layer #2 is missing, you can create a monitor successfully but still see failures in monitoring results because UTCM can’t evaluate the workload.

## Repository structure

Everything here is intentionally simple:

- `samples/monitors/*.json`: baseline-as-code definitions (the “desired state” checked in to source control)
- `scripts/Connect-UtcmGraph.ps1`: connect to Graph using interactive, device code, app-only certificate, or managed identity flows
- `scripts/Apply-UtcmMonitor.ps1`: create or update a monitor from a JSON file
- `scripts/Get-UtcmMonitorHealth.ps1`: query the latest run + active drifts (and optionally fail the run)
- `scripts/New-UtcmSnapshotJob.ps1`: kick off snapshot extraction jobs

## Use case 1 — “Stop external access drift” (Teams federation configuration)

### Story (Teams federation)

Your security team has a clear policy: external federation is allowed, but only for an approved partner allow-list.

Then a customer project hits a deadline. A well-meaning admin loosens external access “for a week” to unblock collaboration.

Three weeks later, the project is done… but the setting never got reverted.

Nobody notices until a different incident forces the question: “When did we start allowing anyone to federate?”

### The desired state (Teams federation)

The desired state is a baseline that continuously monitors Teams federation configuration properties. In this repo, that baseline lives as JSON so it can be reviewed like any other code change.

- Example: `samples/monitors/teams-federationConfiguration.monitor.json`

At a high level, a monitor embeds a baseline (baseline contains one or more resources; each resource contains the set of properties to track).

- `configurationMonitor`: <https://learn.microsoft.com/en-us/graph/api/resources/configurationmonitor?view=graph-rest-beta>
- `configurationBaseline`: <https://learn.microsoft.com/en-us/graph/api/resources/configurationbaseline?view=graph-rest-beta>

### Apply the monitor (PowerShell)

Connect:

```powershell
pwsh -File .\scripts\Connect-UtcmGraph.ps1 -Interactive
```

Create (or apply) the monitor:

```powershell
pwsh -File .\scripts\Apply-UtcmMonitor.ps1 -MonitorJsonPath .\samples\monitors\teams-federationConfiguration.monitor.json
```

### How drift shows up

When a monitor runs, it produces a monitoring result with a drift count:

- `configurationMonitoringResult`: <https://learn.microsoft.com/en-us/graph/api/resources/configurationmonitoringresult?view=graph-rest-beta>

And for the “what changed?” detail, you query the drift objects:

- `configurationDrift`: <https://learn.microsoft.com/en-us/graph/api/resources/configurationdrift?view=graph-rest-beta>

In this repo, the health script gives you the latest run and the active drifts:

```powershell
pwsh -File .\scripts\Get-UtcmMonitorHealth.ps1 -MonitorId <monitorId>
```

If you want this as a pipeline gate:

```powershell
pwsh -File .\scripts\Get-UtcmMonitorHealth.ps1 -MonitorId <monitorId> -FailOnDrift
```

## Use case 2 — “Update rings must not slip” (Intune Windows Update for Business ring)

### Story (Intune update ring)

You’ve tuned update rings over time: deferrals, deadlines, auto update mode, Windows 11 eligibility.

Then an urgent incident happens. Someone pauses feature updates “until we figure it out”. It’s the right decision in the moment.

But the pause never gets removed.

A month later, you don’t have a single dramatic outage — you have a quiet, expensive problem: patch debt.

### The desired state (Intune update ring)

The baseline defines the key ring properties that must not drift (pause flags, deadlines, notifications).

- Example: `samples/monitors/intune-wufb-ring.monitor.json`

Apply it:

```powershell
pwsh -File .\scripts\Apply-UtcmMonitor.ps1 -MonitorJsonPath .\samples\monitors\intune-wufb-ring.monitor.json
```

And gate on drift:

```powershell
pwsh -File .\scripts\Get-UtcmMonitorHealth.ps1 -MonitorId <monitorId> -FailOnDrift
```

## Use case 3 — “Policies must not be paused” (Entra Conditional Access)

### Story (Conditional Access)

Conditional Access is one of those controls you only notice when it *isn’t* there.

During an incident, it’s tempting to disable a policy to reduce user impact, test a theory, or unblock an executive.

Sometimes that’s the right call in the moment.

The risk is what happens later: the incident resolves, the policy never comes back, and you silently drift into a weaker security posture.

### The desired state (Conditional Access)

For “guardrail” Conditional Access policies, the simplest desired state is often just: **the policy exists and it’s enabled**.

This repo includes a monitor definition that tracks a single Conditional Access policy by display name and checks its `State`.

- Example: `samples/monitors/entra-conditionalAccessPolicy.monitor.json`

Supported Entra resource types (including Conditional Access policies) are documented here:

- <https://learn.microsoft.com/en-us/graph/utcm-entra-resources>

### Apply the CA monitor (PowerShell)

```powershell
pwsh -File .\scripts\Apply-UtcmMonitor.ps1 -MonitorJsonPath .\samples\monitors\entra-conditionalAccessPolicy.monitor.json
```

### “Enforcement” as an operating model

UTCM is great at continuously detecting and reporting drift. In practice, “enforcement” usually looks like:

1) UTCM detects drift (for example, a CA policy `State` changes to `disabled`).
2) Your pipeline/automation fails (or alerts) on that drift.
3) A separate, explicit remediation step reverts the change (manual or automated).

That keeps the control loop observable and intentional: drift is *detected* by UTCM, while remediation is a policy decision you can audit.

## Automating UTCM in a production environment

UTCM is built around continuous monitoring, so the automation story is less about “run a script every hour” and more about wiring UTCM into your production operating model:

- Desired state is reviewed and versioned (JSON in source control)
- Monitors are applied idempotently (create/update)
- Drift becomes a signal you can alert on and/or gate deployments with

> Note: UTCM is currently exposed via Microsoft Graph `/beta`. Microsoft’s support policy states `/beta` isn’t supported for production applications.
> Many teams still automate preview features for internal operations, but you should do so with explicit risk acceptance, version pinning, and a safe rollout plan.

### Split automation into “deploy” and “evaluate” pipelines

In practice, separating these concerns keeps things predictable:

1) **Deploy (apply monitors)**
   - Trigger: PR merge / release
   - Action: run `Apply-UtcmMonitor.ps1` against the JSON definitions
   - Output: monitor definitions in UTCM match what’s in your repo

2) **Evaluate (read results + drift, then alert/gate)**
   - Trigger: scheduled job (for example, every 30–60 minutes) or an on-demand check before a sensitive rollout
   - Action: run `Get-UtcmMonitorHealth.ps1 -FailOnDrift` for “guardrail” monitors
   - Output: alerts, dashboards, ticket creation, or failed pipeline stages when drift is detected

This works well because UTCM itself runs the monitors on schedule; your automation is responsible for *applying intent* and *consuming results*.

### Use non-interactive identity in production

For unattended automation, prefer app-only / non-interactive auth patterns:

- **If the job runs on Azure compute** (Functions, Automation, VM, App Service): use **Managed Identity** and `Connect-MgGraph -Identity`.
  - `Connect-MgGraph` supports managed identity auth directly: <https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0>
  - Managed identities overview: <https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview>

- **If the job runs outside Azure** (for example, GitHub Actions): use **workload identity federation** (OIDC) to avoid storing secrets.
  - Workload identity federation concepts: <https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation>
  - Configure trust for GitHub Actions and other issuers: <https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust>
  - App registration + federated credentials: <https://learn.microsoft.com/en-us/graph/auth-register-app-v2>

- **If you must use credentials**, prefer certificate-based app-only auth over client secrets, and store keys/certs in a vault.
  - Azure Key Vault overview: <https://learn.microsoft.com/en-us/azure/key-vault/general/overview>
  - PowerShell SecretManagement abstraction (optional for local/dev + multiple vault backends): <https://learn.microsoft.com/en-us/powershell/utility-modules/secretmanagement/overview>

### Make the permission model explicit (and test it)

Production automation usually fails for one of two reasons:

1) The automation principal doesn’t have the Graph permissions required to manage UTCM resources.
2) The UTCM service principal in the tenant doesn’t have the workload roles/permissions required to *evaluate* the monitored resources (the “two-layer authorization model” earlier).

Treat these like you treat RBAC in IaC:

- Define them, document them, and validate them in a non-production tenant first.
- Keep a lightweight “smoke check” job that creates/updates a canary monitor and validates that results are successful.

### Recommended runtime hosts

You can run the “deploy” and “evaluate” steps in several production-friendly places:

- CI/CD runners (GitHub Actions / Azure DevOps) for apply + gating
- A scheduled job host (for example, **Azure Functions Timer Trigger**) for periodic evaluation and alerting
  - Azure Functions overview: <https://learn.microsoft.com/en-us/azure/azure-functions/functions-overview>

The key is consistency: keep monitor JSON as the source of truth, and make drift handling (alert vs gate vs auto-remediate) an explicit, reviewable decision.

## Snapshots — “show me what we have today”

Monitors are for drift over time. Snapshots are for capturing the tenant’s current configuration state for a set of supported resources.

The snapshot API creates an asynchronous job:

- `configurationBaseline: createSnapshot`: <https://learn.microsoft.com/en-us/graph/api/configurationbaseline-createsnapshot?view=graph-rest-beta>

Example:

```powershell
pwsh -File .\scripts\New-UtcmSnapshotJob.ps1 -DisplayName "Snapshot Demo" -Resources @(
  "microsoft.teams.federationConfiguration",
  "microsoft.intune.windowsUpdateForBusinessRingUpdateProfileWindows10"
)
```

## Updating baselines (the contained-entity gotcha)

There’s one nuance that matters for “baseline-as-code”: `configurationBaseline` is a contained entity under the monitor.

That means if you update the baseline, you should plan to send the full monitor body.

- Update reference (note on contained baseline): <https://learn.microsoft.com/en-us/graph/api/configurationmonitor-update?view=graph-rest-beta>

This is why the JSON files in `samples/monitors/` represent the whole monitor (not just the baseline).

## How this fits into an IaC program (practical operating model)

If you want UTCM to behave like real infrastructure-as-code, treat it like you treat policy-as-code:

1) Put monitors in source control (PR-reviewed JSON).
2) Apply monitors through automation (idempotent create/update).
3) Use drift as a signal:
   - informational for “visibility” monitors
   - blocking for “guardrail” monitors
4) Keep remediation explicit (separate workflow) unless you’re intentionally building auto-fix.

At a minimum, a pipeline can do:

- Authenticate (app-only is the usual direction for CI)
- Apply monitors
- Query drift; fail the build when drift violates guardrails

## Conclusion

UTCM is a promising way to move Microsoft 365 workload configuration closer to the same operational discipline we expect from cloud infrastructure:

- Desired state lives in source control.
- Drift is detected continuously.
- Gates make “temporary” changes visible and accountable.

If you want to run this end-to-end:

- Start with `project-utcm-configuration-management/README.md`
- Create the monitors from `samples/monitors/`
- Use `Get-UtcmMonitorHealth.ps1 -FailOnDrift` as your first drift gate

## References

- UTCM concept overview (preview): <https://learn.microsoft.com/en-us/graph/unified-tenant-configuration-management-concept-overview>
- UTCM API overview (Graph beta): <https://learn.microsoft.com/en-us/graph/api/resources/unified-tenant-configuration-management-api-overview?view=graph-rest-beta>
- UTCM authentication setup: <https://learn.microsoft.com/en-us/graph/utcm-authentication-setup>
- `configurationMonitor` resource type: <https://learn.microsoft.com/en-us/graph/api/resources/configurationmonitor?view=graph-rest-beta>
- `configurationBaseline` resource type: <https://learn.microsoft.com/en-us/graph/api/resources/configurationbaseline?view=graph-rest-beta>
- `configurationMonitoringResult` resource type: <https://learn.microsoft.com/en-us/graph/api/resources/configurationmonitoringresult?view=graph-rest-beta>
- `configurationDrift` resource type: <https://learn.microsoft.com/en-us/graph/api/resources/configurationdrift?view=graph-rest-beta>
- Snapshot creation (`createSnapshot`): <https://learn.microsoft.com/en-us/graph/api/configurationbaseline-createsnapshot?view=graph-rest-beta>
- Supported Entra resource types (includes Conditional Access policies): <https://learn.microsoft.com/en-us/graph/utcm-entra-resources>
- Supported Teams resource types: <https://learn.microsoft.com/en-us/graph/utcm-teams-resources>
- Supported Intune resource types: <https://learn.microsoft.com/en-us/graph/utcm-intune-resources>
- Microsoft Graph versioning and support (`/beta`): <https://learn.microsoft.com/en-us/graph/versioning-and-support#beta-version>
