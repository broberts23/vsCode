# Unified Tenant Configuration Management (UTCM) — Graph (/beta) Config-as-Code

This project shows how to use **Unified Tenant Configuration Management (UTCM)** APIs in **Microsoft Graph `/beta`** to:

- Create **configuration snapshots** (export-like jobs)
- Create/update **configuration monitors** with an embedded **configuration baseline**
- Query **monitoring results** and **drifts** for drift detection

> Important: Graph `/beta` APIs are subject to change and not supported for production usage.
> See <https://learn.microsoft.com/en-us/graph/versioning-and-support#beta-version>

## Prerequisites

- PowerShell **7.4+**
- Microsoft Graph PowerShell SDK installed (see install guide)
  - <https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0>

## Authentication

These scripts use `Connect-MgGraph` + `Invoke-MgGraphRequest`.

- `Connect-MgGraph` reference: <https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0>
- Auth patterns: <https://learn.microsoft.com/en-us/powershell/microsoftgraph/authentication-commands?view=graph-powershell-1.0>

### Option A: Interactive (delegated)

```powershell
pwsh -File .\scripts\Connect-UtcmGraph.ps1 -Interactive
```

### Option B: App-only (certificate)

```powershell
pwsh -File .\scripts\Connect-UtcmGraph.ps1 -TenantId <tenantId> -ClientId <appId> -CertificateThumbprint <thumbprint>
```

## Apply monitors (baseline-as-code)

Two sample monitors are in `samples/monitors/`.

Create a monitor:

```powershell
pwsh -File .\scripts\Apply-UtcmMonitor.ps1 -MonitorJsonPath .\samples\monitors\teams-federationConfiguration.monitor.json
```

Update an existing monitor (full body required when changing baseline):

```powershell
pwsh -File .\scripts\Apply-UtcmMonitor.ps1 -MonitorId <monitorId> -MonitorJsonPath .\samples\monitors\teams-federationConfiguration.monitor.json
```

## Create a snapshot job

```powershell
pwsh -File .\scripts\New-UtcmSnapshotJob.ps1 -DisplayName "Snapshot Demo" -Resources @(
  "microsoft.teams.federationConfiguration",
  "microsoft.intune.windowsUpdateForBusinessRingUpdateProfileWindows10"
)
```

Snapshot API reference: <https://learn.microsoft.com/en-us/graph/api/configurationbaseline-createsnapshot?view=graph-rest-beta>

## Query drift and monitoring results

```powershell
pwsh -File .\scripts\Get-UtcmMonitorHealth.ps1 -MonitorId <monitorId>
```

Add pipeline gating (non-zero exit on drift):

```powershell
pwsh -File .\scripts\Get-UtcmMonitorHealth.ps1 -MonitorId <monitorId> -FailOnDrift
```

## Blog

See [blog.md](blog.md) for the narrative overview, two use-case stories, and how to fit UTCM into an IaC program.
