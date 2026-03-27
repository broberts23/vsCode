# Agent Vending Machine Deployment README

This document covers deployment prerequisites, infrastructure deployment, Function App publishing, and sample HTTP requests for the two endpoints in the agent vending machine scaffold.

## What Gets Deployed

The infrastructure template provisions:

1. a storage account for the Function App
2. an Application Insights instance
3. a Linux Consumption plan
4. a PowerShell 7.4 Function App
5. a system-assigned managed identity on the Function App
6. Easy Auth configuration by using Azure AD authentication

The Function App code provides two HTTP-trigger endpoints:

1. `POST /api/BootstrapOffering`
2. `POST /api/DispenseAgent`

## Prerequisites

Complete these prerequisites before deployment.

1. Azure PowerShell is installed and you can run `Connect-AzAccount`.
2. You have permission to create a resource group and deploy Azure resources.
3. You have a Microsoft Entra application registration that will act as the client for Easy Auth.
4. That app registration exposes an app role for callers of the vending machine API, for example `Agent.Vending.Admin`.
5. You know the Microsoft Entra tenant ID and the client application ID used to call the Function App.
6. Microsoft Agent 365 and Microsoft Entra Agent ID preview prerequisites are already satisfied in the tenant.
7. You are ready to separately grant the runtime identity the Microsoft Graph and Agent ID permissions required for bootstrap or live dispense operations.
8. You have reviewed the sample offer manifest at [project-agent-identities/FunctionApp/config/agent-offerings.sample.json](c:/Repo/vsCode/project-agent-identities/FunctionApp/config/agent-offerings.sample.json) and replaced placeholder object IDs before live use.

## Folder Layout

Deployment assets added for this scaffold:

1. [project-agent-identities/infra/main.bicep](c:/Repo/vsCode/project-agent-identities/infra/main.bicep)
2. [project-agent-identities/infra/parameters.dev.json](c:/Repo/vsCode/project-agent-identities/infra/parameters.dev.json)
3. [project-agent-identities/infra/parameters.test.json](c:/Repo/vsCode/project-agent-identities/infra/parameters.test.json)
4. [project-agent-identities/infra/parameters.prod.json](c:/Repo/vsCode/project-agent-identities/infra/parameters.prod.json)
5. [project-agent-identities/scripts/Deploy-Infrastructure.ps1](c:/Repo/vsCode/project-agent-identities/scripts/Deploy-Infrastructure.ps1)
6. [project-agent-identities/scripts/Deploy-FunctionApp.ps1](c:/Repo/vsCode/project-agent-identities/scripts/Deploy-FunctionApp.ps1)

## Infrastructure Deployment

Sign in first:

```powershell
Connect-AzAccount
```

Deploy dev infrastructure:

```powershell
./scripts/Deploy-Infrastructure.ps1 -Environment dev -ResourceGroupName rg-agent-vending-dev -Location eastus
```

Run a What-If preview:

```powershell
./scripts/Deploy-Infrastructure.ps1 -Environment test -ResourceGroupName rg-agent-vending-test -Location eastus -WhatIf
```

What the template configures:

1. system-assigned managed identity on the Function App
2. PowerShell 7.4 runtime on Linux
3. App settings used by the scaffold
4. `authsettingsV2` for Microsoft Entra sign-in and token validation

## Publish the Function App Code

After the infrastructure exists, publish the Function App contents:

```powershell
./scripts/Deploy-FunctionApp.ps1 -ResourceGroupName rg-agent-vending-dev -FunctionAppName <function-app-name>
```

The script compresses the local `FunctionApp` folder and publishes it by using Zip Deploy.

## Post-Deployment Configuration

The scaffold assumes that Easy Auth authenticates the caller and injects `X-MS-CLIENT-PRINCIPAL` into the request. It also assumes that the Function App managed identity is separately granted the Microsoft Graph permissions needed for whichever execution mode you intend to use.

Recommended next checks:

1. confirm the Function App managed identity exists
2. confirm the Easy Auth app registration is the expected one
3. confirm the allowed audience matches the client application used to call the API
4. keep `AGENT_VENDING_EXECUTION_MODE` as `DryRun` until Graph permissions and offer catalog values are verified

## Sample HTTP Requests

All examples assume:

1. the Function App is protected by Easy Auth
2. the caller already acquired a bearer token for the configured application
3. the token contains the required app role, by default `Agent.Vending.Admin`

### BootstrapOffering

Purpose: turn an offer definition into a blueprint bootstrap plan and matching governance plan.

PowerShell example:

```powershell
$token = '<bearer-token>'
$uri = 'https://<function-app-name>.azurewebsites.net/api/BootstrapOffering'

$body = @{
    offeringId = 'service-desk-mail-triage'
    sponsorObjectIds = @(
        '11111111-1111-1111-1111-111111111111'
    )
    ownerObjectIds = @(
        '22222222-2222-2222-2222-222222222222'
    )
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $body
```

`curl` example:

```bash
curl -X POST "https://<function-app-name>.azurewebsites.net/api/BootstrapOffering" \
  -H "Authorization: Bearer <bearer-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "offeringId": "service-desk-mail-triage",
    "sponsorObjectIds": ["11111111-1111-1111-1111-111111111111"],
    "ownerObjectIds": ["22222222-2222-2222-2222-222222222222"]
  }'
```

Expected result in `DryRun` mode:

1. blueprint creation plan
2. federated credential plan
3. blueprint principal creation plan
4. access package configuration summary

### DispenseAgent

Purpose: create or plan a new agent instance from a vetted offering.

PowerShell example:

```powershell
$token = '<bearer-token>'
$uri = 'https://<function-app-name>.azurewebsites.net/api/DispenseAgent'

$body = @{
    offeringId = 'project-coordinator'
    instanceDisplayName = 'Agent - PMO - Sprint Coordinator - 01'
    sponsorObjectIds = @(
        '11111111-1111-1111-1111-111111111111'
    )
    blueprintAppId = '<bootstrap-output-blueprint-app-id>'
    createAgentUser = $true
    justification = 'Recurring sprint planning and follow-up coordination'
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $body
```

`curl` example:

```bash
curl -X POST "https://<function-app-name>.azurewebsites.net/api/DispenseAgent" \
  -H "Authorization: Bearer <bearer-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "offeringId": "project-coordinator",
    "instanceDisplayName": "Agent - PMO - Sprint Coordinator - 01",
    "sponsorObjectIds": ["11111111-1111-1111-1111-111111111111"],
    "blueprintAppId": "<bootstrap-output-blueprint-app-id>",
    "createAgentUser": true,
    "justification": "Recurring sprint planning and follow-up coordination"
  }'
```

Expected result in `DryRun` mode:

1. agent identity Graph request payload
2. access package governance summary
3. optional agent user guidance
4. expected output artifacts

## Environment Notes

Keep these settings in mind:

1. `AGENT_VENDING_EXECUTION_MODE=DryRun` is the safe default.
2. Set `AGENT_VENDING_EXECUTION_MODE=Live` only after validating Graph permissions and the offer manifest.
3. Replace placeholder sponsor and owner IDs before any real use.
4. If you change `REQUIRED_ADMIN_ROLE`, update the client app registration and caller token issuance accordingly.

## Known Scaffold Boundaries

This pack is a scaffold, not a finished platform.

1. `Live` mode currently creates the agent identity but does not fully automate access package assignment.
2. Agent user creation remains an explicit modeled step rather than a completed provisioning flow.
3. Graph permission grants for the runtime identity are intentionally not auto-consented by the deployment template.
