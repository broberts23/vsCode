# scripts

PowerShell 7.4 helper scripts for deploying and operating the sample.

- Scripts in this folder are intended to run locally or in CI.
- They should not embed secrets; use Key Vault or environment variables.

Planned scripts in this scaffold:

- `Deploy-Infrastructure.ps1` — deploy Bicep
- `Deploy-FunctionCode.ps1` — zip-deploy the Azure Function code
- `New-GraphUsersSubscriptionToEventGrid.ps1` — create a Microsoft Graph subscription that delivers to an Event Grid partner topic (delegated auth via Connect-MgGraph)
- `Activate-EventGridPartnerTopic.ps1` — activate the partner topic (required before events flow)
- `Grant-GraphAppRolesToManagedIdentity.ps1` — grant Microsoft Graph application permissions to the Function App managed identity
- `Set-Policy.ps1` — validate/publish policy configuration
- `SmokeTest-GraphAuth.ps1` — verify Graph auth from your workstation
