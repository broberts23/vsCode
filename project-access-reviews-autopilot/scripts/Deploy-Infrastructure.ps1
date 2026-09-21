<#
.SYNOPSIS
  Deploy Access Reviews Autopilot infrastructure (MI-only, no resource keys in app settings).

.NOTES
  1. Deploy infra first with an empty containerImage.
  2. Build/push the image to the output ACR with az acr build (uses MI AcrPush separately or az login).
  3. Redeploy with -ContainerImage <loginServer>/ara:dev
  4. Store Slack secrets in Key Vault: slack-signing-secret, slack-bot-token (optional channel in App Config later).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [string]$Location = 'australiaeast',

    [Parameter(Mandatory)]
    [string]$TenantId,

    [string]$ApiClientId = '',

    [string]$SpaClientId = '',

    [string]$ApiAudience = 'api://access-reviews-autopilot',

    [string]$ContainerImage = '',

    [string]$BaseName = 'ara',

    [string]$Environment = 'dev'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-AzContext)) {
    throw 'Run Connect-AzAccount first.'
}

if (-not (Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $ResourceGroup -Location $Location | Out-Null
}

$params = @{
    deploymentEnvironment = $Environment
    baseName              = $BaseName
    tenantId              = $TenantId
    apiClientId           = $ApiClientId
    spaClientId           = $SpaClientId
    apiAudience           = $ApiAudience
    containerImage        = $ContainerImage
}

$deployment = New-AzResourceGroupDeployment `
    -Name "ara-$(Get-Date -Format 'yyyyMMddHHmmss')" `
    -ResourceGroupName $ResourceGroup `
    -TemplateFile (Join-Path $PSScriptRoot '..\infra\main.bicep') `
    -TemplateParameterObject $params `
    -Verbose

$deployment.Outputs | Format-Table Name, Value
Write-Host @'
Next steps:
  1. az acr build -r <acrLoginServer> -t ara:dev .
  2. Re-run this script with -ContainerImage <acrLoginServer>/ara:dev
  3. az keyvault secret set --vault-name <kv> --name slack-signing-secret --value <secret>
  4. az keyvault secret set --vault-name <kv> --name slack-bot-token --value <xoxb-...>
  5. Point Slack Request URL to https://<apiFqdn>/slack/interactions
  6. Smoke-test: no AccountKey/SharedAccessKey/Cosmos keys in ACA env
'@
