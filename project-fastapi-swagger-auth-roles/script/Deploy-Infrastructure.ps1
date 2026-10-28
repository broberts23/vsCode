<#
.SYNOPSIS
  Deploy FastAPI Swagger Auth Roles infrastructure (SMI + Cosmos RBAC, no Cosmos keys).

.NOTES
  1. Deploy first with an empty -ContainerImage (hello-world bootstrap).
  2. Run Build-Push-Image.ps1 against the output ACR.
  3. Redeploy with -ContainerImage <loginServer>/fastapi-swagger:dev
  4. Add SPA redirect https://<apiFqdn>/docs/oauth2-redirect on the Entra app.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$ResourceGroup,

  [string]$Location = 'australiaeast',

  [Parameter(Mandatory)]
  [string]$TenantId,

  [Parameter(Mandatory)]
  [string]$ApiClientId,

  [string]$OpenApiClientId = '',

  [string]$ContainerImage = '',

  [string]$AcrName = '',

  [string]$BaseName = 'fsa',

  [ValidateSet('dev', 'test', 'prod')]
  [string]$Environment = 'dev',

  [string]$CosmosDatabaseName = 'identitydb',

  [string]$CosmosContainerName = 'identities'
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
  openApiClientId       = $OpenApiClientId
  containerImage        = $ContainerImage
  acrName               = $AcrName
  cosmosDatabaseName    = $CosmosDatabaseName
  cosmosContainerName   = $CosmosContainerName
}

$deployment = New-AzResourceGroupDeployment `
  -Name "fastapi-swagger-$(Get-Date -Format 'yyyyMMddHHmmss')" `
  -ResourceGroupName $ResourceGroup `
  -TemplateFile (Join-Path $PSScriptRoot '..\infra\main.bicep') `
  -TemplateParameterObject $params `
  -Verbose

$deployment.Outputs | Format-Table -AutoSize

$acr = $deployment.Outputs.acrName.Value
$loginServer = $deployment.Outputs.acrLoginServer.Value
$fqdn = $deployment.Outputs.apiFqdn.Value

Write-Host @"
Next steps:
  1. .\script\Build-Push-Image.ps1 -AcrName $acr
  2. Re-run this script with -ContainerImage ${loginServer}/fastapi-swagger:dev
  3. Entra SPA redirect: https://${fqdn}/docs/oauth2-redirect
"@
