#Requires -Version 7.0
<#
.SYNOPSIS
  Deploys the Flex Consumption Function App (Python 3.14) with Easy Auth and assigns Api.Read to its system MI.

.EXAMPLE
  .\deploy.ps1 -ResourceGroupName 'rg-proxylab' -Location 'australiaeast'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter()]
    [string]$Location = 'australiaeast',

    [Parameter()]
    [ValidateLength(3, 10)]
    [string]$NamePrefix = 'proxylab',

    [Parameter()]
    [string]$OnPremApiBaseUrl = 'https://projectfastapi-benrobertsio.msappproxy.net',

    [Parameter()]
    [string]$OnPremApiAppId = '8f99f135-63dd-4679-88b7-32ad6ebf4219',

    [Parameter()]
    [string]$OnPremApiScope = 'api://8f99f135-63dd-4679-88b7-32ad6ebf4219/.default',

    [Parameter()]
    [string]$OnPremAppRoleValue = 'Api.Read',

    # Azure CLI first-party app — pre-authorized so `az account get-access-token` works for Easy Auth curls.
    [Parameter()]
    [string]$AzureCliClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
)

$ErrorActionPreference = 'Stop'
$infraDir = $PSScriptRoot
$bicepFile = Join-Path $infraDir 'main.bicep'

function Assert-AzCli {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw 'Azure CLI (az) is required.'
    }
    $account = az account show --query id -o tsv 2>$null
    if (-not $account) {
        throw 'Not logged in. Run: az login'
    }
}

function Invoke-GraphAppPatch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationObjectId,

        [Parameter(Mandatory = $true)]
        [string]$BodyJson
    )

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("graph-app-{0}.json" -f [guid]::NewGuid())
    try {
        Set-Content -Path $tmp -Value $BodyJson -Encoding utf8NoBOM
        az rest --method PATCH `
            --url "https://graph.microsoft.com/v1.0/applications/$ApplicationObjectId" `
            --headers 'Content-Type=application/json' `
            --body "@$tmp" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Graph PATCH failed for application $ApplicationObjectId"
        }
    }
    finally {
        Remove-Item -Path $tmp -ErrorAction SilentlyContinue
    }
}

function New-EasyAuthApp {
    param([string]$DisplayName)

    Write-Host "Creating Easy Auth app registration: $DisplayName"
    $appJson = az ad app create `
        --display-name $DisplayName `
        --sign-in-audience AzureADMyOrg `
        --enable-access-token-issuance true `
        --enable-id-token-issuance true `
        --requested-access-token-version 2 `
        -o json | ConvertFrom-Json

    $clientId = $appJson.appId
    $objectId = $appJson.id
    $identifierUri = "api://$clientId"

    az ad app update --id $clientId --identifier-uris $identifierUri | Out-Null

    # Graph rejects preAuthorizedApplications that reference a scope id in the same
    # PATCH that creates the scope. Publish the scope first, then pre-authorize Azure CLI.
    $scopeId = [guid]::NewGuid().ToString()
    $scopePayload = @{
        api = @{
            oauth2PermissionScopes      = @(
                @{
                    adminConsentDescription = 'Allow the app to access the Function App as the signed-in user.'
                    adminConsentDisplayName = 'Access as user'
                    id                      = $scopeId
                    isEnabled               = $true
                    type                    = 'User'
                    userConsentDescription  = 'Allow the app to access the Function App on your behalf.'
                    userConsentDisplayName  = 'Access as user'
                    value                   = 'access_as_user'
                }
            )
            requestedAccessTokenVersion = 2
        }
    } | ConvertTo-Json -Depth 8 -Compress

    $preAuthPayload = @{
        api = @{
            preAuthorizedApplications = @(
                @{
                    appId                  = $AzureCliClientId
                    delegatedPermissionIds = @($scopeId)
                }
            )
        }
    } | ConvertTo-Json -Depth 8 -Compress

    Invoke-GraphAppPatch -ApplicationObjectId $objectId -BodyJson $scopePayload
    Invoke-GraphAppPatch -ApplicationObjectId $objectId -BodyJson $preAuthPayload

    az ad sp create --id $clientId 2>$null | Out-Null

    [PSCustomObject]@{
        ClientId      = $clientId
        ObjectId      = $objectId
        IdentifierUri = $identifierUri
        Scope         = "$identifierUri/access_as_user"
    }
}

function Grant-MiAppRole {
    param(
        [string]$ManagedIdentityPrincipalId,
        [string]$ApiAppId,
        [string]$AppRoleValue
    )

    Write-Host "Resolving API service principal and app role '$AppRoleValue' for $ApiAppId"
    $apiSp = az ad sp show --id $ApiAppId -o json | ConvertFrom-Json
    if (-not $apiSp) {
        throw "Service principal not found for API app $ApiAppId. Ensure the Enterprise App exists."
    }

    $role = $apiSp.appRoles | Where-Object { $_.value -eq $AppRoleValue -and $_.isEnabled }
    if (-not $role) {
        throw "App role '$AppRoleValue' not found (or disabled) on API app $ApiAppId."
    }

    $existing = az rest --method GET `
        --url "https://graph.microsoft.com/v1.0/servicePrincipals/$ManagedIdentityPrincipalId/appRoleAssignments" `
        -o json | ConvertFrom-Json

    $already = @($existing.value) | Where-Object {
        $_.resourceId -eq $apiSp.id -and $_.appRoleId -eq $role.id
    }
    if ($already) {
        Write-Host 'Api.Read already assigned to Function system MI.'
        return
    }

    Write-Host "Assigning $AppRoleValue to Function system MI ($ManagedIdentityPrincipalId)"
    $body = @{
        principalId = $ManagedIdentityPrincipalId
        resourceId  = $apiSp.id
        appRoleId   = $role.id
    } | ConvertTo-Json -Compress

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("mi-approle-{0}.json" -f [guid]::NewGuid())
    try {
        Set-Content -Path $tmp -Value $body -Encoding utf8NoBOM
        az rest --method POST `
            --url "https://graph.microsoft.com/v1.0/servicePrincipals/$ManagedIdentityPrincipalId/appRoleAssignments" `
            --headers 'Content-Type=application/json' `
            --body "@$tmp" | Out-Null
    }
    finally {
        Remove-Item -Path $tmp -ErrorAction SilentlyContinue
    }
}

Assert-AzCli

$tenantId = az account show --query tenantId -o tsv
$subscriptionId = az account show --query id -o tsv
Write-Host "Subscription: $subscriptionId | Tenant: $tenantId | Location: $Location"

$rgExists = az group exists --name $ResourceGroupName -o tsv
if ($rgExists -eq 'false') {
    Write-Host "Creating resource group $ResourceGroupName"
    az group create --name $ResourceGroupName --location $Location | Out-Null
}

$easyAuthDisplayName = "$NamePrefix-fn-easyauth"
$easyAuth = New-EasyAuthApp -DisplayName $easyAuthDisplayName

Write-Host "Deploying Bicep to $ResourceGroupName ..."
$deploymentName = "proxylab-$(Get-Date -Format 'yyyyMMddHHmmss')"
$outputsJson = az deployment group create `
    --name $deploymentName `
    --resource-group $ResourceGroupName `
    --template-file $bicepFile `
    --parameters `
        namePrefix=$NamePrefix `
        location=$Location `
        onPremApiBaseUrl=$OnPremApiBaseUrl `
        onPremApiScope=$OnPremApiScope `
        easyAuthClientId=$($easyAuth.ClientId) `
        tenantId=$tenantId `
    --query properties.outputs `
    -o json

if ($LASTEXITCODE -ne 0) {
    throw 'Bicep deployment failed.'
}

$outputs = $outputsJson | ConvertFrom-Json
$functionAppName = $outputs.functionAppName.value
$hostname = $outputs.functionAppHostname.value
$principalId = $outputs.functionAppPrincipalId.value

Grant-MiAppRole `
    -ManagedIdentityPrincipalId $principalId `
    -ApiAppId $OnPremApiAppId `
    -AppRoleValue $OnPremAppRoleValue

Write-Host ''
Write-Host '=== Deploy complete ==='
Write-Host "Function App:     $functionAppName"
Write-Host "Hostname:         https://$hostname"
Write-Host "System MI OID:    $principalId"
Write-Host "Easy Auth appId:  $($easyAuth.ClientId)"
Write-Host "Easy Auth scope:  $($easyAuth.Scope)"
Write-Host ''
Write-Host 'Next: publish Function code, then call with Easy Auth:'
Write-Host "  cd ..\function-app"
Write-Host "  func azure functionapp publish $functionAppName --python"
Write-Host ''
Write-Host '  $token = az account get-access-token --scope $($easyAuth.Scope) --query accessToken -o tsv'
Write-Host "  curl -sS -H `"Authorization: Bearer `$token`" `"https://$hostname/api/onprem-host`""
