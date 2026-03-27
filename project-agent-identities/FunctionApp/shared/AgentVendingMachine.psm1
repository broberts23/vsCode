#!/usr/bin/env pwsh
#Requires -Version 7.4

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

using namespace System.Net

function Get-EnvironmentSetting {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$DefaultValue,

        [switch]$Required
    )

    $value = [Environment]::GetEnvironmentVariable($Name)
    if (-not [string]::IsNullOrWhiteSpace($value)) {
        return $value
    }

    if ($Required) {
        throw "Missing required environment variable '$Name'."
    }

    return $DefaultValue
}

function ConvertFrom-FunctionRequestBody {
    param(
        [Parameter(Mandatory)]
        $Request
    )

    if ($null -eq $Request.Body) {
        return [pscustomobject]@{}
    }

    if ($Request.Body -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Request.Body)) {
            return [pscustomobject]@{}
        }

        return $Request.Body | ConvertFrom-Json -Depth 20
    }

    if ($Request.Body -is [hashtable]) {
        return [pscustomobject]$Request.Body
    }

    return $Request.Body
}

function Get-ClientPrincipal {
    param(
        [Parameter(Mandatory)]
        $Request
    )

    $principalHeader = $Request.Headers['X-MS-CLIENT-PRINCIPAL']
    if (-not $principalHeader) {
        return $null
    }

    $decodedValue = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($principalHeader))
    return $decodedValue | ConvertFrom-Json -Depth 10
}

function Test-PrincipalHasRole {
    param(
        $Principal,

        [Parameter(Mandatory)]
        [string]$RequiredRole
    )

    if ($null -eq $Principal) {
        return $false
    }

    foreach ($claim in $Principal.claims) {
        if ($claim.typ -in @('roles', 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role') -and $claim.val -eq $RequiredRole) {
            return $true
        }
    }

    return $false
}

function New-JsonResponse {
    param(
        [Parameter(Mandatory)]
        [HttpStatusCode]$StatusCode,

        [Parameter(Mandatory)]
        $Body
    )

    return [HttpResponseContext]@{
        StatusCode = $StatusCode
        Headers    = @{ 'Content-Type' = 'application/json' }
        Body       = $Body | ConvertTo-Json -Depth 20
    }
}

function Get-OfferCatalog {
    param(
        [string]$CatalogPath = $(Get-EnvironmentSetting -Name 'OFFER_CATALOG_PATH' -DefaultValue 'config/agent-offerings.sample.json')
    )

    $functionAppRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $fullPath = [System.IO.Path]::GetFullPath((Join-Path $functionAppRoot $CatalogPath))

    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw "Offer catalog not found at '$fullPath'."
    }

    return (Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json -Depth 20)
}

function Get-OfferDefinition {
    param(
        [Parameter(Mandatory)]
        [string]$OfferingId,

        [Parameter(Mandatory)]
        $Catalog
    )

    $offer = $Catalog.offerings | Where-Object { $_.offeringId -eq $OfferingId } | Select-Object -First 1
    if ($null -eq $offer) {
        throw "Unknown offeringId '$OfferingId'."
    }

    return $offer
}

function Get-DefaultObjectIds {
    param(
        [Parameter(Mandatory)]
        [string]$EnvironmentVariableName
    )

    $value = Get-EnvironmentSetting -Name $EnvironmentVariableName -DefaultValue ''
    if ([string]::IsNullOrWhiteSpace($value)) {
        return @()
    }

    return @($value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function New-BlueprintPlan {
    param(
        [Parameter(Mandatory)]
        $Offer,

        [Parameter(Mandatory)]
        [string[]]$SponsorObjectIds,

        [Parameter(Mandatory)]
        [string[]]$OwnerObjectIds
    )

    $scopeIdentifier = [Guid]::NewGuid().Guid

    return [pscustomobject]@{
        displayName            = $Offer.blueprint.displayName
        description            = $Offer.blueprint.description
        verifiedPublisher      = $Offer.blueprint.verifiedPublisher
        credentialStrategy     = $Offer.blueprint.credentialStrategy
        credentialSource       = $Offer.blueprint.credentialSource
        owners                 = $OwnerObjectIds
        sponsors               = $SponsorObjectIds
        optionalClaims         = $Offer.blueprint.optionalClaims
        requiresAccessAgentScope = [bool]$Offer.blueprint.requiresAccessAgentScope
        graphRequests          = @(
            [pscustomobject]@{
                step   = 'Create blueprint application'
                method = 'POST'
                uri    = 'https://graph.microsoft.com/beta/applications'
                body   = @{
                    '@odata.type'        = 'Microsoft.Graph.AgentIdentityBlueprint'
                    displayName          = $Offer.blueprint.displayName
                    description          = $Offer.blueprint.description
                    'owners@odata.bind'  = @($OwnerObjectIds | ForEach-Object { "https://graph.microsoft.com/v1.0/directoryObjects/$_" })
                    'sponsors@odata.bind' = @($SponsorObjectIds | ForEach-Object { "https://graph.microsoft.com/v1.0/directoryObjects/$_" })
                }
            },
            [pscustomobject]@{
                step   = 'Add managed identity federated credential'
                method = 'POST'
                uri    = 'https://graph.microsoft.com/beta/applications/{agentBlueprintAppId}/federatedIdentityCredentials'
                body   = @{
                    name      = 'agent-vending-machine-mi'
                    issuer    = 'https://login.microsoftonline.com/{tenantId}/v2.0'
                    subject   = '{managedIdentityPrincipalId}'
                    audiences = @('api://AzureADTokenExchange')
                }
            },
            [pscustomobject]@{
                step   = 'Configure optional delegated scope for access_agent'
                method = 'PATCH'
                uri    = 'https://graph.microsoft.com/beta/applications/{agentBlueprintAppId}'
                body   = @{
                    identifierUris = @('api://{agentBlueprintAppId}')
                    api            = @{
                        oauth2PermissionScopes = @(
                            @{
                                adminConsentDescription = 'Allow the application to access the agent on behalf of the signed-in user.'
                                adminConsentDisplayName = 'Access agent'
                                id                      = $scopeIdentifier
                                isEnabled               = $true
                                type                    = 'User'
                                value                   = 'access_agent'
                            }
                        )
                    }
                }
            },
            [pscustomobject]@{
                step   = 'Create blueprint principal'
                method = 'POST'
                uri    = 'https://graph.microsoft.com/beta/serviceprincipals/graph.agentIdentityBlueprintPrincipal'
                body   = @{
                    appId = '{agentBlueprintAppId}'
                }
            }
        )
    }
}

function New-AgentIdentityPlan {
    param(
        [Parameter(Mandatory)]
        $Offer,

        [Parameter(Mandatory)]
        [string]$InstanceDisplayName,

        [Parameter(Mandatory)]
        [string]$BlueprintAppId,

        [Parameter(Mandatory)]
        [string[]]$SponsorObjectIds
    )

    return [pscustomobject]@{
        graphRequest = [pscustomobject]@{
            step   = 'Create agent identity'
            method = 'POST'
            uri    = 'https://graph.microsoft.com/beta/serviceprincipals/Microsoft.Graph.AgentIdentity'
            body   = @{
                displayName              = $InstanceDisplayName
                agentIdentityBlueprintId = $BlueprintAppId
                'sponsors@odata.bind'    = @($SponsorObjectIds | ForEach-Object { "https://graph.microsoft.com/v1.0/directoryObjects/$_" })
            }
        }
        accessPackage = [pscustomobject]@{
            displayName          = $Offer.accessPackage.displayName
            assignmentMode       = $Offer.accessPackage.assignmentMode
            assignmentPolicyName = $Offer.accessPackage.assignmentPolicyDisplayName
            lifecycle            = $Offer.accessPackage.lifecycle
            resources            = $Offer.accessPackage.resources
        }
        agentUser = [pscustomobject]@{
            enabledByDefault = [bool]$Offer.agentUser.enabledByDefault
            requiresLicense  = [bool]$Offer.agentUser.licenseRequired
            workIqTools      = $Offer.agentUser.workIqTools
            scenarios        = $Offer.agentUser.scenarios
            note             = 'The agent user is optional. Grant the blueprint the explicit capability to create agent users before enabling this path.'
        }
    }
}

function Get-GraphAccessToken {
    $identityEndpoint = Get-EnvironmentSetting -Name 'IDENTITY_ENDPOINT' -DefaultValue $env:MSI_ENDPOINT
    $identityHeader = Get-EnvironmentSetting -Name 'IDENTITY_HEADER' -DefaultValue $env:MSI_SECRET

    if ([string]::IsNullOrWhiteSpace($identityEndpoint) -or [string]::IsNullOrWhiteSpace($identityHeader)) {
        throw 'Managed identity endpoint variables are not available. Deploy the Function App with managed identity enabled.'
    }

    $resource = 'https://graph.microsoft.com/'
    $tokenUri = "{0}?resource={1}&api-version=2019-08-01" -f $identityEndpoint, [uri]::EscapeDataString($resource)
    $tokenResponse = Invoke-RestMethod -Method Get -Uri $tokenUri -Headers @{ 'X-IDENTITY-HEADER' = $identityHeader }
    return $tokenResponse.access_token
}

function Invoke-GraphRequest {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        $Body
    )

    $accessToken = Get-GraphAccessToken
    $headers = @{
        Authorization = "Bearer $accessToken"
        'Content-Type' = 'application/json'
        'OData-Version' = '4.0'
    }

    if ($null -eq $Body) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }

    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ($Body | ConvertTo-Json -Depth 20)
}

Export-ModuleMember -Function ConvertFrom-FunctionRequestBody
Export-ModuleMember -Function Get-ClientPrincipal
Export-ModuleMember -Function Get-DefaultObjectIds
Export-ModuleMember -Function Get-EnvironmentSetting
Export-ModuleMember -Function Get-OfferCatalog
Export-ModuleMember -Function Get-OfferDefinition
Export-ModuleMember -Function Invoke-GraphRequest
Export-ModuleMember -Function New-AgentIdentityPlan
Export-ModuleMember -Function New-BlueprintPlan
Export-ModuleMember -Function New-JsonResponse
Export-ModuleMember -Function Test-PrincipalHasRole