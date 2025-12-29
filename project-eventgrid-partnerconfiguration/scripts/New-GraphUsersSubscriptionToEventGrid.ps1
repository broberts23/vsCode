#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AzureSubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PartnerTopicName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Location,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Scopes = @('User.Read.All'),

    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Resource = 'users',

    [Parameter(Mandatory = $false)]
    [ValidateSet('updated', 'updated,deleted')]
    [string]$ChangeType = 'updated,deleted',

    [Parameter(Mandatory = $false)]
    [ValidateRange(45, 41760)]
    [int]$ExpirationInMinutes = 40320,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientState,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$GraphEndpoint = 'https://graph.microsoft.com/v1.0'

    ,
    [Parameter(Mandatory = $false)]
    [switch]$UseAzCliGraphToken

    ,
    [Parameter(Mandatory = $false)]
    [switch]$AsJson
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function New-RandomClientState {
    [CmdletBinding()]
    param()

    $bytes = [byte[]]::new(24)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToBase64String($bytes).TrimEnd('=')
}

function Ensure-GraphConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Scopes,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [switch]$UseDeviceCode
    )

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $context = $null
    try {
        $context = Get-MgContext -ErrorAction Stop
    }
    catch {
        $context = $null
    }

    $missingScopes = @()
    if ($null -eq $context -or $null -eq $context.Scopes) {
        $missingScopes = $Scopes
    }
    else {
        foreach ($scope in $Scopes) {
            if ($context.Scopes -notcontains $scope) {
                $missingScopes += $scope
            }
        }
    }

    if ($missingScopes.Count -gt 0) {
        $connectParams = @{
            Scopes    = $Scopes
            NoWelcome = $true
        }

        if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
            $connectParams['TenantId'] = $TenantId
        }
        if ($UseDeviceCode.IsPresent) {
            $connectParams['UseDeviceCode'] = $true
        }

        Connect-MgGraph @connectParams | Out-Null
    }
}

function Assert-AzCliPresent {
    [CmdletBinding()]
    param()

    $az = Get-Command -Name 'az' -ErrorAction SilentlyContinue
    if ($null -eq $az) {
        throw "Azure CLI ('az') not found. Install Azure CLI and run 'az login' first. See https://learn.microsoft.com/cli/azure/install-azure-cli"
    }
}

function Get-AzCliGraphAccessToken {
    [CmdletBinding()]
    param()

    Assert-AzCliPresent

    $token = & az account get-access-token --resource https://graph.microsoft.com/ --query accessToken -o tsv 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to acquire Microsoft Graph access token via Azure CLI. Details: $token"
    }

    if ([string]::IsNullOrWhiteSpace([string]$token)) {
        throw 'Azure CLI returned an empty Microsoft Graph access token.'
    }

    return [string]$token
}

function Invoke-GraphRest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PATCH')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Body,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken
    )

    $headers = @{ Authorization = "Bearer $AccessToken"; 'Content-Type' = 'application/json' }
    $json = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 10 } else { $null }
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
}

function New-EventGridPartnerEndpointUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AzureSubscriptionId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PartnerTopicName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Location
    )

    # Per Microsoft Learn: "Receive Microsoft Graph change events through Azure Event Grid"
    # The URI uses the EventGrid:? scheme.
    # Example:
    # EventGrid:?azuresubscriptionid=<...>&resourcegroup=<...>&partnertopic=<...>&location=<...>
    return "EventGrid:?azuresubscriptionid=$AzureSubscriptionId&resourcegroup=$ResourceGroupName&partnertopic=$PartnerTopicName&location=$Location"
}

if ([string]::IsNullOrWhiteSpace($ClientState)) {
    $ClientState = New-RandomClientState
}

$notificationUrl = New-EventGridPartnerEndpointUri -AzureSubscriptionId $AzureSubscriptionId -ResourceGroupName $ResourceGroupName -PartnerTopicName $PartnerTopicName -Location $Location
$lifecycleNotificationUrl = $notificationUrl

$expirationDateTime = (Get-Date).ToUniversalTime().AddMinutes($ExpirationInMinutes).ToString('o')

if (-not $UseAzCliGraphToken.IsPresent) {
    Ensure-GraphConnection -Scopes $Scopes -TenantId $TenantId -UseDeviceCode:$UseDeviceCode
}

$body = @{
    changeType               = $ChangeType
    notificationUrl          = $notificationUrl
    lifecycleNotificationUrl = $lifecycleNotificationUrl
    resource                 = $Resource
    expirationDateTime       = $expirationDateTime
    clientState              = $ClientState
}

$createUri = "$GraphEndpoint/subscriptions"

Write-Information -MessageData (
    [pscustomobject]@{
        message             = 'Creating Microsoft Graph subscription (delivery via Event Grid partner topic)'
        graphEndpoint       = $GraphEndpoint
        resource            = $Resource
        changeType          = $ChangeType
        note                = "For 'users' subscriptions, Graph delivers user creation as 'updated' notifications (changeType 'created' isn't supported for users)."
        expirationDateTime  = $expirationDateTime
        partnerTopic        = $PartnerTopicName
        resourceGroup       = $ResourceGroupName
        azureSubscriptionId = $AzureSubscriptionId
    }
)


$response = $null
if ($UseAzCliGraphToken.IsPresent) {
    $token = Get-AzCliGraphAccessToken
    $response = Invoke-GraphRest -Method 'POST' -Uri $createUri -Body $body -AccessToken $token
}
else {
    $response = Invoke-MgGraphRequest -Method POST -Uri $createUri -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 8)
}

# Return an object (useful for piping or CI).
$result = [pscustomobject]@{
    subscriptionId           = $response.id
    resource                 = $response.resource
    changeType               = $response.changeType
    expirationDateTime       = $response.expirationDateTime
    clientState              = $ClientState
    notificationUrl          = $notificationUrl
    lifecycleNotificationUrl = $lifecycleNotificationUrl
    partnerTopicName         = $PartnerTopicName
}

if ($AsJson.IsPresent) {
    $result | ConvertTo-Json -Depth 16
}
else {
    $result
}
