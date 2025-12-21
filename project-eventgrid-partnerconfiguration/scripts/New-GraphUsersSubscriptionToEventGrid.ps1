#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientSecret,

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
    [string]$Resource = 'users',

    [Parameter(Mandatory = $false)]
    [ValidateSet('updated', 'updated,deleted')]
    [string]$ChangeType = 'updated',

    [Parameter(Mandatory = $false)]
    [ValidateRange(45, 41760)]
    [int]$ExpirationInMinutes = 40320,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ClientState,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$GraphEndpoint = 'https://graph.microsoft.com/v1.0'
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

function Get-GraphAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret
    )

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = 'https://graph.microsoft.com/.default'
        grant_type    = 'client_credentials'
    }

    if ([string]::IsNullOrWhiteSpace($tokenResponse.access_token)) {
        throw 'Failed to acquire Microsoft Graph access token (empty access_token).'
    }

    return $tokenResponse.access_token
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

$accessToken = Get-GraphAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

$headers = @{ Authorization = "Bearer $accessToken" }

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
        expirationDateTime  = $expirationDateTime
        partnerTopic        = $PartnerTopicName
        resourceGroup       = $ResourceGroupName
        azureSubscriptionId = $AzureSubscriptionId
    }
)

$response = Invoke-RestMethod -Method Post -Uri $createUri -Headers $headers -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 8)

# Return an object (useful for piping or CI).
[pscustomobject]@{
    subscriptionId           = $response.id
    resource                 = $response.resource
    changeType               = $response.changeType
    expirationDateTime       = $response.expirationDateTime
    clientState              = $ClientState
    notificationUrl          = $notificationUrl
    lifecycleNotificationUrl = $lifecycleNotificationUrl
    partnerTopicName         = $PartnerTopicName
}
