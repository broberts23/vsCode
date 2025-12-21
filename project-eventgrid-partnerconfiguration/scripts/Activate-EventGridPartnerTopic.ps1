#!/usr/bin/env pwsh
#Requires -Version 7.4

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

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ApiVersion = '2025-02-15',

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-AzCliPresent {
    [CmdletBinding()]
    param()

    $az = Get-Command -Name 'az' -ErrorAction SilentlyContinue
    if ($null -eq $az) {
        throw "Azure CLI ('az') not found. Install Azure CLI and run 'az login' first. See https://learn.microsoft.com/cli/azure/install-azure-cli"
    }
}

function Invoke-AzRestJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,

        [Parameter(Mandatory = $false)]
        [string]$Body
    )

    $arguments = @(
        'rest',
        '--method', $Method,
        '--url', $Url
    )

    if (-not [string]::IsNullOrWhiteSpace($Body)) {
        $arguments += @('--headers', 'Content-Type=application/json', '--body', $Body)
    }

    $raw = & az @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "az rest failed ($Method $Url): $raw"
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }

    try {
        return ($raw | ConvertFrom-Json -Depth 64)
    }
    catch {
        # Some management actions return empty bodies.
        return $null
    }
}

Assert-AzCliPresent

$resourceUrl = "https://management.azure.com/subscriptions/$AzureSubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.EventGrid/partnerTopics/$PartnerTopicName?api-version=$ApiVersion"
$activateUrl = "https://management.azure.com/subscriptions/$AzureSubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.EventGrid/partnerTopics/$PartnerTopicName/activate?api-version=$ApiVersion"

$topic = Invoke-AzRestJson -Method GET -Url $resourceUrl
$activationState = $topic.properties.activationState

if ($activationState -eq 'Activated') {
    [pscustomobject]@{
        message          = 'Partner topic already activated'
        partnerTopicName = $PartnerTopicName
        activationState  = $activationState
        id               = $topic.id
    }
    return
}

Write-Information -MessageData (
    [pscustomobject]@{
        message                = 'Activating partner topic'
        partnerTopicName       = $PartnerTopicName
        currentActivationState = $activationState
        apiVersion             = $ApiVersion
    }
)

$activated = $false
$activateError = $null

try {
    # Preferred: explicit activate action (used by the portal).
    Invoke-AzRestJson -Method POST -Url $activateUrl | Out-Null
    $activated = $true
}
catch {
    $activateError = $_
}

if (-not $activated) {
    # Fallback: PUT the resource with activationState updated.
    # This is best-effort and may fail if the RP requires the explicit /activate action.
    $location = $topic.location
    if ([string]::IsNullOrWhiteSpace($location)) {
        throw "Unable to determine partner topic location from GET response; cannot attempt PUT fallback. Activate error: $activateError"
    }

    $updatedBody = [ordered]@{
        location   = $location
        properties = [ordered]@{
            activationState = 'Activated'
        }
    } | ConvertTo-Json -Depth 16

    try {
        Invoke-AzRestJson -Method PUT -Url $resourceUrl -Body $updatedBody | Out-Null
        $activated = $true
    }
    catch {
        throw "Partner topic activation failed via POST /activate and PUT fallback. POST error: $activateError. PUT error: $_"
    }
}

# Poll for state transition.
$deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
$final = $null

while ((Get-Date).ToUniversalTime() -lt $deadline) {
    Start-Sleep -Seconds 5
    $final = Invoke-AzRestJson -Method GET -Url $resourceUrl
    if ($final.properties.activationState -eq 'Activated') {
        break
    }
}

if ($null -eq $final) {
    $final = Invoke-AzRestJson -Method GET -Url $resourceUrl
}

[pscustomobject]@{
    message          = 'Partner topic activation attempted'
    partnerTopicName = $PartnerTopicName
    activationState  = $final.properties.activationState
    id               = $final.id
    apiVersion       = $ApiVersion
}
