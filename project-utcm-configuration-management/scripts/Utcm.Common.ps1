#!/usr/bin/env pwsh
#Requires -Version 7.4

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-UtcmGraphConnected {
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Missing Microsoft Graph PowerShell SDK. Install it: https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0'
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $context = Get-MgContext
    if (-not $context) {
        throw 'Not connected to Microsoft Graph. Run scripts/Connect-UtcmGraph.ps1 first.'
    }
}

function Invoke-UtcmGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [int]$MaxPages = 50
    )

    Assert-UtcmGraphConnected

    $uri = if ($Path.StartsWith('https://', [System.StringComparison]::OrdinalIgnoreCase)) {
        $Path
    }
    else {
        if (-not $Path.StartsWith('/')) { $Path = "/$Path" }
        "https://graph.microsoft.com/beta$Path"
    }

    $parameters = @{ Method = $Method; Uri = $uri }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $parameters.Body = $Body
        $parameters.ContentType = 'application/json'
    }

    $response = Invoke-MgGraphRequest @parameters

    # Paging for collection results.
    if ($null -ne $response -and ($response.PSObject.Properties.Name -contains 'value') -and ($response.value -is [System.Collections.IEnumerable])) {
        $items = @()
        if ($response.value) { $items += @($response.value) }

        $pageCount = 1
        $nextLink = $null
        if ($response.PSObject.Properties.Name -contains '@odata.nextLink') { $nextLink = $response.'@odata.nextLink' }

        while ($nextLink) {
            $pageCount++
            if ($pageCount -gt $MaxPages) {
                throw "Paging exceeded MaxPages ($MaxPages)."
            }

            $next = Invoke-MgGraphRequest -Method GET -Uri $nextLink
            if ($next.value) { $items += @($next.value) }

            if ($next.PSObject.Properties.Name -contains '@odata.nextLink') { $nextLink = $next.'@odata.nextLink' }
            else { $nextLink = $null }
        }

        return $items
    }

    return $response
}

function Get-UtcmConfigurationMonitors {
    [CmdletBinding()]
    param()

    return Invoke-UtcmGraphRequest -Method GET -Path '/admin/configurationManagement/configurationMonitors'
}

function Get-UtcmConfigurationMonitor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$MonitorId
    )

    return Invoke-UtcmGraphRequest -Method GET -Path "/admin/configurationManagement/configurationMonitors/$MonitorId"
}

function New-UtcmConfigurationMonitor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$Monitor
    )

    return Invoke-UtcmGraphRequest -Method POST -Path '/admin/configurationManagement/configurationMonitors' -Body $Monitor
}

function Update-UtcmConfigurationMonitor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$MonitorId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object]$Monitor
    )

    [void](Invoke-UtcmGraphRequest -Method PATCH -Path "/admin/configurationManagement/configurationMonitors/$MonitorId" -Body $Monitor)
}

function New-UtcmSnapshotJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [Parameter()]
        [string]$Description,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Resources
    )

    $body = @{ displayName = $DisplayName; resources = @($Resources) }
    if ($Description) { $body.description = $Description }

    return Invoke-UtcmGraphRequest -Method POST -Path '/admin/configurationManagement/configurationSnapshots/createSnapshot' -Body $body
}

function Get-UtcmMonitoringResults {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$MonitorId
    )

    $items = Invoke-UtcmGraphRequest -Method GET -Path '/admin/configurationManagement/configurationMonitoringResults'
    if ($MonitorId) {
        return $items | Where-Object { $_.monitorId -eq $MonitorId }
    }

    return $items
}

function Get-UtcmDrifts {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$MonitorId
    )

    $items = Invoke-UtcmGraphRequest -Method GET -Path '/admin/configurationManagement/configurationDrifts'
    if ($MonitorId) {
        return $items | Where-Object { $_.monitorId -eq $MonitorId }
    }

    return $items
}
