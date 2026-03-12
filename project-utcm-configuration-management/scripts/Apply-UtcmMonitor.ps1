#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$MonitorId,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$MonitorJsonPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/Utcm.Common.ps1"

$monitor = Get-Content -Path $MonitorJsonPath -Raw | ConvertFrom-Json -Depth 100

if ($MonitorId) {
    Update-UtcmConfigurationMonitor -MonitorId $MonitorId -Monitor $monitor
    [PSCustomObject]@{ action = 'updated'; monitorId = $MonitorId; displayName = $monitor.displayName }
}
else {
    $created = New-UtcmConfigurationMonitor -Monitor $monitor
    # Create returns the monitor object per API docs, but handle null defensively.
    [PSCustomObject]@{ action = 'created'; monitorId = $created.id; displayName = $created.displayName; raw = $created }
}
