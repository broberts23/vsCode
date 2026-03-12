#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$MonitorId,

    [Parameter()]
    [switch]$FailOnDrift
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/Utcm.Common.ps1"

$monitor = Get-UtcmConfigurationMonitor -MonitorId $MonitorId
$results = Get-UtcmMonitoringResults -MonitorId $MonitorId | Sort-Object -Property runInitiationDateTime -Descending
$latestResult = $results | Select-Object -First 1
$drifts = Get-UtcmDrifts -MonitorId $MonitorId | Where-Object { $_.status -eq 'active' }

$report = [PSCustomObject]@{
    monitorId                  = $MonitorId
    displayName                = $monitor.displayName
    status                     = $monitor.status
    mode                       = $monitor.mode
    monitorRunFrequencyInHours = $monitor.monitorRunFrequencyInHours
    latestRunStatus            = $latestResult.runStatus
    latestRunInitiated         = $latestResult.runInitiationDateTime
    latestRunCompleted         = $latestResult.runCompletionDateTime
    driftsCount                = $latestResult.driftsCount
    activeDriftsCount          = @($drifts).Count
    activeDrifts               = $drifts
}

if ($FailOnDrift -and @($drifts).Count -gt 0) {
    $message = "Drift detected for monitor '$($monitor.displayName)' ($MonitorId). Active drifts: $(@($drifts).Count)."
    throw $message
}

$report
