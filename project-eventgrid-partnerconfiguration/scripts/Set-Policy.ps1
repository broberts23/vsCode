#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyPath = (Join-Path -Path $PSScriptRoot -ChildPath '../src/FunctionApp/policy/policy.json')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -Path $PolicyPath -PathType Leaf)) {
    throw "Policy file not found: $PolicyPath"
}

$policy = Get-Content -Path $PolicyPath -Raw | ConvertFrom-Json -Depth 32

if ($null -eq $policy.version) {
    throw 'Policy missing required field: version'
}

if ($null -eq $policy.allowLists) {
    throw 'Policy missing required field: allowLists'
}

Write-Output ([pscustomobject]@{
        PolicyPath = $PolicyPath
        Version    = $policy.version
        Mode       = $policy.mode
        Rules      = @($policy.rules).Count
    })
