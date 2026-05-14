#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Prompt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location $projectRoot
try {
    python ./src/app.py --prompt $Prompt
    if ($LASTEXITCODE -ne 0) {
        throw 'Chat smoke test failed.'
    }
}
finally {
    Pop-Location
}
