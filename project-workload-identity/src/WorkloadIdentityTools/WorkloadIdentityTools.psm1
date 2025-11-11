#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Dot-source Public functions
Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' | ForEach-Object { . $_.FullName }
# Dot-source Private helpers
If (Test-Path (Join-Path $PSScriptRoot 'Private')) {
    Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' | ForEach-Object { . $_.FullName }
}
