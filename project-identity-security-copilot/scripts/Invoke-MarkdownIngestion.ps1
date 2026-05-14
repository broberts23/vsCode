#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PythonStep {
    param(
        [Parameter(Mandatory)]
        [string]$ScriptPath,

        [Parameter(Mandatory)]
        [string]$FailureMessage
    )

    python $ScriptPath
    if ($LASTEXITCODE -ne 0) {
        throw $FailureMessage
    }
}

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location $projectRoot
try {
    Invoke-PythonStep -ScriptPath './src/search/build_index.py' -FailureMessage 'Search index creation failed.'
    Invoke-PythonStep -ScriptPath './src/search/load_documents.py' -FailureMessage 'Document upload failed.'
}
finally {
    Pop-Location
}
