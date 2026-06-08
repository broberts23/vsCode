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
    # Step up one directory and run Python scripts for search index creation and document upload.
    Invoke-PythonStep -ScriptPath (Join-Path $projectRoot 'src/search/build_index.py') -FailureMessage "Failed to create search index"
    Invoke-PythonStep -ScriptPath (Join-Path $projectRoot 'src/search/load_documents.py') -FailureMessage "Failed to upload documents"
}
finally {
    Pop-Location
}
