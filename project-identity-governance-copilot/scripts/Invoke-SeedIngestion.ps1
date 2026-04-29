#!/usr/bin/env pwsh
#Requires -Version 7.4

# This is the PowerShell wrapper around the Python indexing pipeline.
# Think of it as setting process-level environment variables, then calling two focused scripts.

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('seed', 'noisy')]
    [string]$DatasetPack = 'seed',

    [Parameter()]
    [string]$PythonCommand = 'python'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$datasetRoot = Resolve-Path (Join-Path $projectRoot '..\shared\identity_seed\datasets')

# These process-scoped environment variables are how the Python code discovers which dataset pack to load.
$env:IDENTITY_DATASET_ROOT = $datasetRoot.Path
$env:IDENTITY_DATASET_PACK = $DatasetPack

Write-Information "Building search index." -InformationAction Continue
& $PythonCommand (Join-Path $projectRoot 'src/search/build_index.py')

Write-Information "Loading $DatasetPack dataset into Azure AI Search." -InformationAction Continue
& $PythonCommand (Join-Path $projectRoot 'src/search/load_documents.py')