#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$FunctionAppName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter()]
    [string]$SourcePath,

    [Parameter()]
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-ProjectTests {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TestsPath
    )

    $pesterCommand = Get-Command -Name Invoke-Pester -ErrorAction SilentlyContinue
    if (-not $pesterCommand) {
        throw 'Pester is required to run the Function App tests.'
    }

    $result = Invoke-Pester -Path $TestsPath -PassThru
    if ($result -and $result.PSObject.Properties.Name -contains 'FailedCount' -and $result.FailedCount -gt 0) {
        throw "Pester reported $($result.FailedCount) failed tests."
    }
}

$projectRoot = Split-Path $PSScriptRoot -Parent
if (-not $SourcePath) {
    $SourcePath = Join-Path $projectRoot 'FunctionApp'
}

$publishCommand = Get-Command -Name Publish-AzWebApp -ErrorAction SilentlyContinue
if (-not $publishCommand) {
    throw 'Publish-AzWebApp is required to publish the Function App. Install or import the Az.Websites module.'
}

if (-not $SkipTests) {
    $testsPath = Join-Path $projectRoot 'tests'
    if (Test-Path $testsPath) {
        Invoke-ProjectTests -TestsPath $testsPath
    }
}

$items = Get-ChildItem -Path $SourcePath -Force
if (-not $items) {
    throw "Function app source path is empty: $SourcePath"
}

$zipPath = Join-Path ([System.IO.Path]::GetTempPath()) ("functionapp-{0}.zip" -f (Get-Date -Format 'yyyyMMddHHmmss'))
try {
    $itemPaths = $items | Select-Object -ExpandProperty FullName
    Compress-Archive -Path $itemPaths -DestinationPath $zipPath -CompressionLevel Optimal

    if (-not (Test-Path $zipPath)) {
        throw "Failed to create deployment package at: $zipPath"
    }

    if ($PSCmdlet.ShouldProcess($FunctionAppName, 'Publish Function App code with zipdeploy')) {
        Publish-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ArchivePath $zipPath -ErrorAction Stop | Out-Null
    }
}
finally {
    if (Test-Path $zipPath) {
        Remove-Item -Path $zipPath -Force
    }
}