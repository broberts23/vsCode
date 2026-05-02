#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$FunctionAppName,

    [Parameter()]
    [string]$SourcePath,

    [Parameter()]
    [bool]$RunTests = $true
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

if ($RunTests) {
    $testsPath = Join-Path $projectRoot 'tests'
    if (Test-Path $testsPath) {
        Invoke-ProjectTests -TestsPath $testsPath
    }
}

$funcCommand = Get-Command -Name func -ErrorAction SilentlyContinue
if (-not $funcCommand) {
    throw 'Azure Functions Core Tools (`func`) is required to publish the Function App.'
}

Push-Location $SourcePath
try {
    if ($PSCmdlet.ShouldProcess($FunctionAppName, 'Publish Function App code')) {
        & $funcCommand.Source azure functionapp publish $FunctionAppName --powershell
    }
}
finally {
    Pop-Location
}