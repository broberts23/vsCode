#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$FunctionAppName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-TemporaryZipPath {
    $tempFileName = 'agent-vending-machine-{0}.zip' -f ([guid]::NewGuid().Guid)
    return Join-Path ([System.IO.Path]::GetTempPath()) $tempFileName
}

try {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $functionAppRoot = Join-Path $projectRoot 'FunctionApp'

    if (-not (Test-Path -LiteralPath $functionAppRoot)) {
        throw "Function App folder not found: $functionAppRoot"
    }

    $zipPath = New-TemporaryZipPath
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }

    Compress-Archive -Path (Join-Path $functionAppRoot '*') -DestinationPath $zipPath -Force

    if ($PSCmdlet.ShouldProcess($FunctionAppName, 'Publish Function App package')) {
        Publish-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ArchivePath $zipPath -Force
        Write-Host "Published Function App package to $FunctionAppName"
    }
}
catch {
    Write-Error $_.Exception.Message
    throw
}
finally {
    if ($zipPath -and (Test-Path -LiteralPath $zipPath)) {
        Remove-Item -LiteralPath $zipPath -Force
    }
}