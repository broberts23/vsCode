#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Zip-deploys the Function App code to Azure.

.DESCRIPTION
    Publishes FunctionApp/ to the named Function App. Does not deploy
    infrastructure or grant Exchange Online permissions.

.PARAMETER ResourceGroupName
    Resource group containing the Function App.

.PARAMETER FunctionAppName
    Name of the Function App to publish to.

.EXAMPLE
    ./Deploy-FunctionApp.ps1 -ResourceGroupName rg-exomi-dev -FunctionAppName exomi-func-dev-abc123
#>

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
    $tempFileName = 'exomi-functionapp-{0}.zip' -f ([guid]::NewGuid().Guid)
    return Join-Path ([System.IO.Path]::GetTempPath()) $tempFileName
}

$zipPath = $null

try {
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $context) {
        throw 'Not connected to Azure. Run Connect-AzAccount first.'
    }

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
        Publish-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ArchivePath $zipPath -Force | Out-Null
        Write-Host "Published Function App package to $FunctionAppName" -ForegroundColor Green
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
