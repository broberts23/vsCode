#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Zip-deploys the Function App code to Azure via Azure CLI.

.DESCRIPTION
    Publishes FunctionApp/ to the named Function App. Does not deploy
    infrastructure or grant Exchange Online permissions.

.PARAMETER ResourceGroupName
    Resource group containing the Function App.

.PARAMETER FunctionAppName
    Name of the Function App to publish to.

.PARAMETER SubscriptionId
    Optional subscription to target. When omitted, uses the current az account.

.EXAMPLE
    ./Deploy-FunctionApp.ps1 -ResourceGroupName rg-exomi-dev -FunctionAppName exomi-func-dev-abc123
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$FunctionAppName,

    [Parameter()]
    [string]$SubscriptionId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-AzCliPresent {
    [CmdletBinding()]
    param()

    $az = Get-Command -Name 'az' -ErrorAction SilentlyContinue
    if ($null -eq $az) {
        throw "Azure CLI ('az') not found. Install Azure CLI and run 'az login' first. See https://learn.microsoft.com/cli/azure/install-azure-cli"
    }
}

function Assert-AzLogin {
    [CmdletBinding()]
    param()

    $raw = & az account show --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Not logged into Azure CLI. Run 'az login' first. Details: $raw"
    }
}

$stagingDir = $null

try {
    Assert-AzCliPresent
    Assert-AzLogin

    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
        & az account set --subscription $SubscriptionId --only-show-errors | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to set Azure subscription context to '$SubscriptionId'."
        }
    }

    $projectRoot = Split-Path -Parent $PSScriptRoot
    $functionAppRoot = Join-Path $projectRoot 'FunctionApp'

    if (-not (Test-Path -LiteralPath $functionAppRoot -PathType Container)) {
        throw "Function App folder not found: $functionAppRoot"
    }

    $stagingDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('n'))
    $null = New-Item -Path $stagingDir -ItemType Directory
    $zipPath = Join-Path $stagingDir 'functionapp.zip'

    Copy-Item -Path (Join-Path $functionAppRoot '*') -Destination $stagingDir -Recurse -Force
    Compress-Archive -Path (Join-Path $stagingDir '*') -DestinationPath $zipPath -Force

    if ($PSCmdlet.ShouldProcess($FunctionAppName, 'Publish Function App package')) {
        $raw = & az functionapp deployment source config-zip `
            --resource-group $ResourceGroupName `
            --name $FunctionAppName `
            --src $zipPath `
            --only-show-errors `
            -o json 2>&1

        if ($LASTEXITCODE -ne 0) {
            throw "Zip deploy failed: $raw"
        }

        $result = $raw | ConvertFrom-Json -Depth 32
        Write-Host "Published Function App package to $FunctionAppName" -ForegroundColor Green
        if ($null -ne $result.status) {
            Write-Host "Deployment status: $($result.status)"
        }
    }
}
catch {
    Write-Error $_.Exception.Message
    throw
}
finally {
    if ($stagingDir -and (Test-Path -LiteralPath $stagingDir)) {
        Remove-Item -LiteralPath $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
