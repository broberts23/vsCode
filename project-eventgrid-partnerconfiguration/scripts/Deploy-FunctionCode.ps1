#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$SourcePath = (Join-Path -Path $PSScriptRoot -ChildPath '../src/FunctionApp')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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

Assert-AzCliPresent
Assert-AzLogin

if (-not (Test-Path -Path $SourcePath -PathType Container)) {
    throw "SourcePath not found: $SourcePath"
}

& az account set --subscription $SubscriptionId --only-show-errors | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to set Azure subscription context to '$SubscriptionId'."
}

$stagingDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.Guid]::NewGuid().ToString('n'))
$null = New-Item -Path $stagingDir -ItemType Directory

try {
    $zipPath = Join-Path -Path $stagingDir -ChildPath 'functionapp.zip'

    Copy-Item -Path (Join-Path -Path $SourcePath -ChildPath '*') -Destination $stagingDir -Recurse -Force

    if (Test-Path -Path $zipPath -PathType Leaf) {
        Remove-Item -Path $zipPath -Force
    }

    Compress-Archive -Path (Join-Path -Path $stagingDir -ChildPath '*') -DestinationPath $zipPath -Force

    $raw = & az functionapp deployment source config-zip \
    --resource-group $ResourceGroupName \
    --name $FunctionAppName \
    --src $zipPath \
    --only-show-errors -o json 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "Zip deploy failed: $raw"
    }

    $result = $raw | ConvertFrom-Json -Depth 32

    [pscustomobject]@{
        message          = 'Function code deployed (zip deploy)'
        functionAppName  = $FunctionAppName
        resourceGroup    = $ResourceGroupName
        deploymentStatus = $result.status
        deploymentId     = $result.id
        active           = $result.active
    }
}
finally {
    Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
}
