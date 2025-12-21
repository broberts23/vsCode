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

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Location = 'westeurope',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ParametersFile = (Join-Path -Path $PSScriptRoot -ChildPath '../infra/parameters.dev.bicepparam')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Verbose "Deploying infra to RG '$ResourceGroupName' in subscription '$SubscriptionId'"
Write-Verbose "Parameters: $ParametersFile"

# This is intentionally a stub scaffold.
# Choose one deployment approach and implement it:
# - Az PowerShell: New-AzResourceGroupDeployment (https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroupdeployment?view=azps-latest)
# - Azure CLI: az deployment group create

throw 'Not implemented: wire this script to your preferred deployment toolchain.'
