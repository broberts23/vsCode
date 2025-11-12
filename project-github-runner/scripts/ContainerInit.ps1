#!/usr/bin/env pwsh
Requires -Version 7.4
<#
.SYNOPSIS
Bootstrap script to run inside the container to ensure required PowerShell modules are installed: Az, Microsoft.Graph.Beta, Microsoft.PowerShell.SecretManagement.

This script is intended to be used as a container init script. It installs modules to the CurrentUser scope and does minimal verification.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Output 'Installing required PowerShell modules (Az, Microsoft.Graph.Beta, Microsoft.PowerShell.SecretManagement)...'

$modules = @('Az.Accounts', 'Az.Resources', 'Az.KeyVault', 'Microsoft.Graph.Beta', 'Microsoft.PowerShell.SecretManagement')
foreach ($m in $modules) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Output "Installing module: $m"
        try {
            Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }
        catch {
            Write-Warning ("Failed to install {0}: {1}" -f $m, $_)
        }
    }
    else {
        Write-Output "Module already available: $m"
    }
}

Write-Output 'Module installation complete.'
