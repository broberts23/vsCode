#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
Install required PowerShell modules for the toolkit.
#>
[CmdletBinding()] Param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


Function Install-IfMissing {
    Param([string]$Name, [string]$Version)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Information "Installing $Name $Version" -InformationAction Continue
        Install-Module -Name $Name -RequiredVersion $Version -Scope CurrentUser -Force -AllowClobber
    }
    else {
        Write-Information "$Name already present" -InformationAction Continue
    }
}

# Install only the minimal Microsoft Graph submodules required by the toolkit
# - Authentication: Connect-MgGraph / Invoke-MgGraphRequest
Install-IfMissing -Name Microsoft.Graph.Authentication -Version '2.32.0'

# - Applications: Get-MgApplication, New-MgApplicationFederatedIdentityCredential, Add-MgApplicationKey
Install-IfMissing -Name Microsoft.Graph.Applications -Version '2.32.0'

# - Authorization policy (consent posture): Get-MgPolicyAuthorizationPolicy
Install-IfMissing -Name Microsoft.Graph.Identity.SignIns -Version '2.32.0'

# - Directory roles and members: Get-MgDirectoryRole, Get-MgDirectoryRoleMember
Install-IfMissing -Name Microsoft.Graph.Identity.DirectoryManagement -Version '2.32.0'

# Note: Risky workload identity cmdlets use Invoke-MgGraphRequest against REST beta endpoints; no beta module is required.
Write-Information 'Module installation complete.' -InformationAction Continue
