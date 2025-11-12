#!/usr/bin/env pwsh
#Requires -Version 7.4
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $AppObjectId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Name,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Issuer,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Subject
)

<#
.SYNOPSIS
Adds a federated identity credential to an existing Entra application using Microsoft Graph (beta).

.NOTES
Requires Microsoft.Graph.Beta module and an interactive Connect-MgGraph session with Application.ReadWrite.All.
Microsoft Graph PowerShell docs (beta): https://learn.microsoft.com/powershell/microsoftgraph/overview?view=graph-powershell-beta
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Verbose 'Ensuring Microsoft.Graph.Beta is available...'
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Beta)) {
    Write-Verbose 'Installing Microsoft.Graph.Beta module (CurrentUser)...'
    Install-Module -Name Microsoft.Graph.Beta -Scope CurrentUser -Force -AllowClobber
}

Import-Module Microsoft.Graph.Beta -Force

# Ensure an authenticated Graph session exists
try { $profile = Get-MgProfile -ErrorAction SilentlyContinue } catch { $profile = $null }
if (-not $profile) { Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'Directory.ReadWrite.All' }

if ($PSCmdlet.ShouldProcess("Application/$AppObjectId", "Create federatedIdentityCredential '$Name'")) {
    $body = [PSCustomObject]@{
        name        = $Name
        issuer      = $Issuer
        subject     = $Subject
        description = 'Created by project-github-runner'
        audiences   = @('api://AzureADTokenExchange')
    }

    $uri = "https://graph.microsoft.com/beta/applications/$AppObjectId/federatedIdentityCredentials"
    try {
        $resp = Invoke-MgGraphRequest -Method POST -Uri $uri -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json'
        return $resp
    }
    catch { throw $_ }
}
