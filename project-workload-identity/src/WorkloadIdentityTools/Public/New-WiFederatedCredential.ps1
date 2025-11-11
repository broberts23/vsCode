#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Create a federated identity credential for an application.

.DESCRIPTION
Wrapper for New-MgApplicationFederatedIdentityCredential enforcing required fields and defaults.
Docs: New-MgApplicationFederatedIdentityCredential — https://learn.microsoft.com/powershell/module/microsoft.graph.applications/new-mgapplicationfederatedidentitycredential?view=graph-powershell-1.0

.PARAMETER ApplicationId
Target application object ID.
.PARAMETER Name
Unique friendly name for the federated credential.
.PARAMETER Issuer
Issuer URL of external identity provider (e.g., https://token.actions.githubusercontent.com).
.PARAMETER Subject
Subject identifier (e.g., repo:owner/name:ref:branch for GitHub OIDC).
.PARAMETER Audience
Audience; default api://AzureADTokenExchange per docs.

.OUTPUTS
Federated identity credential object.
#>
Function New-WiFederatedCredential {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    [OutputType([psobject])]
    Param(
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$ApplicationId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Issuer,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Subject,
        [Parameter()][ValidateNotNullOrEmpty()][string]$Audience = 'api://AzureADTokenExchange'
    )
    if ($PSCmdlet.ShouldProcess("App $ApplicationId","Add federated credential $Name")) {
        $body = @{ name = $Name; issuer = $Issuer; subject = $Subject; audiences = @($Audience) }
        try {
            $fid = New-MgApplicationFederatedIdentityCredential -ApplicationId $ApplicationId -BodyParameter $body
        } catch {
            Throw "Failed to create federated credential: $($_.Exception.Message)"
        }
        return $fid
    }
}
