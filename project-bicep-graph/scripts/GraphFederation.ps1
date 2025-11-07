#!/usr/bin/env pwsh
Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
<#!
GraphFederation.ps1
Purpose: Placeholder script to create a federated identity credential (workload identity federation) on an application when not yet declaratively supported in Bicep.
Docs:
- Federated identity credentials overview: https://learn.microsoft.com/graph/api/resources/federatedidentitycredentials-overview?view=graph-rest-1.0
- Workload identity federation concepts: https://learn.microsoft.com/azure/active-directory/develop/workload-identity-federation
!>

param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ApplicationObjectId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Issuer = 'https://token.actions.githubusercontent.com',
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Subject = 'repo:OWNER/REPO:pull_request',
    [Parameter()][ValidateNotNullOrEmpty()][string]$Audience = 'api://AzureADTokenExchange',
    [Parameter()][ValidateNotNullOrEmpty()][string]$CredentialName = 'github-pr'
)

function New-FederatedIdentityCredential {
    [CmdletBinding()] [OutputType([pscustomobject])] param(
        [string]$AppObjectId,
        [string]$Issuer,
        [string]$Subject,
        [string]$Audience,
        [string]$Name
    )
    # Placeholder: implement Graph POST using Invoke-PimGraphRequest or Invoke-RestMethod with access token.
    # POST https://graph.microsoft.com/v1.0/applications/{AppObjectId}/federatedIdentityCredentials
    $body = @{ issuer=$Issuer; subject=$Subject; audiences=@($Audience); name=$Name }
    [pscustomobject]@{ RequestBody=$body; AppObjectId=$AppObjectId; Created=$false; Note='Implement Graph call.' }
}

$credential = New-FederatedIdentityCredential -AppObjectId $ApplicationObjectId -Issuer $Issuer -Subject $Subject -Audience $Audience -Name $CredentialName
$credential | ConvertTo-Json -Depth 5
