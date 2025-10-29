#!/usr/bin/env pwsh
Requires -Version 7.4

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
    [Parameter(Mandatory=$true)]
    [string] $RoleId,

    [Parameter(Mandatory=$true)]
    [string] $ResourceId,

    [Parameter(Mandatory=$false)]
    [string] $Justification = 'CI triggered activation',

    [Parameter(Mandatory=$false)]
    [string] $VaultName,

    [Parameter(Mandatory=$false)]
    [string] $SecretName
)

Import-Module -Name (Join-Path $PSScriptRoot 'PimAutomation.psm1')


Write-Verbose 'Connect to Graph: for demos this uses interactive auth. TODO: configure OIDC or managed identity for CI.'
Connect-PimGraph -Verbose

$req = New-PimActivationRequest -RoleId $RoleId -ResourceId $ResourceId -Justification $Justification

if ($VaultName -and $SecretName) {
    Write-Verbose "Rotating secret $SecretName in vault $VaultName under request $($req.requestId)"
    # For RBAC demo we require the assignee object id (the automation principal objectId)
    if (-not $env:ASSIGNEE_OBJECT_ID) {
        Write-Verbose 'ASSIGNEE_OBJECT_ID env var not set; supply the automation principal objectId as ASSIGNEE_OBJECT_ID in CI.'
    }
    if (-not $env:VAULT_RESOURCE_ID) {
        Write-Verbose 'VAULT_RESOURCE_ID env var not set; supply the Key Vault resource id as VAULT_RESOURCE_ID in CI.'
    }

    $rotation = Rotate-KeyVaultSecretWithPim -VaultName $VaultName -SecretName $SecretName -RequestId $req.requestId -AssigneeObjectId $env:ASSIGNEE_OBJECT_ID -VaultResourceId $env:VAULT_RESOURCE_ID
    $out = [pscustomobject]@{
        request = $req
        rotation = $rotation
    }
} else {
    $out = $req
}

Write-Output ($out | ConvertTo-Json -Depth 6)
