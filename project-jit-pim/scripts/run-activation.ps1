#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('\S')]
    [string] $RoleId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('\S')]
    [string] $ResourceId,

    [Parameter(Mandatory = $false)]
    [string] $Justification = 'CI triggered activation'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Import the PimAutomation module from the scripts folder relative to this script
try {
    $scriptPath = $MyInvocation.MyCommand.Definition
    if (-not $scriptPath) { $scriptPath = $PSScriptRoot }
    $scriptDir = if ($scriptPath) { Split-Path -Path $scriptPath -Parent } else { Split-Path -Path $PSCommandPath -Parent }
    $modulePath = Join-Path $scriptDir 'PimAutomation.psm1'
    if (-not (Test-Path $modulePath)) {
        Write-Error ("Module file not found at expected path: {0}" -f $modulePath)
        throw 'PimAutomation module not found. Ensure the script is executed from the repository checkout and the scripts folder exists.'
    }
    # Suppress PowerShell's module-import verbose chatter (Importing function/alias/cmdlet) which
    # appears when callers run with -Verbose. Restore previous preference after import.
    $__oldVerbosePreference = $VerbosePreference
    $VerbosePreference = 'SilentlyContinue'
    try {
        Import-Module -Name $modulePath -Force -ErrorAction Stop -Verbose:$false
    }
    finally {
        $VerbosePreference = $__oldVerbosePreference
    }
}
catch {
    Write-Error ("Failed to import PimAutomation module: {0}" -f $_)
    throw
}

# If the resourceId looks like a Key Vault resource, derive the vault name so the lifecycle helper
# can rotate a secret without requiring callers to pass the vault name explicitly.
$vaultName = $null
if ($ResourceId -match '/providers/Microsoft.KeyVault/vaults/([^/]+)$') {
    $vaultName = $matches[1]
}

if ($vaultName) {
    Write-Verbose "Rotating secrets in vault $vaultName"

    # Resolve assignee object id from environment (set by workflow using RBAC-based lookup).
    $assignee = $env:ASSIGNEE_OBJECT_ID
    if (-not $assignee -or $assignee.Trim() -eq '') {
        throw 'ASSIGNEE_OBJECT_ID must be pre-populated by the workflow. Ensure the workflow step exports it via az role assignment list and $GITHUB_ENV.'
    }

    # Vault resource id - use the provided ResourceId
    $vaultResourceId = $ResourceId

    $assigneePreview = if ($assignee.Length -ge 8) { $assignee.Substring(0, 8) } else { $assignee }

    # Diagnostic logging to help troubleshoot RBAC/role-assignment failures
    Write-Verbose "Invoking Invoke-TempKeyVaultRotationLifecycle with VaultName='$vaultName', VaultResourceId='$vaultResourceId', AssigneeObjectId='${assigneePreview}'"

    # Use the lifecycle helper (it will generate a random secret value internally)
    try {
        $lifecycleResult = Invoke-TempKeyVaultRotationLifecycle -VaultName $vaultName -AssigneeObjectId $assignee -VaultResourceId $vaultResourceId -RoleDefinitionId $RoleId -Verbose
    }
    catch {
        Write-Error ("Invoke-TempKeyVaultRotationLifecycle failed: {0}" -f $_)
        throw
    }

    $out = [pscustomobject]@{
        vault      = $vaultName
        lifecycle  = $lifecycleResult
        justification = $Justification
    }
}
else {
    $out = [pscustomobject]@{
        resourceId   = $ResourceId
        roleId       = $RoleId
        justification = $Justification
        note         = 'Resource is not a Key Vault; no rotation performed.'
    }
}

Write-Output ($out | ConvertTo-Json -Depth 6)
