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
    Import-Module -Name $modulePath -Force -ErrorAction Stop
}
catch {
    Write-Error ("Failed to import PimAutomation module: {0}" -f $_)
    throw
}

Write-Verbose 'Connect to Graph: for demos this uses interactive auth. TODO: configure OIDC or managed identity for CI.'
Connect-PimGraph -Verbose

$req = New-PimActivationRequest -RoleId $RoleId -ResourceId $ResourceId -Justification $Justification

# If the resourceId looks like a Key Vault resource, derive the vault name so the lifecycle helper
# can rotate a secret without requiring callers to pass the vault name explicitly.
$vaultName = $null
if ($ResourceId -match '/providers/Microsoft.KeyVault/vaults/([^/]+)$') {
    $vaultName = $matches[1]
}

if ($vaultName) {
    Write-Verbose "Rotating secret in vault $vaultName under request $($req.requestId)"

    # Resolve assignee object id from environment (set by workflow using RBAC-based lookup).
    $assignee = $env:ASSIGNEE_OBJECT_ID
    if (-not $assignee -or $assignee.Trim() -eq '') {
        throw 'ASSIGNEE_OBJECT_ID must be pre-populated by the workflow. Ensure the workflow step exports it via az role assignment list and $GITHUB_ENV.'
    }

    # Vault resource id - use the provided ResourceId
    $vaultResourceId = $ResourceId

    # Diagnostic logging to help troubleshoot RBAC/role-assignment failures
    Write-Verbose "Invoking Invoke-TempKeyVaultRotationLifecycle with VaultName='$vaultName', VaultResourceId='$vaultResourceId', AssigneeObjectId='${assignee.Substring(0,8)}...', SecretName='auto-rotated-secret'"

    # Use the lifecycle helper (it will generate a random secret value internally)
    try {
        $lifecycleResult = Invoke-TempKeyVaultRotationLifecycle -VaultName $vaultName -SecretName ("auto-rotated-secret") -AssigneeObjectId $assignee -VaultResourceId $vaultResourceId -RoleDefinitionId $RoleId -Verbose
    }
    catch {
        Write-Error ("Invoke-TempKeyVaultRotationLifecycle failed: {0}" -f $_)
        throw
    }

    $out = [pscustomobject]@{
        request   = $req
        lifecycle = $lifecycleResult
    }
}
else {
    $out = $req
}

Write-Output ($out | ConvertTo-Json -Depth 6)
