[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('\S')]
    [string] $RoleId,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('\S')]
    [string] $ResourceId,

    [Parameter(Mandatory=$false)]
    [string] $Justification = 'CI triggered activation'
)

Import-Module -Name (Join-Path $PSScriptRoot 'PimAutomation.psm1')

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
    if (-not $env:ASSIGNEE_OBJECT_ID) { Write-Verbose 'ASSIGNEE_OBJECT_ID env var not set; supply the automation principal objectId as ASSIGNEE_OBJECT_ID in CI.' }
    # Vault resource id - use the provided ResourceId
    $vaultResourceId = $ResourceId

    # Use the lifecycle helper (it will generate a random secret value internally)
    $lifecycleResult = Invoke-TempKeyVaultRotationLifecycle -VaultName $vaultName -SecretName ("auto-rotated-secret") -AssigneeObjectId $env:ASSIGNEE_OBJECT_ID -VaultResourceId $vaultResourceId -Verbose

    $out = [pscustomobject]@{
        request = $req
        lifecycle = $lifecycleResult
    }
} else {
    $out = $req
}

Write-Output ($out | ConvertTo-Json -Depth 6)
