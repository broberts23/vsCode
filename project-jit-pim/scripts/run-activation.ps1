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

    # Resolve assignee object id. Prefer explicit env var ASSIGNEE_OBJECT_ID, otherwise try to derive
    # using Azure CLI (preferred in CI) or fallback to Az cmdlets if available.
    $assignee = $env:ASSIGNEE_OBJECT_ID
    if (-not $assignee -or $assignee.Trim() -eq '') {
        Write-Verbose 'ASSIGNEE_OBJECT_ID not provided; attempting to derive from environment (Azure CLI or Az modules).'

        # Try Azure CLI: if AZURE_CLIENT_ID exists, the login may be a service principal
        try {
            if (Get-Command az -ErrorAction SilentlyContinue) {
                if ($env:AZURE_CLIENT_ID) {
                    try {
                        $spId = (& az ad sp show --id $env:AZURE_CLIENT_ID --query objectId -o tsv) -as [string]
                        if ($spId -and $spId.Trim()) { $assignee = $spId.Trim(); Write-Verbose "Derived assignee from service principal: $($assignee.Substring(0,6))..." }
                    } catch { Write-Verbose "az ad sp show failed: $_" }
                }

                if (-not $assignee) {
                    try {
                        $userId = (& az ad signed-in-user show --query objectId -o tsv) -as [string]
                        if ($userId -and $userId.Trim()) { $assignee = $userId.Trim(); Write-Verbose "Derived assignee from signed-in user: $($assignee.Substring(0,6))..." }
                    } catch { Write-Verbose "az signed-in-user lookup failed: $_" }
                }
            }
        } catch { Write-Verbose "Azure CLI not available or lookup failed: $_" }

        # Fallback: try Az cmdlets if installed and available
        if (-not $assignee -or $assignee.Trim() -eq '') {
            try {
                if (Get-Command Get-AzADServicePrincipal -ErrorAction SilentlyContinue) {
                    if ($env:AZURE_CLIENT_ID) {
                        try {
                            $sp = Get-AzADServicePrincipal -ApplicationId $env:AZURE_CLIENT_ID -ErrorAction Stop
                            if ($sp -and $sp.Id) { $assignee = $sp.Id; Write-Verbose "Derived assignee from Az module (service principal): $($assignee.Substring(0,6))..." }
                        } catch { Write-Verbose "Get-AzADServicePrincipal failed: $_" }
                    }
                }
            } catch { }
        }

        if (-not $assignee -or $assignee.Trim() -eq '') {
            throw 'ASSIGNEE_OBJECT_ID is not set and could not be derived. Set ASSIGNEE_OBJECT_ID in the workflow environment or ensure Azure CLI/Az modules can resolve the current principal.'
        }
    }

    # Vault resource id - use the provided ResourceId
    $vaultResourceId = $ResourceId

    # Use the lifecycle helper (it will generate a random secret value internally)
    $lifecycleResult = Invoke-TempKeyVaultRotationLifecycle -VaultName $vaultName -SecretName ("auto-rotated-secret") -AssigneeObjectId $assignee -VaultResourceId $vaultResourceId -Verbose

    $out = [pscustomobject]@{
        request = $req
        lifecycle = $lifecycleResult
    }
} else {
    $out = $req
}

Write-Output ($out | ConvertTo-Json -Depth 6)
