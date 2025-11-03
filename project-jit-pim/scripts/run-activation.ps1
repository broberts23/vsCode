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

        $clientId = $env:AZURE_CLIENT_ID
        $tenantId = $env:AZURE_TENANT_ID

        # Try Azure CLI: resolve service principal by application id (requires Graph Application.Read.All)
        try {
            if (Get-Command az -ErrorAction SilentlyContinue) {
                if ($clientId) {
                    try {
                        $spId = (& az ad sp show --id $clientId --query objectId -o tsv) -as [string]
                        if ($spId -and $spId.Trim()) { $assignee = $spId.Trim(); Write-Verbose "Derived assignee from service principal: $($assignee.Substring(0,6))..." }
                    } catch { Write-Verbose "az ad sp show failed: $_" }
                }

                # For app-only identities without directory read, fall back to ARM RBAC lookups
                if (-not $assignee -and $clientId) {
                    $subscriptionId = $null
                    if ($ResourceId -match '^/subscriptions/([^/]+)/') { $subscriptionId = $matches[1] }
                    if (-not $subscriptionId -and $env:AZURE_SUBSCRIPTION_ID) { $subscriptionId = $env:AZURE_SUBSCRIPTION_ID }

                    if ($subscriptionId) {
                        try {
                            $principalId = (& az role assignment list --assignee $clientId --scope "/subscriptions/$subscriptionId" --query '[0].principalId' -o tsv) -as [string]
                            if ($principalId -and $principalId.Trim()) {
                                $assignee = $principalId.Trim()
                                Write-Verbose "Derived assignee from role assignment: $($assignee.Substring(0,6))..."
                            }
                        } catch { Write-Verbose "az role assignment list lookup failed: $_" }
                    }
                }
            }
        } catch { Write-Verbose "Azure CLI not available or lookup failed: $_" }

        # Fallback: try Az cmdlets if installed and available
        if (-not $assignee -or $assignee.Trim() -eq '') {
            try {
                if (Get-Command Get-AzADServicePrincipal -ErrorAction SilentlyContinue) {
                    if ($clientId) {
                        try {
                            $sp = Get-AzADServicePrincipal -ApplicationId $clientId -ErrorAction Stop
                            if ($sp -and $sp.Id) { $assignee = $sp.Id; Write-Verbose "Derived assignee from Az module (service principal): $($assignee.Substring(0,6))..." }
                        } catch { Write-Verbose "Get-AzADServicePrincipal failed: $_" }
                    }
                }
            } catch { }
        }

        if (-not $assignee -or $assignee.Trim() -eq '') {
            throw 'ASSIGNEE_OBJECT_ID is not set and could not be derived. Provide ASSIGNEE_OBJECT_ID in the workflow (preferred) or grant permissions so az can resolve the current principal.'
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
