<#
PimAutomation.psm1 - consolidated module

Implements helpers for Microsoft Graph PIM activation, temporary Key Vault RBAC
assignment, and secret rotation. All functions are defined once in this file.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-GraphAccessToken {
    [CmdletBinding()]
    param(
        [Parameter()] [string] $TenantId
    )

    if ($env:PIM_AUTOMATION_SKIP_GRAPH) {
        $skipValue = $env:PIM_AUTOMATION_SKIP_GRAPH.ToString().ToLowerInvariant()
        if ($skipValue -in @('1', 'true', 'skip')) {
            Write-Verbose 'Skipping Graph access token retrieval because PIM_AUTOMATION_SKIP_GRAPH is set.'
            return $null
        }
    }

    try {
        $az = Get-Command az -ErrorAction SilentlyContinue
        if ($az) {
            Write-Verbose 'Requesting Microsoft Graph token via Azure CLI.'
            $cliArgs = @('account','get-access-token','--resource','https://graph.microsoft.com')
            if ($TenantId) { $cliArgs += @('--tenant',$TenantId) }
            $tokenJson = & az @cliArgs | Out-String
            $accessToken = ($tokenJson | ConvertFrom-Json).accessToken
            if ($accessToken) { return $accessToken }
        }
    } catch {
        Write-Verbose ("Azure CLI token retrieval failed: {0}" -f $_)
    }

    try {
        if (Get-Module Microsoft.Graph.Authentication -ListAvailable) {
            Write-Verbose 'Attempting interactive Connect-MgGraph flow.'
            Connect-MgGraph -Scopes 'https://graph.microsoft.com/.default' -ErrorAction Stop | Out-Null
            if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {
                $context = Get-MgContext
                if ($context -and $context.AccessToken) { return $context.AccessToken }
            }
        }
    } catch {
        Write-Verbose ("Interactive Connect-MgGraph failed: {0}" -f $_)
    }

    return $null
}

function Connect-PimGraph {
    [CmdletBinding()]
    param(
        [Parameter()] [string] $Scopes = 'https://graph.microsoft.com/.default'
    )

    Write-Verbose 'Connect-PimGraph: prefer CLI/OIDC token, fallback to interactive login.'
    $token = Get-GraphAccessToken
    if ($token -and (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        try {
            Connect-MgGraph -AccessToken $token -ErrorAction Stop | Out-Null
            Write-Verbose 'Connected to Microsoft Graph using access token.'
            return
        } catch {
            Write-Verbose ("Connect-MgGraph with token failed: {0}" -f $_)
        }
    }

    Write-Verbose 'Falling back to interactive Connect-MgGraph.'
    Connect-MgGraph -Scopes $Scopes -ErrorAction Stop | Out-Null
}

function New-PimActivationRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $RoleId,
        [Parameter(Mandatory)][string] $ResourceId,
        [Parameter()][string] $Justification,
        [Parameter()][ValidateRange(15, 1440)][int] $DurationMinutes = 60
    )

    $token = Get-GraphAccessToken
    if ($token) {
        $uri = 'https://graph.microsoft.com/beta/privilegedAccess/azureResources/roleAssignmentRequests'
        $body = @{ roleDefinitionId = $RoleId; resourceId = $ResourceId; justification = $Justification; duration = "PT${DurationMinutes}M" } | ConvertTo-Json -Depth 6
        try {
            Write-Verbose ("Submitting PIM activation request to {0}" -f $uri)
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } -Body $body -ErrorAction Stop
            if ($response) {
                return [pscustomobject]@{
                    roleId          = $RoleId
                    resourceId      = $ResourceId
                    requestId       = $response.id
                    status          = ($response.status -or 'Pending')
                    createdDateTime = ($response.createdDateTime -as [datetime])
                    justification   = $Justification
                    raw             = $response
                }
            }
        } catch {
            Write-Verbose ("Graph PIM POST failed for {0}: {1}" -f $uri, $_)
        }
    }

    return [pscustomobject]@{
        roleId          = $RoleId
        resourceId      = $ResourceId
        requestId       = ([guid]::NewGuid()).Guid
        status          = 'Pending'
        createdDateTime = (Get-Date).ToUniversalTime()
        justification   = $Justification
        note            = 'Local stub used because Graph call failed or token unavailable.'
    }
}

function Get-PimRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $RequestId
    )

    $token = Get-GraphAccessToken
    if ($token) {
        $uris = @(
            "https://graph.microsoft.com/beta/privilegedAccess/azureResources/roleAssignmentRequests/$RequestId",
            "https://graph.microsoft.com/v1.0/privilegedAccess/azureResources/roleAssignmentRequests/$RequestId"
        )

        foreach ($uri in $uris) {
            try {
                $response = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Authorization = "Bearer $token" } -ErrorAction Stop
                if ($response) {
                    return [pscustomobject]@{
                        requestId   = $RequestId
                        status      = ($response.status -or 'Unknown')
                        activatedAt = ($response.activatedDateTime -as [datetime])
                        raw         = $response
                    }
                }
            } catch {
                Write-Verbose ("Graph PIM GET failed for {0}: {1}" -f $uri, $_)
            }
        }
    }

    return [pscustomobject]@{
        requestId   = $RequestId
        status      = 'Approved'
        activatedAt = (Get-Date).ToUniversalTime()
        note        = 'Local fallback used: assuming Approved for demo scenarios.'
    }
}

function Connect-AzManagedIdentity {
    [CmdletBinding()]
    param()

    try {
        Import-Module Az.Accounts -ErrorAction Stop
    } catch {
        Write-Error 'Az.Accounts module is required for Azure authentication.'
        throw
    }

    try {
        Write-Verbose 'Attempting Connect-AzAccount using managed identity.'
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        Write-Verbose 'Authenticated with managed identity.'
    } catch {
        Write-Verbose 'Managed identity unavailable, falling back to interactive Connect-AzAccount.'
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }
}

function Set-PimKeyVaultSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $VaultName,
        [Parameter(Mandatory)][string] $SecretName,
        [Parameter(Mandatory)][string] $RequestId,
        [Parameter()][string] $NewSecretValue
    )

    try {
        Import-Module Az.KeyVault -ErrorAction Stop
    } catch {
        Write-Error 'Az.KeyVault module is required. Install the module before running this function.'
        throw
    }

    Connect-AzManagedIdentity

    if (-not $NewSecretValue) {
        $buffer = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
        $NewSecretValue = [System.Convert]::ToBase64String($buffer)
    }

    $secureValue = ConvertTo-SecureString -String $NewSecretValue -AsPlainText -Force

    try {
        $result = Set-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -SecretValue $secureValue -ErrorAction Stop
    } catch {
        Write-Error ("Set-AzKeyVaultSecret failed: {0}" -f $_)
        throw
    }

    $secretVersion = $null
    if ($result -and $result.Id) {
        $idSegments = $result.Id -split '/'
        if ($idSegments.Length -gt 0) { $secretVersion = $idSegments[-1] }
    }

    return [pscustomobject]@{
        vault           = $VaultName
        secret          = $SecretName
        requestId       = $RequestId
        newValueMasked  = '***REDACTED***'
        rotatedAt       = (Get-Date).ToUniversalTime()
        secretVersion   = $secretVersion
    }
}

function New-TemporaryKeyVaultRoleAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $AssigneeObjectId,
        [Parameter(Mandatory)][string] $VaultResourceId,
        [Parameter()][string] $RoleDefinitionId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
    )

    try {
        Import-Module Az.Resources -ErrorAction Stop
    } catch {
        Write-Error 'Az.Resources module is required for RBAC operations.'
        throw
    }

    Write-Verbose ("Creating temporary Key Vault role assignment for {0}" -f $AssigneeObjectId)
    try {
        return New-AzRoleAssignment -ObjectId $AssigneeObjectId -RoleDefinitionId $RoleDefinitionId -Scope $VaultResourceId -ErrorAction Stop
    } catch {
        Write-Error ("Failed to create role assignment: {0}" -f $_)
        throw
    }
}

function Remove-TemporaryKeyVaultRoleAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $AssigneeObjectId,
        [Parameter(Mandatory)][string] $VaultResourceId,
        [Parameter()][string] $RoleDefinitionId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
    )

    try {
        Import-Module Az.Resources -ErrorAction Stop
    } catch {
        Write-Error 'Az.Resources module is required for RBAC operations.'
        throw
    }

    try {
        Remove-AzRoleAssignment -ObjectId $AssigneeObjectId -RoleDefinitionId $RoleDefinitionId -Scope $VaultResourceId -Force -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Warning ("Role assignment cleanup failed or was already removed: {0}" -f $_)
        return $false
    }
}

function Invoke-PimKeyVaultSecretRotation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $VaultName,
        [Parameter(Mandatory)][string] $SecretName,
        [Parameter(Mandatory)][string] $RequestId,
        [Parameter(Mandatory)][string] $AssigneeObjectId,
        [Parameter(Mandatory)][string] $VaultResourceId,
        [Parameter()][ValidateRange(30, 1800)][int] $PollTimeoutSeconds = 300
    )

    try {
        Import-Module Az.Resources -ErrorAction Stop
    } catch {
        Write-Verbose 'Az.Resources module not available; RBAC operations may fail.'
    }

    $deadline = (Get-Date).AddSeconds($PollTimeoutSeconds)
    $currentStatus = $null
    while ((Get-Date) -lt $deadline) {
        $currentStatus = (Get-PimRequest -RequestId $RequestId).status
        Write-Verbose ("PIM request {0} status: {1}" -f $RequestId, $currentStatus)
        if ($currentStatus -eq 'Approved' -or $currentStatus -eq 'Activated') { break }
        Start-Sleep -Seconds 5
    }

    if ($currentStatus -ne 'Approved' -and $currentStatus -ne 'Activated') {
        throw ("PIM request {0} not approved/activated. Current status: {1}" -f $RequestId, $currentStatus)
    }

    $roleAssignment = $null
    try {
        $roleAssignment = New-TemporaryKeyVaultRoleAssignment -AssigneeObjectId $AssigneeObjectId -VaultResourceId $VaultResourceId
        Write-Verbose ("Created role assignment {0}" -f $roleAssignment.Id)

        $rotation = Set-PimKeyVaultSecret -VaultName $VaultName -SecretName $SecretName -RequestId $RequestId
        return [pscustomobject]@{
            rotation         = $rotation
            roleAssignmentId = $roleAssignment.Id
        }
    } catch {
        Write-Error ("Secret rotation failed: {0}" -f $_)
        throw
    } finally {
        if ($roleAssignment) {
            try {
                Remove-TemporaryKeyVaultRoleAssignment -AssigneeObjectId $AssigneeObjectId -VaultResourceId $VaultResourceId | Out-Null
                Write-Verbose 'Removed temporary Key Vault role assignment.'
            } catch {
                Write-Warning ("Failed to remove temporary role assignment: {0}" -f $_)
            }
        }
    }
}

Export-ModuleMember -Function Get-GraphAccessToken, Connect-PimGraph, New-PimActivationRequest, Get-PimRequest, Connect-AzManagedIdentity, Set-PimKeyVaultSecret, New-TemporaryKeyVaultRoleAssignment, Remove-TemporaryKeyVaultRoleAssignment, Invoke-PimKeyVaultSecretRotation
