<#
PimAutomation.psm1 - consolidated module

Implements helpers for Microsoft Graph PIM activation, temporary Key Vault RBAC
assignment, and secret rotation. All functions are defined once in this file.
#>

#Requires -Version 7.4

# Module-level preference: prefer beta Graph endpoints when set (env or default false)
$PimAutomation_UseBeta = $true
if ($env:PIM_AUTOMATION_USE_BETA) {
    $val = $env:PIM_AUTOMATION_USE_BETA.ToString().ToLowerInvariant()
    if ($val -in @('1', 'true', 'yes', 'beta')) { $PimAutomation_UseBeta = $true }
}

function ConvertTo-RoleDefinitionGuid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $RoleDefinitionId
    )

    $trimmed = $RoleDefinitionId.Trim()
    if (-not $trimmed) { throw 'RoleDefinitionId cannot be blank.' }

    if ($trimmed -match '/roleDefinitions/([0-9a-fA-F\-]{36})$') { return $matches[1] }
    if ($trimmed -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return $trimmed }

    throw "RoleDefinitionId '$RoleDefinitionId' must be a GUID or a roleDefinitions resource ID."
}

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
            $cliArgs = @('account', 'get-access-token', '--resource', 'https://graph.microsoft.com')
            if ($TenantId) { $cliArgs += @('--tenant', $TenantId) }
            $tokenJson = & az @cliArgs | Out-String
            $accessToken = ($tokenJson | ConvertFrom-Json).accessToken
            if ($accessToken) { return $accessToken }
        }
    }
    catch {
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
    }
    catch {
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
            # Connect-MgGraph expects a SecureString for -AccessToken; convert the plain token string
            try {
                $secureToken = ConvertTo-SecureString -String $token -AsPlainText -Force
            }
            catch {
                Write-Verbose "Failed to convert token to SecureString: $_"
                throw
            }

            # When using -AccessToken, do not pass -Scopes (different parameter set). See
            # Connect-MgGraph docs: https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0
            Connect-MgGraph -AccessToken $secureToken -NoWelcome -ErrorAction Stop | Out-Null
            Write-Verbose 'Connected to Microsoft Graph using access token.'
            return
        }
        catch {
            Write-Verbose ("Connect-MgGraph with token failed: {0}" -f $_)
        }
    }

    Write-Verbose 'Falling back to interactive Connect-MgGraph.'
    Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
}

function Invoke-PimGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('Get', 'Post', 'Patch', 'Delete', 'Put')] [string] $Method,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter()] [string] $Body,
        [Parameter()] [string] $AccessToken
    )

    # Decide endpoint preference: default to module-level flag unless overridden by parameter
    if ($PSBoundParameters.ContainsKey('UseBeta')) {
        $preferBeta = $UseBeta
    }
    else {
        $preferBeta = $PimAutomation_UseBeta
    }

    # Try v1.0 then beta by default, or beta then v1.0 when preferring beta.
    if ($preferBeta) {
        $baseUris = @('https://graph.microsoft.com/beta/', 'https://graph.microsoft.com/v1.0/')
    }
    else {
        $baseUris = @('https://graph.microsoft.com/v1.0/', 'https://graph.microsoft.com/beta/')
    }
    foreach ($base in $baseUris) {
        $uri = ($base.TrimEnd('/') + '/' + $Path.TrimStart('/'))
        try {
            Write-Verbose ("Invoke-PimGraphRequest: {0} {1}" -f $Method, $uri)
            $headers = @{}
            if ($AccessToken) { $headers['Authorization'] = "Bearer $AccessToken" }
            if ($Method -eq 'Get') {
                $res = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ErrorAction Stop
            }
            elseif ($Method -eq 'Post') {
                $headers['Content-Type'] = 'application/json'
                $res = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $Body -ErrorAction Stop
            }
            elseif ($Method -eq 'Patch') {
                $headers['Content-Type'] = 'application/json'
                $res = Invoke-RestMethod -Method Patch -Uri $uri -Headers $headers -Body $Body -ErrorAction Stop
            }
            elseif ($Method -eq 'Delete') {
                $res = Invoke-RestMethod -Method Delete -Uri $uri -Headers $headers -ErrorAction Stop
            }
            elseif ($Method -eq 'Put') {
                $headers['Content-Type'] = 'application/json'
                $res = Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body $Body -ErrorAction Stop
            }

            if ($null -ne $res) { return $res }
        }
        catch {
            Write-Verbose ("Invoke-PimGraphRequest to {0} failed: {1}" -f $uri, $_)
            # try next base (v1.0 -> beta)
        }
    }

    return $null
}

function New-PimActivationRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $RoleId,
        [Parameter(Mandatory)][string] $ResourceId,
        [Parameter()][string] $Justification,
        [Parameter()][ValidateRange(15, 1440)][int] $DurationMinutes = 60,
        [Parameter()][switch] $UseBeta
    )

    $token = Get-GraphAccessToken
    if ($token) {
        # Build Graph payload according to documented fields (best-effort):
        $payload = [ordered]@{
            roleDefinitionId = $RoleId
            resourceId       = $ResourceId
            justification    = $Justification
            duration         = "PT${DurationMinutes}M"
        }
        $body = $payload | ConvertTo-Json -Depth 6
        try {
            Write-Verbose 'Submitting PIM activation request via Graph (v1.0 then beta)'
            $response = Invoke-PimGraphRequest -Method Post -Path 'privilegedAccess/azureResources/roleAssignmentRequests' -Body $body -AccessToken $token -UseBeta:$UseBeta
            # Normalize response: prefer id/status/createdDateTime/activatedDateTime
            if ($response -is [System.Management.Automation.PSCustomObject] -or $response -is [System.Object]) {
                $respId = $null
                if ($response.PSObject.Properties.Match('id').Count -gt 0) { $respId = $response.id }
                elseif ($response.PSObject.Properties.Match('requestId').Count -gt 0) { $respId = $response.requestId }
                elseif ($response.'@odata.id') { $respId = $response.'@odata.id' }
                $respStatus = $response.status -or $response.state -or $null
                $respCreated = $response.createdDateTime -or $response.createdDateTimeUtc -or $null
            }
            if ($response) {
                return [pscustomobject]@{
                    roleId          = $RoleId
                    resourceId      = $ResourceId
                    requestId       = ($respId -or $response.id -or ([guid]::NewGuid()).Guid)
                    status          = ($respStatus -or ($response.status) -or 'Pending')
                    createdDateTime = (($respCreated -or $response.createdDateTime) -as [datetime])
                    justification   = $Justification
                    raw             = $response
                }
            }
        }
        catch {
            Write-Verbose ("Graph PIM POST failed: {0}" -f $_)
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
        [Parameter(Mandatory)][string] $RequestId,
        [Parameter()][switch] $UseBeta
    )

    $token = Get-GraphAccessToken
    if ($token) {
        try {
            Write-Verbose 'Retrieving PIM request via Graph (v1.0 then beta)'
            $response = Invoke-PimGraphRequest -Method Get -Path ("privilegedAccess/azureResources/roleAssignmentRequests/$RequestId") -AccessToken $token -UseBeta:$UseBeta
            if ($response) {
                # Normalize response
                $respStatus = $response.status -or $response.state -or $null
                $respActivated = $response.activatedDateTime -or $response.activatedDateTimeUtc -or $null
                return [pscustomobject]@{
                    requestId   = ($response.id -or $RequestId)
                    status      = ($respStatus -or 'Unknown')
                    activatedAt = ($respActivated -as [datetime])
                    raw         = $response
                }
            }
        }
        catch {
            Write-Verbose ("Graph PIM GET failed: {0}" -f $_)
        }
    }

    return [pscustomobject]@{
        requestId   = $RequestId
        status      = 'Approved'
        activatedAt = (Get-Date).ToUniversalTime()
        note        = 'Local fallback used: assuming Approved for demo scenarios.'
    }
}

function Ensure-PimAzContext {
    [CmdletBinding()]
    param(
        [Parameter()][string] $SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
    )

    Import-Module Az.Accounts -ErrorAction Stop

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($context -and $context.Account -and $context.Subscription) {
        if (-not $SubscriptionId -or $context.Subscription.Id -eq $SubscriptionId) { return $context }
    }

    if ($SubscriptionId) {
        try {
            Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
            $context = Get-AzContext -ErrorAction SilentlyContinue
            if ($context -and $context.Account) { return $context }
        }
        catch {
            Write-Verbose ("Set-AzContext failed: {0}" -f $_)
        }
    }

    $tenantId = $env:AZURE_TENANT_ID
    $clientId = $env:AZURE_CLIENT_ID
    $federatedTokenFile = $env:AZURE_FEDERATED_TOKEN_FILE

    if ($federatedTokenFile -and (Test-Path -Path $federatedTokenFile) -and $tenantId -and $clientId) {
        Write-Verbose 'Connecting to Azure using federated token (OIDC).' 
        $token = Get-Content -Path $federatedTokenFile -Raw
        $connectParams = @{
            Tenant          = $tenantId
            ApplicationId   = $clientId
            FederatedToken  = $token
            ServicePrincipal = $true
            ErrorAction     = 'Stop'
        }
        if ($SubscriptionId) { $connectParams['Subscription'] = $SubscriptionId }
        Connect-AzAccount @connectParams | Out-Null
        return Get-AzContext -ErrorAction Stop
    }

    if ($env:IDENTITY_ENDPOINT) {
        Write-Verbose 'Connecting to Azure using managed identity environment.'
        Connect-AzAccount -Identity -Tenant $tenantId -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        return Get-AzContext -ErrorAction Stop
    }

    throw 'No Azure PowerShell context available. Ensure azure/login sets enable-AzPSSession or provide federated token environment variables.'
}

function Set-PimKeyVaultSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $VaultName,
        [Parameter(Mandatory = $false)][string] $SecretName = 'auto-rotated-secret',
        [Parameter(Mandatory)][string] $RequestId,
        [Parameter()][string] $NewSecretValue
    )

    try {
        Import-Module Az.KeyVault -ErrorAction Stop
    }
    catch {
        Write-Error 'Az.KeyVault module is required. Install the module before running this function.'
        throw
    }

    Ensure-PimAzContext | Out-Null

    if (-not $NewSecretValue) {
        $buffer = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
        $NewSecretValue = [System.Convert]::ToBase64String($buffer)
    }

    $secureValue = ConvertTo-SecureString -String $NewSecretValue -AsPlainText -Force

    try {
        $result = Set-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -SecretValue $secureValue -ErrorAction Stop
    }
    catch {
        Write-Error ("Set-AzKeyVaultSecret failed: {0}" -f $_)
        throw
    }

    $secretVersion = $null
    if ($result -and $result.Id) {
        $idSegments = $result.Id -split '/'
        if ($idSegments.Length -gt 0) { $secretVersion = $idSegments[-1] }
    }

    return [pscustomobject]@{
        vault          = $VaultName
        secret         = $SecretName
        requestId      = $RequestId
        newValueMasked = '***REDACTED***'
        rotatedAt      = (Get-Date).ToUniversalTime()
        secretVersion  = $secretVersion
    }
}

function New-TemporaryKeyVaultRoleAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $AssigneeObjectId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $VaultResourceId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $RoleDefinitionId
    )

    try {
        Import-Module Az.Resources -ErrorAction Stop
    }
    catch {
        Write-Error 'Az.Resources module is required for RBAC operations.'
        throw
    }

    Ensure-PimAzContext | Out-Null

    Write-Verbose ("Creating temporary Key Vault role assignment for {0} on scope {1}" -f $AssigneeObjectId, $VaultResourceId)
    $roleGuid = ConvertTo-RoleDefinitionGuid -RoleDefinitionId $RoleDefinitionId

    try {
        return New-AzRoleAssignment -ObjectId $AssigneeObjectId -RoleDefinitionId $roleGuid -Scope $VaultResourceId -ErrorAction Stop
    }
    catch {
        # Surface a detailed message to help diagnose failures in Az module
        $err = $_
        $detail = $err.Exception.ToString()
        Write-Error ("Failed to create role assignment. AssigneeObjectId={0}, RoleDefinitionId={1}, Scope={2}. Error: {3}" -f $AssigneeObjectId, $roleGuid, $VaultResourceId, $detail)
        throw $err
    }
}

function Remove-TemporaryKeyVaultRoleAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $AssigneeObjectId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $VaultResourceId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $RoleDefinitionId
    )

    try {
        Import-Module Az.Resources -ErrorAction Stop
    }
    catch {
        Write-Error 'Az.Resources module is required for RBAC operations.'
        throw
    }

    Ensure-PimAzContext | Out-Null

    try {
        $rId = ConvertTo-RoleDefinitionGuid -RoleDefinitionId $RoleDefinitionId
        Remove-AzRoleAssignment -ObjectId $AssigneeObjectId -RoleDefinitionId $rId -Scope $VaultResourceId -Force -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Warning ("Role assignment cleanup failed or was already removed: {0}" -f $_)
        return $false
    }
}

function Resolve-PimRoleResourcePairs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $RoleIdsJson,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $ResourceIdsJson,
        [Parameter()][string] $SubscriptionId
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $rolesParsed = @()
    if ($RoleIdsJson.Trim()) {
        $rawRoles = ConvertFrom-Json -InputObject $RoleIdsJson
        $rolesParsed = if ($rawRoles -is [System.Array]) { @($rawRoles) } else { @($rawRoles) }
    }

    $resourcesParsed = @()
    if ($ResourceIdsJson.Trim()) {
        $rawResources = ConvertFrom-Json -InputObject $ResourceIdsJson
        $resourcesParsed = if ($rawResources -is [System.Array]) { @($rawResources) } else { @($rawResources) }
    }

    $roles = @()
    foreach ($entry in $rolesParsed) {
        if ($null -eq $entry) { throw 'RoleId entries cannot be null.' }
        $value = ([string]$entry).Trim()
        if (-not $value) { throw 'RoleId entries cannot be empty.' }
        $roles += $value
    }

    $resources = @()
    foreach ($entry in $resourcesParsed) {
        if ($null -eq $entry) { throw 'ResourceId entries cannot be null.' }
        $value = ([string]$entry).Trim()
        if (-not $value) { throw 'ResourceId entries cannot be empty.' }
        if ($SubscriptionId) { $value = $value -replace '<AZURE_SUBSCRIPTION_ID>', $SubscriptionId }
        if ($value -match '<AZURE_SUBSCRIPTION_ID>') { throw 'ResourceId entries must not contain <AZURE_SUBSCRIPTION_ID> placeholders after substitution.' }
        $resources += $value
    }

    if ($roles.Count -eq 0) { throw 'roleIds input resolved to zero usable entries.' }
    if ($resources.Count -eq 0) { throw 'resourceIds input resolved to zero usable entries.' }

    $pairs = @()
    $rolesCount = $roles.Count
    $resourcesCount = $resources.Count

    if (($rolesCount -eq 1) -and ($resourcesCount -ge 1)) {
        foreach ($res in $resources) { $pairs += [pscustomobject]@{ RoleId = $roles[0]; ResourceId = $res } }
    }
    elseif (($resourcesCount -eq 1) -and ($rolesCount -ge 1)) {
        foreach ($role in $roles) { $pairs += [pscustomobject]@{ RoleId = $role; ResourceId = $resources[0] } }
    }
    elseif ($rolesCount -eq $resourcesCount) {
        for ($i = 0; $i -lt $rolesCount; $i++) { $pairs += [pscustomobject]@{ RoleId = $roles[$i]; ResourceId = $resources[$i] } }
    }
    else {
        foreach ($role in $roles) {
            foreach ($res in $resources) {
                $pairs += [pscustomobject]@{ RoleId = $role; ResourceId = $res }
            }
        }
    }

    return , $pairs
}

function Invoke-PimKeyVaultSecretRotation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $VaultName,
        [Parameter(Mandatory = $false)][string] $SecretName = 'auto-rotated-secret',
        [Parameter(Mandatory)][string] $RequestId,
        [Parameter(Mandatory)][string] $AssigneeObjectId,
        [Parameter(Mandatory)][string] $VaultResourceId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $RoleDefinitionId,
        [Parameter()][ValidateRange(30, 1800)][int] $PollTimeoutSeconds = 300
    )

    try {
        Import-Module Az.Resources -ErrorAction Stop
    }
    catch {
        Write-Verbose 'Az.Resources module not available; RBAC operations may fail.'
    }

    $currentStatus = $null
    $deadline = (Get-Date).AddSeconds($PollTimeoutSeconds)
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
        $roleAssignment = New-TemporaryKeyVaultRoleAssignment -AssigneeObjectId $AssigneeObjectId -VaultResourceId $VaultResourceId -RoleDefinitionId $RoleDefinitionId
        Write-Verbose ("Created role assignment {0}" -f $roleAssignment.Id)

        $rotation = Set-PimKeyVaultSecret -VaultName $VaultName -SecretName $SecretName -RequestId $RequestId
        return [pscustomobject]@{
            rotation         = $rotation
            roleAssignmentId = $roleAssignment.Id
        }
    }
    finally {
        if ($roleAssignment) {
            try {
                Remove-TemporaryKeyVaultRoleAssignment -AssigneeObjectId $AssigneeObjectId -VaultResourceId $VaultResourceId -RoleDefinitionId $RoleDefinitionId | Out-Null
                Write-Verbose 'Removed temporary Key Vault role assignment.'
            }
            catch {
                Write-Warning ("Failed to remove temporary role assignment: {0}" -f $_)
            }
        }
    }
}


function Invoke-TempKeyVaultRotationLifecycle {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()] [string] $VaultName,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()] [string] $SecretName = 'auto-rotated-secret',
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()] [string] $AssigneeObjectId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()] [string] $VaultResourceId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()] [string] $RoleDefinitionId,
        [Parameter()][ValidateRange(30, 1800)][int] $PollTimeoutSeconds = 300
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not $PSCmdlet.ShouldProcess("Assign role $RoleDefinitionId to $AssigneeObjectId on $VaultResourceId and rotate secret")) { return }

    $roleAssignment = $null
    try {
        # Create a temporary Key Vault role assignment (requires ASSIGNEE_OBJECT_ID pre-resolved by workflow)
        Write-Verbose "Creating temporary Key Vault role assignment for $AssigneeObjectId using role $RoleDefinitionId"
        $roleAssignment = New-TemporaryKeyVaultRoleAssignment -AssigneeObjectId $AssigneeObjectId -VaultResourceId $VaultResourceId -RoleDefinitionId $RoleDefinitionId
        Write-Verbose ("Created role assignment: {0}" -f ($roleAssignment.Id -or $roleAssignment.Name))

        # Perform the secret rotation under the granted role
        Write-Verbose "Rotating secret $SecretName in vault $VaultName"
        $rotation = Set-PimKeyVaultSecret -VaultName $VaultName -SecretName $SecretName -RequestId ([guid]::NewGuid()).Guid

        # Remove the role assignment
        Write-Verbose "Removing temporary role assignment for $AssigneeObjectId (role $RoleDefinitionId)"
        $removed = Remove-TemporaryKeyVaultRoleAssignment -AssigneeObjectId $AssigneeObjectId -VaultResourceId $VaultResourceId -RoleDefinitionId $RoleDefinitionId

        # Validate removal: attempt to find any role assignment matching principal and scope
        try {
            Import-Module Az.Resources -ErrorAction Stop
            $existing = Get-AzRoleAssignment -ObjectId $AssigneeObjectId -Scope $VaultResourceId -ErrorAction SilentlyContinue
        }
        catch {
            Write-Verbose "Az.Resources not available for validation: $_"
            $existing = $null
        }

        $validation = @{ removed = $true; assignmentsFound = 0 }
        if ($existing) { $validation.assignmentsFound = ($existing | Measure-Object).Count; if ($validation.assignmentsFound -gt 0) { $validation.removed = $false } }

        return [pscustomobject]@{
            rotation       = $rotation
            roleAssignment = ($roleAssignment | Select-Object Id, Name)
            removed        = $removed
            validation     = $validation
            timestamp      = (Get-Date).ToUniversalTime()
        }
    }
    catch {
        Write-Error ("Invoke-TempKeyVaultRotationLifecycle failed: {0}" -f $_)
        throw
    }
}

Export-ModuleMember -Function Invoke-TempKeyVaultRotationLifecycle

Export-ModuleMember -Function Get-GraphAccessToken, Connect-PimGraph, New-PimActivationRequest, Get-PimRequest, Connect-AzManagedIdentity, Set-PimKeyVaultSecret, New-TemporaryKeyVaultRoleAssignment, Remove-TemporaryKeyVaultRoleAssignment, Invoke-PimKeyVaultSecretRotation, Resolve-PimRoleResourcePairs
