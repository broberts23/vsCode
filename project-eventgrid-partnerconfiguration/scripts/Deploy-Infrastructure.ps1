#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Location = 'centralindia',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ParametersFile = (Join-Path -Path $PSScriptRoot -ChildPath '../infra/parameters.dev.bicepparam'),

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$BootstrapUserAssignedIdentityName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$PartnerTopicName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$PartnerTopicEventSubscriptionName = 'to-governance-function',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$FunctionResourceId,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraphBootstrap,

    [Parameter(Mandatory = $false)]
    [ValidateSet(
        'User.ReadWrite.All',
        'Directory.Read.All',
        'GroupMember.ReadWrite.All',
        'Group.ReadWrite.All'
    )]
    [string[]]$BootstrapGraphAppRoles = @('User.ReadWrite.All')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Information', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Information'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Information' { 'White' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
    }

    if ([string]::IsNullOrWhiteSpace($Message)) {
        $Message = '(no message)'
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Assert-AzCliPresent {
    [CmdletBinding()]
    param()

    $az = Get-Command -Name 'az' -ErrorAction SilentlyContinue
    if ($null -eq $az) {
        throw "Azure CLI ('az') not found. Install Azure CLI and run 'az login' first. See https://learn.microsoft.com/cli/azure/install-azure-cli"
    }
}

function Assert-AzLogin {
    [CmdletBinding()]
    param()

    $raw = & az account show --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Not logged into Azure CLI. Run 'az login' first. Details: $raw"
    }
}

function Get-NameFromResourceId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceId
    )

    $segments = $ResourceId.Trim('/') -split '/'
    if ($segments.Length -lt 1) {
        return $null
    }

    return $segments[-1]
}

function Get-SafeResourceName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Base,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Suffix
    )

    $name = ("$Base-$Suffix").ToLowerInvariant()
    $name = ($name -replace '[^a-z0-9-]', '-')
    $name = ($name -replace '-{2,}', '-')
    $name = $name.Trim('-')

    if ($name.Length -gt 128) {
        $name = $name.Substring(0, 128).Trim('-')
    }
    return $name
}

function Get-DeterministicShortHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [ValidateRange(4, 32)]
        [int]$Length = 12
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    $hex = [System.BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
    return $hex.Substring(0, $Length)
}

function Get-EffectivePartnerTopicName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$PartnerTopicName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupId
    )

    if (-not [string]::IsNullOrWhiteSpace($PartnerTopicName)) {
        return $PartnerTopicName
    }

    $suffix = Get-DeterministicShortHash -Value $ResourceGroupId -Length 14
    # Keep name simple and deterministic across redeploys.
    return "pt-graph-$suffix"
}

function Test-PartnerTopicExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PartnerTopicName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiVersion = '2025-02-15'
    )

    $url = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.EventGrid/partnerTopics/$PartnerTopicName`?api-version=$ApiVersion"
    $raw = & az rest --method GET --url $url --only-show-errors 2>&1
    if ($LASTEXITCODE -eq 0) {
        return $true
    }

    # If it's a 404 / NotFound, treat as non-existent; otherwise surface the error.
    $text = [string]$raw
    if ($text -match 'NotFound' -or $text -match '404') {
        return $false
    }

    throw "Failed checking partner topic existence for '$PartnerTopicName'. Details: $text"
}

function Get-AvailablePartnerTopicName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$PartnerTopicName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName
    )

    # If the caller explicitly provided a name, respect it.
    if (-not [string]::IsNullOrWhiteSpace($PartnerTopicName)) {
        return $PartnerTopicName
    }

    $baseName = Get-EffectivePartnerTopicName -PartnerTopicName $null -ResourceGroupId $ResourceGroupId

    # Microsoft Graph bootstrap can fail if a partner topic with the same name already exists.
    # In that case, pick a unique name (without deleting anything automatically).
    if (-not (Test-PartnerTopicExists -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -PartnerTopicName $baseName)) {
        return $baseName
    }

    for ($i = 1; $i -le 5; $i++) {
        $suffix = ([Guid]::NewGuid().ToString('N')).Substring(0, 8)
        $candidate = "$baseName-$suffix"
        if (-not (Test-PartnerTopicExists -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -PartnerTopicName $candidate)) {
            Write-Log -Level Warning -Message "Partner topic '$baseName' already exists; using '$candidate' for this run."
            return $candidate
        }
    }

    throw "Unable to find an available partner topic name based on '$baseName' after multiple attempts. Consider supplying -PartnerTopicName explicitly."
}

function Wait-PartnerTopic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PartnerTopicName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiVersion = '2025-02-15',

        [Parameter(Mandatory = $false)]
        [ValidateRange(10, 7200)]
        [int]$TimeoutSeconds = 300
    )

    $url = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.EventGrid/partnerTopics/$PartnerTopicName`?api-version=$ApiVersion"
    $deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)

    while ((Get-Date).ToUniversalTime() -lt $deadline) {
        try {
            Invoke-AzJson -AzParameters @('rest', '--method', 'GET', '--url', $url, '--only-show-errors') | Out-Null
            return
        }
        catch {
            Start-Sleep -Seconds 10
        }
    }

    throw "Partner topic did not become visible within ${TimeoutSeconds}s: $url"
}

function Get-PartnerTopicSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PartnerTopicName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiVersion = '2025-02-15'
    )

    $url = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.EventGrid/partnerTopics/$PartnerTopicName`?api-version=$ApiVersion"
    $pt = Invoke-AzJson -AzParameters @('rest', '--method', 'GET', '--url', $url, '--only-show-errors')

    $source = $null
    if ($null -ne $pt -and $null -ne $pt.properties) {
        $source = $pt.properties.source
    }

    if ([string]::IsNullOrWhiteSpace([string]$source)) {
        throw "Partner topic '$PartnerTopicName' has no properties.source; cannot safely update partner topic identity."
    }

    return [string]$source
}

function Wait-FunctionResource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FunctionResourceId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiVersion = '2025-03-01',

        [Parameter(Mandatory = $false)]
        [ValidateRange(10, 7200)]
        [int]$TimeoutSeconds = 900
    )

    $url = "https://management.azure.com$FunctionResourceId`?api-version=$ApiVersion"
    $deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)

    while ((Get-Date).ToUniversalTime() -lt $deadline) {
        try {
            Invoke-AzJson -AzParameters @('rest', '--method', 'GET', '--url', $url, '--only-show-errors') | Out-Null
            return
        }
        catch {
            Start-Sleep -Seconds 10
        }
    }

    throw "Function resource did not become visible within ${TimeoutSeconds}s: $url"
}

function Set-FunctionAppSetting {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FunctionAppName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )

    if (-not $PSCmdlet.ShouldProcess("$ResourceGroupName/$FunctionAppName", "Set Function App appSetting '$Name'")) {
        return
    }

    & az functionapp config appsettings set --resource-group $ResourceGroupName --name $FunctionAppName --settings "$Name=$Value" --only-show-errors | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set Function App setting '$Name' on '$FunctionAppName'."
    }
}

function Invoke-AzJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$AzParameters
    )

    $raw = & az $AzParameters 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "az command failed: az $($AzParameters -join ' ') :: $raw"
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }

    return ($raw | ConvertFrom-Json -Depth 64)
}

function Get-OrCreateUserAssignedManagedIdentity {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Location,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $existing = $null
    try {
        $existing = Invoke-AzJson -AzParameters @(
            'identity', 'show',
            '--resource-group', $ResourceGroupName,
            '--name', $Name,
            '--only-show-errors',
            '-o', 'json'
        )
    }
    catch {
        $existing = $null
    }

    if ($null -ne $existing -and -not [string]::IsNullOrWhiteSpace([string]$existing.id)) {
        return $existing
    }

    if (-not $PSCmdlet.ShouldProcess("$ResourceGroupName/$Name", "Create user-assigned managed identity")) {
        return $null
    }

    return (Invoke-AzJson -AzParameters @(
            'identity', 'create',
            '--resource-group', $ResourceGroupName,
            '--name', $Name,
            '--location', $Location,
            '--only-show-errors',
            '-o', 'json'
        ))
}

function Resolve-ServicePrincipalObjectIdByAppId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AppId,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 60)]
        [int]$MaxAttempts = 30,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 60)]
        [int]$SleepSeconds = 5
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $sp = Invoke-AzJson -AzParameters @(
                'rest',
                '--method', 'GET',
                '--url', "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId%20eq%20'$AppId'&`$select=id,appId,displayName",
                '--only-show-errors'
            )

            $id = if ($null -ne $sp.value -and @($sp.value).Count -gt 0) { $sp.value[0].id } else { $null }
            if (-not [string]::IsNullOrWhiteSpace([string]$id)) {
                return [string]$id
            }
        }
        catch {
            Write-Log -Level Warning -Message "Attempt $attempt of ${MaxAttempts} - service principal for appId '$AppId' not resolvable yet. $($_.Exception.Message)"
        }

        Start-Sleep -Seconds $SleepSeconds
    }

    throw "Unable to resolve service principal object id for appId '$AppId' after $MaxAttempts attempts."
}

function New-RoleAssignmentIfMissing {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AssigneeObjectId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Role,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Scope
    )

    $existing = & az role assignment list --assignee-object-id $AssigneeObjectId --role $Role --scope $Scope --query '[0].id' -o tsv --only-show-errors 2>&1
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$existing)) {
        return [pscustomobject]@{ role = $Role; scope = $Scope; status = 'AlreadyAssigned'; assignmentId = $existing }
    }

    if (-not $PSCmdlet.ShouldProcess($Scope, "Create role assignment '$Role' for objectId '$AssigneeObjectId'")) {
        return [pscustomobject]@{ role = $Role; scope = $Scope; status = 'Skipped'; assignmentId = $null }
    }

    $created = Invoke-AzJson -AzParameters @(
        'role', 'assignment', 'create',
        '--assignee-object-id', $AssigneeObjectId,
        '--assignee-principal-type', 'ServicePrincipal',
        '--role', $Role,
        '--scope', $Scope,
        '--only-show-errors',
        '-o', 'json'
    )

    return [pscustomobject]@{ role = $Role; scope = $Scope; status = 'Created'; assignmentId = $created.id }
}

function New-GraphAppRoleAssignmentsIfMissing {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServicePrincipalAppId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$AppRoles
    )

    $servicePrincipalObjectId = Resolve-ServicePrincipalObjectIdByAppId -AppId $ServicePrincipalAppId

    $graphAppId = '00000003-0000-0000-c000-000000000000'
    $graphSp = Invoke-AzJson -AzParameters @(
        'rest',
        '--method', 'GET',
        '--url', "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId%20eq%20'$graphAppId'&`$select=id,appId,displayName,appRoles",
        '--only-show-errors'
    )

    $graphSpId = $graphSp.value[0].id
    if ([string]::IsNullOrWhiteSpace($graphSpId)) {
        throw 'Unable to resolve Microsoft Graph service principal in this tenant.'
    }

    $graphAppRoles = @($graphSp.value[0].appRoles)
    $existingAssignments = Invoke-AzJson -AzParameters @(
        'rest',
        '--method', 'GET',
        '--url', "https://graph.microsoft.com/v1.0/servicePrincipals/$servicePrincipalObjectId/appRoleAssignments?`$select=id,resourceId,appRoleId",
        '--only-show-errors'
    )
    $existingForGraph = @($existingAssignments.value | Where-Object { $_.resourceId -eq $graphSpId })

    $results = @()
    foreach ($roleValue in $AppRoles) {
        $role = $graphAppRoles | Where-Object { $_.value -eq $roleValue -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
        if ($null -eq $role) {
            throw "App role '$roleValue' not found on Microsoft Graph service principal, or not an Application role."
        }

        $already = $existingForGraph | Where-Object { $_.appRoleId -eq $role.id } | Select-Object -First 1
        if ($null -ne $already) {
            $results += [pscustomobject]@{ role = $roleValue; appRoleId = $role.id; assignmentId = $already.id; status = 'AlreadyAssigned' }
            continue
        }

        $body = [ordered]@{
            principalId = $servicePrincipalObjectId
            resourceId  = $graphSpId
            appRoleId   = $role.id
        } | ConvertTo-Json -Depth 8

        if (-not $PSCmdlet.ShouldProcess($servicePrincipalObjectId, "Assign Microsoft Graph app role '$roleValue'")) {
            $results += [pscustomobject]@{ role = $roleValue; appRoleId = $role.id; assignmentId = $null; status = 'Skipped' }
            continue
        }

        $created = Invoke-AzJson -AzParameters @(
            'rest',
            '--method', 'POST',
            '--url', "https://graph.microsoft.com/v1.0/servicePrincipals/$servicePrincipalObjectId/appRoleAssignments",
            '--headers', 'Content-Type=application/json',
            '--body', $body,
            '--only-show-errors'
        )

        $results += [pscustomobject]@{ role = $roleValue; appRoleId = $role.id; assignmentId = $created.id; status = 'Created' }
    }

    return $results
}

# --- Main script logic ---

Assert-AzCliPresent
Assert-AzLogin

Write-Log -Level Information -Message "Deploying infra to RG '$ResourceGroupName' in subscription '$SubscriptionId'"
Write-Log -Level Information -Message "Parameters: $ParametersFile"

if (-not (Test-Path -Path $ParametersFile -PathType Leaf)) {
    throw "Parameters file not found: $ParametersFile"
}

& az account set --subscription $SubscriptionId --only-show-errors | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to set Azure subscription context to '$SubscriptionId'."
}

Write-Log -Level Information -Message "Ensuring resource group exists: $ResourceGroupName ($Location)"
& az group create --name $ResourceGroupName --location $Location --only-show-errors | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create/ensure resource group '$ResourceGroupName'."
}

$uamiName = $BootstrapUserAssignedIdentityName
if ([string]::IsNullOrWhiteSpace($uamiName)) {
    $suffix = ([Guid]::NewGuid().ToString('N')).Substring(0, 8)
    $uamiName = Get-SafeResourceName -Base 'uami-eg-governance' -Suffix "$ResourceGroupName-$suffix"
}

Write-Log -Level Information -Message "Ensuring user-assigned managed identity exists: $uamiName"
$uami = Get-OrCreateUserAssignedManagedIdentity -ResourceGroupName $ResourceGroupName -Location $Location -Name $uamiName -Confirm:$false

if ([string]::IsNullOrWhiteSpace([string]$uami.principalId) -or [string]::IsNullOrWhiteSpace([string]$uami.clientId)) {
    throw 'Managed identity missing principalId/clientId.'
}

$rgScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
Write-Log -Level Information -Message "Ensuring Azure RBAC role assignments on scope: $rgScope"
$rbac = @(
    New-RoleAssignmentIfMissing -AssigneeObjectId $uami.principalId -Role 'Contributor' -Scope $rgScope -Confirm:$false
)

Write-Log -Level Information -Message "Ensuring Microsoft Graph app role assignments: $($BootstrapGraphAppRoles -join ',')"
$graphRoleAssignments = New-GraphAppRoleAssignmentsIfMissing -ServicePrincipalAppId $uami.clientId -AppRoles $BootstrapGraphAppRoles -Confirm:$false

$templateFile = (Join-Path -Path $PSScriptRoot -ChildPath '../infra/main.bicep')
if (-not (Test-Path -Path $templateFile -PathType Leaf)) {
    throw "Bicep template not found: $templateFile"
}

$deploymentName = "eg-partnercfg-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Write-Log -Level Information -Message "Starting deployment: $deploymentName"

$deploymentAzParameters = @(
    'deployment', 'group', 'create',
    '--name', $deploymentName,
    '--resource-group', $ResourceGroupName,
    '--template-file', $templateFile,
    '--parameters', $ParametersFile,
    '--parameters', "bootstrapUserAssignedIdentityName=$uamiName",
    '--only-show-errors',
    '--query', 'properties.outputs',
    '-o', 'json'
)

if (-not [string]::IsNullOrWhiteSpace($FunctionResourceId)) {
    $deploymentAzParameters += @('--parameters', "functionResourceId=$FunctionResourceId")
}

$stderrFile = New-TemporaryFile
try {
    Write-Log -Level Information -Message "Starting az deployment..."
    $raw = & az $deploymentAzParameters 2> $stderrFile
    $stderr = Get-Content -Path $stderrFile -Raw
}
finally {
    Remove-Item -Path $stderrFile -Force -ErrorAction SilentlyContinue
}

if ($LASTEXITCODE -ne 0) {
    $details = if (-not [string]::IsNullOrWhiteSpace($stderr)) { $stderr } else { ($raw -join "`n") }
    throw "Deployment failed: $details"
}

$rawText = if ($raw -is [System.Array]) { ($raw -join "`n") } else { [string]$raw }
$rawText = $rawText.Trim()
if ([string]::IsNullOrWhiteSpace($rawText)) {
    throw "Deployment succeeded but produced no JSON outputs. stderr: $stderr"
}

try {
    $outputs = $rawText | ConvertFrom-Json -Depth 64
}
catch {
    # Fallback: attempt to extract the JSON object if extra text leaked into stdout.
    $start = $rawText.IndexOf('{')
    $end = $rawText.LastIndexOf('}')
    if ($start -ge 0 -and $end -gt $start) {
        $jsonOnly = $rawText.Substring($start, $end - $start + 1)
        $outputs = $jsonOnly | ConvertFrom-Json -Depth 64
    }
    else {
        throw
    }
}

Write-Log -Level Success -Message "Deployment succeeded: $deploymentName"

$functionAppId = $outputs.functionAppId.value
$functionResourceId = $outputs.functionResourceIdOut.value
$partnerConfigurationId = $outputs.partnerConfigurationId.value

$bootstrapIdentityName = $null
$bootstrapIdentityClientId = $null
$bootstrapIdentityPrincipalId = $null
$bootstrapGraphRoleAssignments = $null
$graphSubscription = $null
$partnerTopicActivation = $null

$partnerTopicNameOut = $null
$partnerTopicEventSubscriptionId = $null

if ($outputs.PSObject.Properties.Name -contains 'bootstrapIdentityName') {
    $bootstrapIdentityName = $outputs.bootstrapIdentityName.value
}
if ($outputs.PSObject.Properties.Name -contains 'bootstrapIdentityClientId') {
    $bootstrapIdentityClientId = $outputs.bootstrapIdentityClientId.value
}
if ($outputs.PSObject.Properties.Name -contains 'bootstrapIdentityPrincipalId') {
    $bootstrapIdentityPrincipalId = $outputs.bootstrapIdentityPrincipalId.value
}
if ($outputs.PSObject.Properties.Name -contains 'bootstrapGraphRoleAssignments') {
    $bootstrapGraphRoleAssignments = $outputs.bootstrapGraphRoleAssignments.value
}
if ($outputs.PSObject.Properties.Name -contains 'graphSubscription') {
    $graphSubscription = $outputs.graphSubscription.value
}
if ($outputs.PSObject.Properties.Name -contains 'partnerTopicActivation') {
    $partnerTopicActivation = $outputs.partnerTopicActivation.value
}

$functionAppName = (Get-NameFromResourceId -ResourceId $functionAppId)

if (-not $SkipGraphBootstrap.IsPresent) {
    $deployFunctionCodeScript = (Join-Path -Path $PSScriptRoot -ChildPath './Deploy-FunctionCode.ps1')
    if (-not (Test-Path -Path $deployFunctionCodeScript -PathType Leaf)) {
        throw "Deploy script not found: $deployFunctionCodeScript"
    }

    Write-Log -Level Information -Message "Deploying Function code (zip deploy) to '$functionAppName'"

    # IMPORTANT: Call the script in-process so you receive a real object back.
    # If we spawn a new `pwsh` process, PowerShell formats the object to text and properties like
    # `.deploymentStatus` no longer exist.
    $DeployCode = & $deployFunctionCodeScript `
        -SubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -FunctionAppName $functionAppName

    # Some scripts can emit multiple pipeline objects; prefer the last PSCustomObject if so.
    if ($DeployCode -is [System.Array]) {
        $DeployCode = @($DeployCode | Where-Object { $_ -is [psobject] } | Select-Object -Last 1)
        if ($DeployCode -is [System.Array] -and $DeployCode.Count -gt 0) {
            $DeployCode = $DeployCode[0]
        }
    }

    if ($null -eq $DeployCode) {
        Write-Log -Level Error -Message 'Function code deployment returned no result.'
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$DeployCode.deploymentStatus)) {
        $detailsParts = @(
            "status=$($DeployCode.deploymentStatus)"
            $(if (-not [string]::IsNullOrWhiteSpace([string]$DeployCode.deploymentId)) { "id=$($DeployCode.deploymentId)" })
            $(if ($null -ne $DeployCode.active) { "active=$($DeployCode.active)" })
        ) | Where-Object { $null -ne $_ }

        $details = $detailsParts -join ' '

        $msg = if (-not [string]::IsNullOrWhiteSpace([string]$DeployCode.message)) { $DeployCode.message } else { 'Function code deployed.' }
        Write-Log -Level Success -Message "$msg $details".Trim()
    }
    else {
        $msg = if (-not [string]::IsNullOrWhiteSpace([string]$DeployCode.message)) { $DeployCode.message } else { 'Function code deployed.' }
        Write-Log -Level Success -Message $msg
    }

    Write-Log -Level Information -Message "Waiting for Function resource to appear (required for Event Grid endpoint validation): $functionResourceId"
    Wait-FunctionResource -FunctionResourceId $functionResourceId

    $rg = Invoke-AzJson -AzParameters @('group', 'show', '--name', $ResourceGroupName, '--only-show-errors', '-o', 'json')
    $effectivePartnerTopicName = Get-AvailablePartnerTopicName -PartnerTopicName $PartnerTopicName -ResourceGroupId $rg.id -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName
    $partnerTopicNameOut = $effectivePartnerTopicName

    Write-Log -Level Information -Message "Bootstrapping Graph -> Event Grid using partner topic '$effectivePartnerTopicName'"

    $newSubscriptionScript = (Join-Path -Path $PSScriptRoot -ChildPath './New-GraphUsersSubscriptionToEventGrid.ps1')
    if (-not (Test-Path -Path $newSubscriptionScript -PathType Leaf)) {
        throw "Bootstrap script not found: $newSubscriptionScript"
    }

    $rawGraphSub = & pwsh -NoProfile -File $newSubscriptionScript `
        -AzureSubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -PartnerTopicName $effectivePartnerTopicName `
        -Location $Location `
        -UseAzCliGraphToken `
        -AsJson -InformationAction SilentlyContinue 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "New-GraphUsersSubscriptionToEventGrid.ps1 failed: $rawGraphSub"
    }

    $graphSubscription = ($rawGraphSub | ConvertFrom-Json -Depth 32)

    if ($null -ne $graphSubscription -and -not [string]::IsNullOrWhiteSpace([string]$graphSubscription.subscriptionId)) {
        Write-Log -Level Success -Message "Graph subscription created. subscriptionId=$($graphSubscription.subscriptionId) expires=$($graphSubscription.expirationDateTime)"
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$graphSubscription.clientState)) {
        Write-Log -Level Information -Message 'Updating Function App setting GRAPH_CLIENT_STATE'
        Set-FunctionAppSetting -ResourceGroupName $ResourceGroupName -FunctionAppName $functionAppName -Name 'GRAPH_CLIENT_STATE' -Value $graphSubscription.clientState -Confirm:$false
    }

    Write-Log -Level Information -Message "Waiting for partner topic resource to appear: $effectivePartnerTopicName"
    Wait-PartnerTopic -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -PartnerTopicName $effectivePartnerTopicName

    Write-Log -Level Information -Message "Reading partner topic source (required for safe update): $effectivePartnerTopicName"
    $partnerTopicSource = Get-PartnerTopicSource -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -PartnerTopicName $effectivePartnerTopicName

    $activateScript = (Join-Path -Path $PSScriptRoot -ChildPath './Activate-EventGridPartnerTopic.ps1')
    if (-not (Test-Path -Path $activateScript -PathType Leaf)) {
        throw "Bootstrap script not found: $activateScript"
    }

    $rawActivation = & pwsh -NoProfile -File $activateScript `
        -AzureSubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -PartnerTopicName $effectivePartnerTopicName `
        -AsJson -InformationAction SilentlyContinue 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Activate-EventGridPartnerTopic.ps1 failed: $rawActivation"
    }

    $partnerTopicActivation = ($rawActivation | ConvertFrom-Json -Depth 32)

    if ($null -ne $partnerTopicActivation -and -not [string]::IsNullOrWhiteSpace([string]$partnerTopicActivation.activationState)) {
        Write-Log -Level Success -Message "Partner topic activation state: $($partnerTopicActivation.activationState)"
    }

    # Second deployment: now that the partner topic exists/activated, create the partner topic -> Function event subscription via Bicep.
    $deploymentNameLink = "${deploymentName}-link"
    Write-Log -Level Information -Message "Creating partner topic -> Function link via Bicep deployment: $deploymentNameLink"

    $linkTemplateFile = (Join-Path -Path $PSScriptRoot -ChildPath '../infra/link.bicep')
    if (-not (Test-Path -Path $linkTemplateFile -PathType Leaf)) {
        throw "Link Bicep template not found: $linkTemplateFile"
    }

    $deploymentAzParametersLink = @(
        'deployment', 'group', 'create',
        '--name', $deploymentNameLink,
        '--resource-group', $ResourceGroupName,
        '--template-file', $linkTemplateFile,
        '--parameters', "bootstrapUserAssignedIdentityName=$uamiName",
        '--parameters', "partnerTopicName=$effectivePartnerTopicName",
        '--parameters', "partnerTopicSource=$partnerTopicSource",
        '--parameters', "partnerTopicEventSubscriptionName=$PartnerTopicEventSubscriptionName",
        '--parameters', "functionResourceId=$functionResourceId",
        '--only-show-errors',
        '--query', 'properties.outputs',
        '-o', 'json'
    )

    $stderrFileLink = New-TemporaryFile
    try {
        $rawLink = & az $deploymentAzParametersLink 2> $stderrFileLink
        $stderrLink = Get-Content -Path $stderrFileLink -Raw
    }
    finally {
        Remove-Item -Path $stderrFileLink -Force -ErrorAction SilentlyContinue
    }

    if ($LASTEXITCODE -ne 0) {
        $detailsLink = if (-not [string]::IsNullOrWhiteSpace($stderrLink)) { $stderrLink } else { ($rawLink -join "`n") }
        throw "Link deployment failed: $detailsLink"
    }

    $rawLinkText = if ($rawLink -is [System.Array]) { ($rawLink -join "`n") } else { [string]$rawLink }
    $rawLinkText = $rawLinkText.Trim()
    if ([string]::IsNullOrWhiteSpace($rawLinkText)) {
        throw "Link deployment succeeded but produced no JSON outputs. stderr: $stderrLink"
    }

    $outputsLink = $null
    try {
        $outputsLink = $rawLinkText | ConvertFrom-Json -Depth 64
    }
    catch {
        $startLink = $rawLinkText.IndexOf('{')
        $endLink = $rawLinkText.LastIndexOf('}')
        if ($startLink -ge 0 -and $endLink -gt $startLink) {
            $jsonOnlyLink = $rawLinkText.Substring($startLink, $endLink - $startLink + 1)
            $outputsLink = $jsonOnlyLink | ConvertFrom-Json -Depth 64
        }
        else {
            throw
        }
    }

    if ($null -ne $outputsLink -and $outputsLink.PSObject.Properties.Name -contains 'partnerTopicEventSubscriptionId') {
        $partnerTopicEventSubscriptionId = $outputsLink.partnerTopicEventSubscriptionId.value
        if (-not [string]::IsNullOrWhiteSpace([string]$partnerTopicEventSubscriptionId)) {
            Write-Log -Level Success -Message "Partner topic event subscription created/updated. id=$partnerTopicEventSubscriptionId"
        }
    }
}

[pscustomobject]@{
    deploymentName                  = $deploymentName
    resourceGroupName               = $ResourceGroupName
    location                        = $Location
    partnerConfigurationId          = $partnerConfigurationId
    functionAppId                   = $functionAppId
    functionAppName                 = $functionAppName
    functionResourceId              = $functionResourceId
    functionName                    = (Get-NameFromResourceId -ResourceId $functionResourceId)

    bootstrapIdentityName           = $bootstrapIdentityName
    bootstrapIdentityClientId       = $bootstrapIdentityClientId
    bootstrapIdentityPrincipalId    = $bootstrapIdentityPrincipalId

    bootstrapGraphRoleAssignments   = if ($null -ne $bootstrapGraphRoleAssignments) { $bootstrapGraphRoleAssignments } else { $graphRoleAssignments }
    bootstrapAzureRbacAssignments   = $rbac
    partnerTopicName                = $partnerTopicNameOut
    partnerTopicEventSubscriptionId = $partnerTopicEventSubscriptionId
    graphSubscription               = $graphSubscription
    partnerTopicActivation          = $partnerTopicActivation
}
