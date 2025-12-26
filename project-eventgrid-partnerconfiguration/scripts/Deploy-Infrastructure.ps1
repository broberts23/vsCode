#!/usr/bin/env pwsh
#Requires -Version 7.4

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidAssignmentToAutomaticVariable',
    '',
    Justification = 'No assignment to $args exists in this script; suppress false-positive editor diagnostic.'
)]
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
    [ValidateSet('User.Read.All', 'Directory.Read.All')]
    [string[]]$BootstrapGraphAppRoles = @('User.Read.All')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseApprovedVerbs',
    '',
    Justification = 'Internal helper function.'
)]
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

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseApprovedVerbs',
    '',
    Justification = 'Internal helper function.'
)]
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

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseApprovedVerbs',
    '',
    Justification = 'Internal helper function.'
)]
function New-GraphAppRoleAssignmentsIfMissing {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServicePrincipalObjectId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$AppRoles
    )

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
        '--url', "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalObjectId/appRoleAssignments?`$select=id,resourceId,appRoleId",
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
            principalId = $ServicePrincipalObjectId
            resourceId  = $graphSpId
            appRoleId   = $role.id
        } | ConvertTo-Json -Depth 8

        if (-not $PSCmdlet.ShouldProcess($ServicePrincipalObjectId, "Assign Microsoft Graph app role '$roleValue'")) {
            $results += [pscustomobject]@{ role = $roleValue; appRoleId = $role.id; assignmentId = $null; status = 'Skipped' }
            continue
        }

        $created = Invoke-AzJson -AzParameters @(
            'rest',
            '--method', 'POST',
            '--url', "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalObjectId/appRoleAssignments",
            '--headers', 'Content-Type=application/json',
            '--body', $body,
            '--only-show-errors'
        )

        $results += [pscustomobject]@{ role = $roleValue; appRoleId = $role.id; assignmentId = $created.id; status = 'Created' }
    }

    return $results
}

Assert-AzCliPresent
Assert-AzLogin

Write-Verbose "Deploying infra to RG '$ResourceGroupName' in subscription '$SubscriptionId'"
Write-Verbose "Parameters: $ParametersFile"

if (-not (Test-Path -Path $ParametersFile -PathType Leaf)) {
    throw "Parameters file not found: $ParametersFile"
}

& az account set --subscription $SubscriptionId --only-show-errors | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to set Azure subscription context to '$SubscriptionId'."
}

Write-Verbose "Ensuring resource group exists: $ResourceGroupName ($Location)"
& az group create --name $ResourceGroupName --location $Location --only-show-errors | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create/ensure resource group '$ResourceGroupName'."
}

$uamiName = $BootstrapUserAssignedIdentityName
if ([string]::IsNullOrWhiteSpace($uamiName)) {
    $suffix = ([Guid]::NewGuid().ToString('N')).Substring(0, 8)
    $uamiName = Get-SafeResourceName -Base 'uami-eg-governance' -Suffix "$ResourceGroupName-$suffix"
}

Write-Verbose "Ensuring user-assigned managed identity exists: $uamiName"
$uami = Get-OrCreateUserAssignedManagedIdentity -ResourceGroupName $ResourceGroupName -Location $Location -Name $uamiName

if ([string]::IsNullOrWhiteSpace([string]$uami.principalId) -or [string]::IsNullOrWhiteSpace([string]$uami.clientId)) {
    throw 'Managed identity missing principalId/clientId.'
}

$rgScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
Write-Verbose "Ensuring Azure RBAC role assignments on scope: $rgScope"
$rbac = @(
    New-RoleAssignmentIfMissing -AssigneeObjectId $uami.principalId -Role 'Contributor' -Scope $rgScope
)

Write-Verbose "Ensuring Microsoft Graph app role assignments: $($BootstrapGraphAppRoles -join ',')"
$graphRoleAssignments = New-GraphAppRoleAssignmentsIfMissing -ServicePrincipalObjectId $uami.principalId -AppRoles $BootstrapGraphAppRoles

$templateFile = (Join-Path -Path $PSScriptRoot -ChildPath '../infra/main.bicep')
if (-not (Test-Path -Path $templateFile -PathType Leaf)) {
    throw "Bicep template not found: $templateFile"
}

$deploymentName = "eg-partnercfg-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Write-Verbose "Starting deployment: $deploymentName"

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

$stderrFile = New-TemporaryFile
try {
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

$functionAppId = $outputs.functionAppId.value
$functionResourceId = $outputs.functionResourceIdOut.value
$partnerConfigurationId = $outputs.partnerConfigurationId.value

$bootstrapIdentityName = $null
$bootstrapIdentityClientId = $null
$bootstrapIdentityPrincipalId = $null
$bootstrapGraphRoleAssignments = $null
$graphSubscription = $null
$partnerTopicActivation = $null

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

[pscustomobject]@{
    deploymentName                = $deploymentName
    resourceGroupName             = $ResourceGroupName
    location                      = $Location
    partnerConfigurationId        = $partnerConfigurationId
    functionAppId                 = $functionAppId
    functionAppName               = (Get-NameFromResourceId -ResourceId $functionAppId)
    functionResourceId            = $functionResourceId
    functionName                  = (Get-NameFromResourceId -ResourceId $functionResourceId)

    bootstrapIdentityName         = $bootstrapIdentityName
    bootstrapIdentityClientId     = $bootstrapIdentityClientId
    bootstrapIdentityPrincipalId  = $bootstrapIdentityPrincipalId

    bootstrapGraphRoleAssignments = if ($null -ne $bootstrapGraphRoleAssignments) { $bootstrapGraphRoleAssignments } else { $graphRoleAssignments }
    bootstrapAzureRbacAssignments = $rbac
    graphSubscription             = $graphSubscription
    partnerTopicActivation        = $partnerTopicActivation
}
