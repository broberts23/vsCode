#Requires -Version 7.0
<#
.SYNOPSIS
  Applies Conditional Access Policy A from a UTCM baseline, then registers a UTCM monitor for drift.

.DESCRIPTION
  Unified Tenant Configuration Management (UTCM) stores desired state as a configuration baseline
  and monitors the tenant for drift. This script:
    1. Materializes infra/utcm/baselines/ca-app-proxy-mfa.baseline.json (token substitution)
    2. Creates or updates the Conditional Access policy via Microsoft Graph to match Assert=Present
    3. Asserts the UTCM service principal can read Conditional Access
    4. Creates (or refreshes) a UTCM configurationMonitor from the baseline

  UTCM itself detects drift; remediation of Create/Update for CA is applied here via Graph so the
  baseline becomes real desired state before monitoring starts.

.NOTES
  Uses Microsoft Graph PowerShell auth (Connect-MgGraph), not Azure CLI.
  Azure CLI cannot request UTCM scopes (AADSTS65002 first-party preauthorization).

.EXAMPLE
  Connect-MgGraph -Scopes @(
    'ConfigurationMonitoring.ReadWrite.All',
    'Policy.ReadWrite.ConditionalAccess',
    'Policy.Read.All',
    'Application.ReadWrite.All'
  )
  .\Deploy-UtcmCaAppProxyMfa.ps1

.EXAMPLE
  .\Deploy-UtcmCaAppProxyMfa.ps1 -PilotUserId '<oid>' -BreakGlassUserId '<oid>' -Enforce
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$AppProxyApplicationId = '8f99f135-63dd-4679-88b7-32ad6ebf4219',

    [Parameter()]
    [string]$PilotUserId = '',

    [Parameter()]
    [string]$BreakGlassUserId = '',

    [Parameter()]
    [string]$PolicyDisplayName = 'CA-Lab-AppProxy-RequireMFA',

    [Parameter()]
    [string]$MonitorDisplayName = 'UTCM Lab AppProxy RequireMFA',

    [Parameter()]
    [switch]$Enforce,

    [Parameter()]
    [string]$BaselinePath = (Join-Path $PSScriptRoot 'baselines\ca-app-proxy-mfa.baseline.json')
)

$ErrorActionPreference = 'Stop'
$UtcmServicePrincipalAppId = '03b07b79-c5bc-4b5e-9bfa-13acf4a99998'
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$RequiredGraphScopes = @(
    'ConfigurationMonitoring.ReadWrite.All',
    'Policy.ReadWrite.ConditionalAccess',
    'Policy.Read.All',
    'Application.ReadWrite.All'
)

function Assert-MgGraphAuth {
    if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
        throw "Microsoft.Graph.Authentication is required. Install-Module Microsoft.Graph.Authentication, then Connect-MgGraph."
    }
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Invoke-MgGraphRequest not found. Install/update Microsoft.Graph.Authentication.'
    }

    $ctx = Get-MgContext
    if (-not $ctx) {
        throw @"
No Graph PowerShell session. Run:

  Connect-MgGraph -Scopes @('$($RequiredGraphScopes -join "','")')

Then re-run this script in the same PowerShell session.
"@
    }

    $have = @($ctx.Scopes)
    $missing = @($RequiredGraphScopes | Where-Object { $_ -notin $have })
    if ($missing.Count -gt 0) {
        throw @"
Connected to Graph but missing scopes: $($missing -join ', ')

Reconnect with:

  Connect-MgGraph -Scopes @('$($RequiredGraphScopes -join "','")')
"@
    }

    Write-Host "Using Microsoft Graph PowerShell as $($ctx.Account) (tenant $($ctx.TenantId))"
}

function Invoke-GraphJson {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PATCH', 'DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body = $null
    )

    # Relative Graph paths work with Invoke-MgGraphRequest; strip absolute graph host if present.
    $relativeUri = $Uri
    if ($relativeUri -match '^https://graph\.microsoft\.com/(v1\.0|beta)(/.*)?$') {
        $relativeUri = '/' + $Matches[1] + $(if ($Matches[2]) { $Matches[2] } else { '' })
    }

    $jsonSent = $null
    try {
        # PATCH/DELETE often return 204 No Content; PSObject parsing can fail on empty bodies.
        $outputType = if ($Method -in @('PATCH', 'DELETE')) { 'HttpResponseMessage' } else { 'PSObject' }
        $params = @{
            Method      = $Method
            Uri         = $relativeUri
            OutputType  = $outputType
            ErrorAction = 'Stop'
        }
        if ($null -ne $Body) {
            # Never pass a JSON string: Invoke-MgGraphRequest may serialize it again
            # (body becomes a quoted string → Graph BadRequest). Pass Dictionary/List
            # so arrays stay arrays and String is not treated as char IEnumerable.
            $netBody = if ($Body -is [string]) {
                ConvertTo-NetObject ($Body | ConvertFrom-Json -AsHashtable -Depth 20)
            }
            else {
                ConvertTo-NetObject $Body
            }
            $jsonSent = ConvertTo-StableJson -InputObject $netBody
            $params.Body = $netBody
        }

        $response = Invoke-MgGraphRequest @params
        if ($outputType -eq 'HttpResponseMessage') {
            return $null
        }
        return $response
    }
    catch {
        $graphDetail = Get-GraphErrorDetail -ErrorRecord $_
        $suffix = if ($jsonSent) { "`nRequest body: $jsonSent" } else { '' }
        throw "Graph $Method $relativeUri failed: $graphDetail$suffix"
    }
}

function Get-GraphErrorDetail {
    param([Parameter(Mandatory)]$ErrorRecord)
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return [string]$ErrorRecord.ErrorDetails.Message
    }
    $ex = $ErrorRecord.Exception
    while ($ex) {
        foreach ($propName in @('ResponseContent', 'Message', 'ResponseBody', 'Content')) {
            $prop = $ex.PSObject.Properties[$propName]
            if ($prop -and $prop.Value -and [string]$prop.Value -ne $ex.Message) {
                $text = [string]$prop.Value
                if ($text.Length -gt 0 -and $text -match '\{|"error"|innerError|BadRequest') {
                    return $text
                }
            }
        }
        if ($ex.Response -and $ex.Response.Content) {
            try {
                return $ex.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            }
            catch {
                # continue walking
            }
        }
        $ex = $ex.InnerException
    }
    return [string]$ErrorRecord.Exception.Message
}

function ConvertTo-StableJson {
    param([Parameter(Mandatory)]$InputObject)
    $settings = [Newtonsoft.Json.JsonSerializerSettings]::new()
    $settings.NullValueHandling = [Newtonsoft.Json.NullValueHandling]::Ignore
    return [Newtonsoft.Json.JsonConvert]::SerializeObject(
        (ConvertTo-NetObject $InputObject),
        $settings
    )
}

function ConvertTo-NetObject {
    param($Value)
    # IMPORTANT: always `return , $collection` — PowerShell enumerates IEnumerable
    # returns, so a one-item list becomes a scalar ("all" instead of ["all"]).
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $dict = [System.Collections.Generic.Dictionary[string, object]]::new()
        foreach ($key in $Value.Keys) {
            $converted = ConvertTo-NetObject $Value[$key]
            if ($null -ne $converted) {
                $dict[[string]$key] = $converted
            }
        }
        return , $dict
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $list.Add((ConvertTo-NetObject $item))
        }
        return , $list
    }
    if ($Value -is [psobject]) {
        $dict = [System.Collections.Generic.Dictionary[string, object]]::new()
        foreach ($prop in $Value.PSObject.Properties) {
            if ($prop.Name -in @('PropertyCount', 'Length', 'Chars', 'SyncRoot', 'IsReadOnly', 'IsFixedSize', 'IsSynchronized', 'Count')) {
                continue
            }
            $converted = ConvertTo-NetObject $prop.Value
            if ($null -ne $converted) {
                $dict[$prop.Name] = $converted
            }
        }
        return , $dict
    }
    return $Value
}

function Get-OrCreateUtcmServicePrincipal {
    $existing = Invoke-GraphJson -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$UtcmServicePrincipalAppId'"
    if ($existing.value -and $existing.value.Count -gt 0) {
        return $existing.value[0]
    }
    Write-Host "Creating UTCM service principal ($UtcmServicePrincipalAppId)"
    return Invoke-GraphJson -Method POST `
        -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' `
        -Body @{ appId = $UtcmServicePrincipalAppId }
}

function Assert-UtcmGraphAppRole {
    param(
        [Parameter(Mandatory)][string]$UtcmSpId,
        [Parameter(Mandatory)][string]$PermissionValue
    )

    $graphSp = Invoke-GraphJson -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$GraphAppId'"
    $graph = $graphSp.value[0]
    $role = $graph.appRoles | Where-Object { $_.value -eq $PermissionValue -and $_.isEnabled }
    if (-not $role) {
        throw "Graph app role '$PermissionValue' not found."
    }

    $assignments = Invoke-GraphJson -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$UtcmSpId/appRoleAssignments"
    $already = @($assignments.value) | Where-Object {
        $_.resourceId -eq $graph.id -and $_.appRoleId -eq $role.id
    }
    if ($already) {
        Write-Host "UTCM SP already has $PermissionValue"
        return
    }

    Write-Host "Granting UTCM SP application permission: $PermissionValue"
    Invoke-GraphJson -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$UtcmSpId/appRoleAssignments" `
        -Body @{
        principalId = $UtcmSpId
        resourceId  = $graph.id
        appRoleId   = $role.id
    } | Out-Null
}

function Expand-BaselineTokens {
    param(
        [Parameter(Mandatory)][string]$JsonText,
        [Parameter(Mandatory)][hashtable]$Tokens
    )

    $result = $JsonText
    foreach ($key in $Tokens.Keys) {
        $result = $result.Replace("{{$key}}", [string]$Tokens[$key])
    }
    # Drop empty placeholders (break-glass / optional pilot). Default IncludeUsers to All.
    $obj = $result | ConvertFrom-Json
    foreach ($resource in @($obj.resources)) {
        $exclude = @($resource.properties.ExcludeUsers) | Where-Object { $_ -and $_ -notmatch '^\s*$' -and $_ -notmatch '\{\{' }
        $resource.properties.ExcludeUsers = @($exclude)
        $include = @($resource.properties.IncludeUsers) | Where-Object { $_ -and $_ -notmatch '^\s*$' -and $_ -notmatch '\{\{' }
        if ($include.Count -lt 1) {
            $include = @('All')
        }
        $resource.properties.IncludeUsers = @($include)
    }
    return $obj
}

function ConvertTo-StringList {
    param($Value)
    $items = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Value) {
        return , $items
    }
    # Wrap scalar strings so foreach does not iterate characters.
    $enumerable = if ($Value -is [string]) { @($Value) } else { @($Value) }
    foreach ($item in $enumerable) {
        if ($null -eq $item) { continue }
        # Nested string[] from prior wrapping — flatten one level.
        if ($item -is [System.Collections.IEnumerable] -and -not ($item -is [string])) {
            foreach ($nested in $item) {
                if ($null -eq $nested) { continue }
                $nestedText = [string]$nested
                if ($nestedText.Length -gt 0) {
                    $items.Add($nestedText)
                }
            }
            continue
        }
        $text = [string]$item
        if ($text.Length -gt 0) {
            $items.Add($text)
        }
    }
    return , $items
}

function ConvertTo-GraphCaPolicyBody {
    param(
        [Parameter(Mandatory)]$UtcmProperties,
        [Parameter(Mandatory)][string]$DisplayName
    )

    $state = [string]$UtcmProperties.State
    if ($Enforce) {
        $state = 'enabled'
    }

    $includeUsers = ConvertTo-StringList $UtcmProperties.IncludeUsers
    if ($includeUsers.Count -lt 1) {
        $includeUsers = ConvertTo-StringList @('All')
    }

    $users = [ordered]@{
        includeUsers = $includeUsers
    }
    $excludeUsers = ConvertTo-StringList $UtcmProperties.ExcludeUsers
    if ($excludeUsers.Count -gt 0) {
        $users['excludeUsers'] = $excludeUsers
    }

    $grantOperator = [string]$UtcmProperties.GrantControlOperator
    if (-not $grantOperator) {
        $grantOperator = 'OR'
    }

    $body = [ordered]@{
        displayName   = $DisplayName
        state         = $state
        conditions    = [ordered]@{
            clientAppTypes = (ConvertTo-StringList $UtcmProperties.ClientAppTypes)
            applications   = [ordered]@{
                includeApplications = (ConvertTo-StringList $UtcmProperties.IncludeApplications)
            }
            users          = $users
        }
        grantControls = [ordered]@{
            operator                    = $grantOperator
            builtInControls             = (ConvertTo-StringList $UtcmProperties.BuiltInControls)
            customAuthenticationFactors = [System.Collections.Generic.List[string]]::new()
            termsOfUse                  = [System.Collections.Generic.List[string]]::new()
        }
    }

    if ([bool]$UtcmProperties.SignInFrequencyIsEnabled) {
        $freqType = [string]$UtcmProperties.SignInFrequencyType
        if ($freqType) {
            $freqType = $freqType.ToLowerInvariant()
        }
        else {
            $freqType = 'hours'
        }
        $freqInterval = [string]$UtcmProperties.SignInFrequencyInterval
        if (-not $freqInterval) {
            $freqInterval = 'timeBased'
        }
        $body['sessionControls'] = [ordered]@{
            signInFrequency = [ordered]@{
                isEnabled         = $true
                type              = $freqType
                value             = [int]$UtcmProperties.SignInFrequencyValue
                frequencyInterval = $freqInterval
            }
        }
    }

    return , $body
}

function Set-ConditionalAccessPolicy {
    param(
        [Parameter(Mandatory)]$PolicyBody,
        [Parameter(Mandatory)][string]$DisplayName
    )

    $safeName = $DisplayName.Replace("'", "''")
    $existing = Invoke-GraphJson -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$filter=displayName eq '$safeName'"

    if ($existing.value -and $existing.value.Count -gt 0) {
        $id = $existing.value[0].id
        Write-Host "Updating Conditional Access policy $DisplayName ($id)"
        # OrderedDictionary/hashtable copy without displayName (immutable on some tenants).
        $patch = [ordered]@{}
        foreach ($key in $PolicyBody.Keys) {
            if ($key -ne 'displayName') {
                $patch[$key] = $PolicyBody[$key]
            }
        }
        Invoke-GraphJson -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$id" `
            -Body $patch | Out-Null
        return $id
    }

    Write-Host "Creating Conditional Access policy $DisplayName"
    $created = Invoke-GraphJson -Method POST `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' `
        -Body $PolicyBody
    return $created.id
}

function ConvertTo-UtcmDisplayName {
    param([Parameter(Mandatory)][string]$Name)
    # UTCM allows only letters, numbers, and spaces in monitor/baseline displayName.
    $cleaned = [regex]::Replace($Name, '[^A-Za-z0-9 ]+', ' ')
    $cleaned = [regex]::Replace($cleaned, '\s+', ' ').Trim()
    if (-not $cleaned) {
        throw "UTCM displayName '$Name' is empty after removing invalid characters."
    }
    return $cleaned
}

function Set-UtcmMonitor {
    param(
        [Parameter(Mandatory)]$Baseline,
        [Parameter(Mandatory)][string]$MonitorName
    )

    $monitorName = ConvertTo-UtcmDisplayName $MonitorName
    $baselineName = ConvertTo-UtcmDisplayName ([string]$Baseline.displayName)
    $safeName = $monitorName.Replace("'", "''")
    $existing = Invoke-GraphJson -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/admin/configurationManagement/configurationMonitors?`$filter=displayName eq '$safeName'"

    $monitorBody = @{
        displayName = $monitorName
        description = [string]$Baseline.description
        baseline    = @{
            displayName = $baselineName
            description = [string]$Baseline.description
            resources   = @(
                foreach ($r in @($Baseline.resources)) {
                    @{
                        # Resource labels may include hyphens (unlike monitor/baseline names).
                        displayName  = [string]$r.displayName
                        resourceType = [string]$r.resourceType
                        properties   = $r.properties
                    }
                }
            )
        }
    }

    if ($existing.value -and $existing.value.Count -gt 0) {
        $id = $existing.value[0].id
        Write-Host "Updating UTCM monitor $monitorName ($id)"
        Invoke-GraphJson -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/admin/configurationManagement/configurationMonitors/$id" `
            -Body $monitorBody | Out-Null
        return $id
    }

    Write-Host "Creating UTCM monitor $monitorName"
    $created = Invoke-GraphJson -Method POST `
        -Uri 'https://graph.microsoft.com/v1.0/admin/configurationManagement/configurationMonitors' `
        -Body $monitorBody
    return $created.id
}

Assert-MgGraphAuth

if (-not (Test-Path -LiteralPath $BaselinePath)) {
    throw "Baseline not found: $BaselinePath"
}

$tokens = @{
    AppProxyApplicationId = $AppProxyApplicationId
    PilotUserId           = $PilotUserId
    BreakGlassUserId      = $BreakGlassUserId
}

$rawBaseline = Get-Content -LiteralPath $BaselinePath -Raw
# Optional -PilotUserId overrides baseline IncludeUsers (default All).
if ($PilotUserId) {
    $rawBaseline = $rawBaseline -replace '"IncludeUsers"\s*:\s*\[[^\]]*\]', ("`"IncludeUsers`": [`n          `"$PilotUserId`"`n        ]")
}

$baseline = Expand-BaselineTokens -JsonText $rawBaseline -Tokens $tokens

# Keep policy display name consistent with resource key.
$resource = @($baseline.resources) | Where-Object { $_.properties.DisplayName -eq $PolicyDisplayName } | Select-Object -First 1
if (-not $resource) {
    $resource = @($baseline.resources)[0]
    $PolicyDisplayName = [string]$resource.properties.DisplayName
}

Write-Host '=== Assert UTCM service principal permissions ==='
$utcmSp = Get-OrCreateUtcmServicePrincipal
Assert-UtcmGraphAppRole -UtcmSpId $utcmSp.id -PermissionValue 'Policy.Read.All'
Assert-UtcmGraphAppRole -UtcmSpId $utcmSp.id -PermissionValue 'Policy.Read.ConditionalAccess'

Write-Host '=== Apply Conditional Access desired state (Graph) ==='
$policyBody = ConvertTo-GraphCaPolicyBody -UtcmProperties $resource.properties -DisplayName $PolicyDisplayName
$policyId = Set-ConditionalAccessPolicy -PolicyBody $policyBody -DisplayName $PolicyDisplayName

Write-Host '=== Register UTCM monitor from baseline ==='
$monitorId = Set-UtcmMonitor -Baseline $baseline -MonitorName $MonitorDisplayName

$materialized = Join-Path $PSScriptRoot ("baselines\ca-app-proxy-mfa.materialized.{0}.json" -f (Get-Date -Format 'yyyyMMddHHmmss'))
($baseline | ConvertTo-Json -Depth 20) | Set-Content -Path $materialized -Encoding utf8

Write-Host ''
Write-Host '=== Done ==='
Write-Host "CA policy id:     $policyId"
Write-Host "CA policy name:   $PolicyDisplayName"
Write-Host "CA state:         $(if ($Enforce) { 'enabled' } else { 'enabledForReportingButNotEnforced' })"
Write-Host "UTCM monitor id:  $monitorId"
Write-Host "Materialized:     $materialized"
Write-Host ''
Write-Host 'Verify:'
Write-Host '  1) Browser → App Proxy URL (report-only: check CA insights; -Enforce: expect MFA)'
Write-Host '  2) Easy Auth curl → Function /api/onprem-host still returns host JSON'
Write-Host '  3) Entra admin center → Tenant governance → Configuration management → Monitors'
