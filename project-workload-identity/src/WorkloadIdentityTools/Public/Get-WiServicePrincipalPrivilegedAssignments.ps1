#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Identify service principals assigned to privileged directory roles.

.DESCRIPTION
Enumerates privileged directory role assignments using Microsoft Graph beta RBAC cmdlets.
Primary data source: Get-MgBetaRoleManagementDirectoryRoleAssignment.
Docs: https://learn.microsoft.com/powershell/module/microsoft.graph.beta.identity.governance/get-mgbetarolemanagementdirectoryroleassignment?view=graph-powershell-beta

.OUTPUTS
PSCustomObject with RoleId, RoleDisplayName, ServicePrincipalId, AppId, DisplayName.
#>
Function Get-WiServicePrincipalPrivilegedAssignments {
    [CmdletBinding()] 
    [OutputType([psobject])]
    Param(
        [Parameter()][string[]]$PrivilegedRoleTemplateIds = @(
            '62e90394-69f5-4237-9190-012177145e10', # Global Administrator
            'e8611ab8-c189-46e8-94e1-60213ab1f814', # Privileged Role Administrator
            '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30', # Application Administrator
            '158c047a-c907-4556-b7ef-446551a6b5f7', # Cloud Application Administrator
            'f2ef992c-3afb-46b9-b7cf-a126ee74c451', # Global Reader
            '9360feb5-f418-4baa-8175-e2a00bac4301', # Directory Writers
            'fe930be7-5e62-47db-91af-98c3a49a38b1'  # User Administrator
        )
    )
    if (-not (Get-Command -Name Get-MgBetaRoleManagementDirectoryRoleAssignment -ErrorAction SilentlyContinue)) {
        Throw 'Get-MgBetaRoleManagementDirectoryRoleAssignment not available. Install Microsoft.Graph.Beta.Identity.Governance module.'
    }
    if (-not (Get-Command -Name Get-MgBetaRoleManagementDirectoryRoleDefinition -ErrorAction SilentlyContinue)) {
        Throw 'Get-MgBetaRoleManagementDirectoryRoleDefinition not available. Install Microsoft.Graph.Beta.Identity.Governance module.'
    }
    $normalizedTemplateIds = @()
    if ($PrivilegedRoleTemplateIds) {
        foreach ($tid in $PrivilegedRoleTemplateIds) {
            try {
                $normalizedTemplateIds += [Guid]$tid
            }
            catch {
                Write-Warning "Invalid role template id supplied: $tid"
            }
        }
    }
    Write-Verbose ("[PrivRole] Normalized role template ids: {0}" -f ($normalizedTemplateIds -join ', '))

    $spCache = [System.Collections.Generic.Dictionary[string, object]]::new()
    $results = New-Object System.Collections.Generic.List[object]
    $roleDefinitions = New-Object System.Collections.Generic.List[object]
    foreach ($templateGuid in $normalizedTemplateIds) {
        $templateFilter = $templateGuid.ToString()
        try {
            $defs = Get-MgBetaRoleManagementDirectoryRoleDefinition -Filter "templateId eq '$templateFilter'" -All -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to resolve role definition for template $templateFilter : $($_.Exception.Message)"
            continue
        }
        foreach ($def in @($defs)) {
            $roleDefinitions.Add($def)
        }
        if (-not $defs) {
            Write-Verbose "[PrivRole] No activated role definition found for template $templateFilter"
        }
    }
    Write-Verbose ("[PrivRole] Resolved {0} role definitions from templates" -f $roleDefinitions.Count)

    foreach ($roleDefinition in $roleDefinitions) {
        try {
            $assignments = Get-MgBetaRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($roleDefinition.Id)'" -All -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to get assignments for role $($roleDefinition.DisplayName): $($_.Exception.Message)"
            continue
        }
        $assignmentCount = @($assignments).Count
        Write-Verbose ("[PrivRole] Role definition {0} ({1}) has {2} assignments" -f $roleDefinition.DisplayName, $roleDefinition.TemplateId, $assignmentCount)
        foreach ($assignment in @($assignments)) {
            if (-not $assignment.PrincipalId) { continue }
            $spDetails = $null
            if ($spCache.ContainsKey($assignment.PrincipalId)) {
                $spDetails = $spCache[$assignment.PrincipalId]
            }
            else {
                try {
                    $spDetails = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId -ErrorAction Stop
                }
                catch {
                    $spDetails = $null
                }
                $spCache[$assignment.PrincipalId] = $spDetails
            }

            if (-not $spDetails) {
                Write-Verbose ("[PrivRole] Skipping principal {0} because Get-MgServicePrincipal failed or returned null" -f $assignment.PrincipalId)
                continue
            }

            Write-Verbose ("[PrivRole] Adding SP {0} ({1}) from beta assignment for role {2}" -f $spDetails.DisplayName, $spDetails.AppId, $roleDefinition.DisplayName)
            $results.Add([PSCustomObject]@{
                    RoleId             = $roleDefinition.Id
                    RoleDisplayName    = $roleDefinition.DisplayName
                    ServicePrincipalId = $assignment.PrincipalId
                    AppId              = $spDetails.AppId
                    DisplayName        = $spDetails.DisplayName
                })
        }
    }

    if (($results.Count -eq 0) -and (Get-Command -Name Get-MgDirectoryRole -ErrorAction SilentlyContinue)) {
        Write-Verbose '[PrivRole] Beta assignment enumeration yielded no matches; falling back to Get-MgDirectoryRole member listing.'
        try { $roles = Get-MgDirectoryRole -All } catch { $roles = @(); Write-Warning "Failed to get roles via Get-MgDirectoryRole fallback: $($_.Exception.Message)" }
        Write-Verbose ("[PrivRole] Fallback found {0} activated directory roles" -f (@($roles).Count))
        foreach ($role in $roles) {
            $roleTemplateGuid = $null
            if ($role.RoleTemplateId) {
                try { $roleTemplateGuid = [Guid]$role.RoleTemplateId } catch { $roleTemplateGuid = $null }
            }
            if ($normalizedTemplateIds -and ($roleTemplateGuid -notin $normalizedTemplateIds)) { continue }
            try { $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All } catch { Write-Warning "Failed members for role $($role.DisplayName): $($_.Exception.Message)"; continue }
            $memberCount = @($members).Count
            Write-Verbose ("[PrivRole] Role {0} ({1}) has {2} members (fallback)" -f $role.DisplayName, $role.RoleTemplateId, $memberCount)
            foreach ($m in $members) {
                $spDetails = $null
                if ($spCache.ContainsKey($m.Id)) {
                    $spDetails = $spCache[$m.Id]
                }
                else {
                    try {
                        $spDetails = Get-MgServicePrincipal -ServicePrincipalId $m.Id -ErrorAction Stop
                    }
                    catch {
                        $spDetails = $null
                    }
                    $spCache[$m.Id] = $spDetails
                }

                if (-not $spDetails) {
                    Write-Verbose ("[PrivRole] Skipping member {0} because Get-MgServicePrincipal failed or returned null (fallback)" -f $m.Id)
                    continue
                }

                Write-Verbose ("[PrivRole] Adding SP {0} ({1}) for role {2} (fallback)" -f $spDetails.DisplayName, $spDetails.AppId, $role.DisplayName)
                $results.Add([PSCustomObject]@{
                        RoleId             = $role.Id
                        RoleDisplayName    = $role.DisplayName
                        ServicePrincipalId = $m.Id
                        AppId              = $spDetails.AppId
                        DisplayName        = $spDetails.DisplayName
                    })
            }
        }
    }

    # Fallback: Some tenants or API versions may still not return memberships via either API path.
    # Scan service principals and inspect their `memberOf` relationships for directoryRole membership.
    if ($results.Count -eq 0) {
        Write-Verbose '[PrivRole] No results from role->members enumeration; falling back to scanning service principals memberOf.'
        try {
            $allSps = Get-MgServicePrincipal -All -Property 'Id,AppId,DisplayName'
        }
        catch {
            Write-Warning "Failed to enumerate service principals for fallback: $($_.Exception.Message)"
            return $results
        }

        foreach ($sp in $allSps) {
            try {
                $memberOf = Get-MgServicePrincipalMemberOf -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
            }
            catch {
                $memberOf = @()
            }
            foreach ($m in @($memberOf)) {
                # Attempt to treat $m as a directoryRole-like object (has RoleTemplateId)
                $mRoleTemplateId = $null
                $prop1 = $m.PSObject.Properties['roleTemplateId']
                $prop2 = $m.PSObject.Properties['RoleTemplateId']
                if ($prop1) { $mRoleTemplateId = [string]$prop1.Value }
                elseif ($prop2) { $mRoleTemplateId = [string]$prop2.Value }
                if (-not $mRoleTemplateId) { continue }
                try { $mGuid = [Guid]$mRoleTemplateId } catch { continue }
                if ($normalizedTemplateIds -and ($mGuid -in $normalizedTemplateIds)) {
                    # We have a privileged role membership for this SP
                    $results.Add([PSCustomObject]@{
                            RoleId             = ($m.Id -or $null)
                            RoleDisplayName    = ($m.DisplayName -or $m.Id)
                            ServicePrincipalId = $sp.Id
                            AppId              = $sp.AppId
                            DisplayName        = $sp.DisplayName
                        })
                    Write-Verbose ("[PrivRole] Fallback matched SP {0} ({1}) to role {2}" -f $sp.DisplayName, $sp.AppId, ($m.DisplayName -or $mRoleTemplateId))
                }
            }
        }
    }

    return $results
}
