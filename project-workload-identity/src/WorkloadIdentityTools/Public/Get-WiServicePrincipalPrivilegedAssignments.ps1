#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Identify service principals assigned to privileged directory roles.

.DESCRIPTION
Enumerates directory roles and their members, filtering for service principals.
Uses Get-MgDirectoryRole.* cmdlets.
Docs: Get-MgDirectoryRole — https://learn.microsoft.com/powershell/module/microsoft.graph.directoryroles/get-mgdirectoryrole?view=graph-powershell-1.0

.OUTPUTS
PSCustomObject with RoleId, RoleDisplayName, ServicePrincipalId, AppId, DisplayName.
#>
Function Get-WiServicePrincipalPrivilegedAssignments {
    [CmdletBinding()] 
    [OutputType([psobject])]
    Param(
        [Parameter()][string[]]$PrivilegedRoleNames = @('Global Administrator','Privileged Role Administrator','Application Administrator','Cloud Application Administrator','Directory Writers','User Administrator')
    )
    if (-not (Get-Command -Name Get-MgDirectoryRole -ErrorAction SilentlyContinue)) {
        Throw 'Get-MgDirectoryRole not available. Install Microsoft.Graph.DirectoryRoles module.'
    }
    try { $roles = Get-MgDirectoryRole -All } catch { Throw "Failed to get roles: $($_.Exception.Message)" }
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($role in $roles) {
        if ($PrivilegedRoleNames -and ($role.DisplayName -notin $PrivilegedRoleNames)) { continue }
        try { $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All } catch { Write-Warning "Failed members for role $($role.DisplayName): $($_.Exception.Message)"; continue }
        foreach ($m in $members) {
            if ($m.'@odata.type' -like '*servicePrincipal*') {
                $results.Add([PSCustomObject]@{
                    RoleId             = $role.Id
                    RoleDisplayName    = $role.DisplayName
                    ServicePrincipalId = $m.Id
                    AppId              = $m.AppId
                    DisplayName        = $m.DisplayName
                })
            }
        }
    }
    return $results
}
