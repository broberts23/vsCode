#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Flag applications with high-privilege requiredResourceAccess entries.

.DESCRIPTION
Inspects app requiredResourceAccess for known high privilege scopes / roles (Directory.ReadWrite.All, Application.ReadWrite.All, User.ReadWrite.All, Group.ReadWrite.All, etc.).
Docs: Get-MgApplication — https://learn.microsoft.com/powershell/module/microsoft.graph.applications/get-mgapplication?view=graph-powershell-1.0

.PARAMETER HighPrivilegeValues
List of permission value strings considered high privilege.

.OUTPUTS
PSCustomObject with ApplicationId, DisplayName, HighPrivilegePermissions.
#>
Function Get-WiHighPrivilegeAppPermissions {
    [CmdletBinding()] 
    [OutputType([psobject])]
    Param(
        [Parameter()][string]$GraphResourceAppId = '00000003-0000-0000-c000-000000000000',
        # High-privilege Microsoft Graph appRole IDs (not display values).
        [Parameter()][string[]]$HighPrivilegeAppRoleIds = @(
            '19dbc75e-c2e2-444c-a770-ec69d8559fc7', # Directory.ReadWrite.All
            '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9', # Application.ReadWrite.All
            '1138cb37-bd11-4084-a2b7-9f71582aeddb', # Device.ReadWrite.All
            '62a82d76-70ea-41e2-9197-370581804d09', # Group.ReadWrite.All
            '204e0828-b5ca-4ad8-b9f3-f32a958e7cc4', # User.ReadWrite.All
            '246dd0d5-5bd0-4def-940b-0421030a5b68', # Policy.ReadWrite.Authorization
            '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'  # RoleManagement.ReadWrite.Directory
        )
    )
    try { $apps = Get-MgApplication -All -Property 'RequiredResourceAccess,DisplayName,AppId' } catch { Throw "Failed to retrieve applications: $($_.Exception.Message)" }

    $highPrivilegeLabels = @{
        '19dbc75e-c2e2-444c-a770-ec69d8559fc7' = 'Directory.ReadWrite.All'
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9' = 'Application.ReadWrite.All'
        '1138cb37-bd11-4084-a2b7-9f71582aeddb' = 'Device.ReadWrite.All'
        '62a82d76-70ea-41e2-9197-370581804d09' = 'Group.ReadWrite.All'
        '204e0828-b5ca-4ad8-b9f3-f32a958e7cc4' = 'User.ReadWrite.All'
        '246dd0d5-5bd0-4def-940b-0421030a5b68' = 'Policy.ReadWrite.Authorization'
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8' = 'RoleManagement.ReadWrite.Directory'
    }

    $results = New-Object System.Collections.Generic.List[object]
    $graphSp = $null
    foreach ($app in $apps) {
        Write-Verbose ("[HighPriv] Inspecting app {0} ({1})" -f $app.DisplayName, $app.Id)
        $matched = New-Object System.Collections.Generic.List[string]
        $graphAccess = $app.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $GraphResourceAppId }
        if (-not $graphAccess) {
            Write-Verbose '  [HighPriv] No Graph requiredResourceAccess found.'
        }
        foreach ($resource in $graphAccess) {
            foreach ($access in $resource.ResourceAccess) {
                $accessId = [string]$access.Id
                Write-Verbose ("  [HighPriv]   AccessId={0}, Type={1}, IsHighPriv={2}" -f $accessId, $access.Type, ($HighPrivilegeAppRoleIds -contains $accessId))
                if ($HighPrivilegeAppRoleIds -contains $accessId) {
                    $label = if ($highPrivilegeLabels.ContainsKey($accessId)) { $highPrivilegeLabels[$accessId] } else { $accessId }
                    if (-not $matched.Contains($label)) {
                        Write-Verbose ("  [HighPriv]   Matched {0}" -f $label)
                        $matched.Add($label)
                    }
                }
            }
        }

        # Also inspect Graph appRoleAssignments on the application's service principal
        if (-not $graphSp) {
            try {
                $graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphResourceAppId'" -ConsistencyLevel eventual -ErrorAction Stop
            }
            catch {
                Write-Verbose "[HighPriv] Failed to resolve Graph service principal: $($_.Exception.Message)"
            }
        }

        if ($graphSp -and $app.AppId) {
            try {
                $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue
            }
            catch {
                $sp = $null
            }

            if ($sp) {
                try {
                    $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
                }
                catch {
                    $assignments = @()
                }

                foreach ($assignment in $assignments) {
                    if ($assignment.ResourceId -ne $graphSp.Id -or -not $assignment.AppRoleId) {
                        continue
                    }

                    $assignmentId = [string]$assignment.AppRoleId
                    Write-Verbose ("  [HighPriv]   Assignment AppRoleId={0}, IsHighPriv={1}" -f $assignmentId, ($HighPrivilegeAppRoleIds -contains $assignmentId))
                    if ($HighPrivilegeAppRoleIds -contains $assignmentId) {
                        $label = if ($highPrivilegeLabels.ContainsKey($assignmentId)) { $highPrivilegeLabels[$assignmentId] } else { $assignmentId }
                        if (-not $matched.Contains($label)) {
                            Write-Verbose ("  [HighPriv]   Matched via assignment {0}" -f $label)
                            $matched.Add($label)
                        }
                    }
                }
            }
        }
        if ($matched.Count -gt 0) {
            Write-Verbose ("[HighPriv] App {0} has high-priv perms: {1}" -f $app.DisplayName, ($matched -join ', '))
            $results.Add([PSCustomObject]@{
                    ApplicationId            = $app.Id
                    DisplayName              = $app.DisplayName
                    HighPrivilegePermissions = $matched.ToArray()
                })
        }
        else {
            Write-Verbose ("[HighPriv] App {0} has no matching high-priv perms." -f $app.DisplayName)
        }
    }
    return $results
}

