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
        [Parameter()][string[]]$HighPrivilegeValues = @('Directory.ReadWrite.All','Application.ReadWrite.All','Device.ReadWrite.All','Group.ReadWrite.All','User.ReadWrite.All','Policy.ReadWrite.Authorization','RoleManagement.ReadWrite.Directory')
    )
    try { $apps = Get-MgApplication -All -Property 'RequiredResourceAccess,DisplayName' } catch { Throw "Failed to retrieve applications: $($_.Exception.Message)" }
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($app in $apps) {
        $matched = New-Object System.Collections.Generic.List[string]
        $raw = $app | ConvertTo-Json -Depth 10
        foreach ($val in $HighPrivilegeValues) { if ($raw -match $val) { $matched.Add($val) } }
        if ($matched.Count -gt 0) {
            $results.Add([PSCustomObject]@{
                ApplicationId            = $app.Id
                DisplayName              = $app.DisplayName
                HighPrivilegePermissions = $matched.ToArray()
            })
        }
    }
    return $results
}
