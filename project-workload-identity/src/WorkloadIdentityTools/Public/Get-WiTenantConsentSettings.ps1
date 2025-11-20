#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Report user consent restriction and admin consent workflow posture.

.DESCRIPTION
Retrieves authorization policy properties to understand consent settings.
Docs: Get-MgPolicyAuthorizationPolicy — https://learn.microsoft.com/powershell/module/microsoft.graph.identity.signins/get-mgpolicyauthorizationpolicy?view=graph-powershell-1.0

.OUTPUTS
PSCustomObject with key consent posture properties.
#>
Function Get-WiTenantConsentSettings {
    [CmdletBinding()] 
    [OutputType([psobject])]
    Param()
    try { $policy = Get-MgPolicyAuthorizationPolicy } catch { Throw "Failed to retrieve authorization policy: $($_.Exception.Message)" }

    $policyProperties = $policy.PSObject.Properties
    $permissionGrantPoliciesAssignedProp = $policyProperties | Where-Object { $_.Name -ieq 'permissionGrantPoliciesAssigned' } | Select-Object -First 1
    $permissionGrantPoliciesAssignedToDefaultUserRoleProp = $policyProperties | Where-Object { $_.Name -ieq 'permissionGrantPolicyIdsAssignedToDefaultUserRole' -or $_.Name -ieq 'permissionGrantPoliciesAssignedToDefaultUserRole' } | Select-Object -First 1

    $permissionGrantPoliciesAssigned = if ($permissionGrantPoliciesAssignedProp) { $permissionGrantPoliciesAssignedProp.Value } else { $null }
    $permissionGrantPoliciesAssignedToDefaultUserRole = if ($permissionGrantPoliciesAssignedToDefaultUserRoleProp) { $permissionGrantPoliciesAssignedToDefaultUserRoleProp.Value } else { $null }

    return [PSCustomObject]@{
        DefaultUserRolePermissionsAllowed                 = $policy.DefaultUserRolePermissions
        PermissionGrantPoliciesAssigned                   = $permissionGrantPoliciesAssigned
        PermissionGrantPolicyIdsAssignedToDefaultUserRole = $permissionGrantPoliciesAssignedToDefaultUserRole
    }
}
