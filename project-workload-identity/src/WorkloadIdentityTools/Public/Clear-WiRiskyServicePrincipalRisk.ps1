#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Approved-verb wrapper to dismiss risk for risky service principals.
.DESCRIPTION
Calls underlying Dismiss-WiRiskyServicePrincipal for backward compatibility.
Use this cmdlet instead of the deprecated Dismiss-WiRiskyServicePrincipal.
#>
Function Clear-WiRiskyServicePrincipalRisk {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][ValidateNotNullOrEmpty()][string[]]$ServicePrincipalId
    )
    Process {
        Dismiss-WiRiskyServicePrincipal -ServicePrincipalId $ServicePrincipalId -Confirm:$ConfirmPreference -WhatIf:$WhatIfPreference
    }
}
