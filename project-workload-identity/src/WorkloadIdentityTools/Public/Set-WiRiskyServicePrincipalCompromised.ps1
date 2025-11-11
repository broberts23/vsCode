#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Approved-verb wrapper to confirm risky service principals as compromised.
.DESCRIPTION
Calls underlying Confirm-WiRiskyServicePrincipalCompromised for backward compatibility.
Use this cmdlet instead of the deprecated Confirm-WiRiskyServicePrincipalCompromised.
#>
Function Set-WiRiskyServicePrincipalCompromised {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][ValidateNotNullOrEmpty()][string[]]$ServicePrincipalId
    )
    Process {
        Confirm-WiRiskyServicePrincipalCompromised -ServicePrincipalId $ServicePrincipalId -Confirm:$ConfirmPreference -WhatIf:$WhatIfPreference
    }
}
