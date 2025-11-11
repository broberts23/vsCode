#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Dismiss risk on risky service principals (beta).

.DESCRIPTION
Calls POST /beta/identityProtection/riskyServicePrincipals/dismiss to set RiskLevel to none for the given risky service principal ids.
Requires IdentityRiskyServicePrincipal.ReadWrite.All and Security Administrator or equivalent role.

.PARAMETER ServicePrincipalId
One or more risky service principal ids to dismiss.

Docs:
- dismiss (beta): https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-dismiss?view=graph-rest-beta
#>
Function Dismiss-WiRiskyServicePrincipal {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][ValidateNotNullOrEmpty()][string[]]$ServicePrincipalId
    )
    Begin { 
        Write-Warning 'DEPRECATION: Dismiss-WiRiskyServicePrincipal will be removed in a future release. Use Clear-WiRiskyServicePrincipalRisk instead.'
        $buffer = New-Object System.Collections.Generic.List[string] 
    }
    Process { $ServicePrincipalId | ForEach-Object { $buffer.Add($_) } }
    End {
        if ($buffer.Count -eq 0) { return }
        if ($PSCmdlet.ShouldProcess("$($buffer.Count) service principals", "Dismiss risk")) {
            $body = @{ servicePrincipalIds = $buffer.ToArray() }
            Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/identityProtection/riskyServicePrincipals/dismiss' -Body ($body | ConvertTo-Json) -ContentType 'application/json' -ErrorAction Stop | Out-Null
        }
    }
}
