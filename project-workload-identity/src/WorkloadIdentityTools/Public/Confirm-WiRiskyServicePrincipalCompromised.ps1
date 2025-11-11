#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Confirm risky service principals as compromised (beta).

.DESCRIPTION
Calls POST /beta/identityProtection/riskyServicePrincipals/confirmCompromised with a list of risky service principal ids.
Requires IdentityRiskyServicePrincipal.ReadWrite.All and Security Administrator or equivalent role.

.PARAMETER ServicePrincipalId
One or more risky service principal ids to confirm as compromised.

Docs:
- confirmCompromised (beta): https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-confirmcompromised?view=graph-rest-beta
#>
Function Confirm-WiRiskyServicePrincipalCompromised {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][ValidateNotNullOrEmpty()][string[]]$ServicePrincipalId
    )
    Begin { 
        Write-Warning 'DEPRECATION: Confirm-WiRiskyServicePrincipalCompromised will be removed in a future release. Use Set-WiRiskyServicePrincipalCompromised instead.'
        $buffer = New-Object System.Collections.Generic.List[string] 
    }
    Process { $ServicePrincipalId | ForEach-Object { $buffer.Add($_) } }
    End {
        if ($buffer.Count -eq 0) { return }
        if ($PSCmdlet.ShouldProcess("$($buffer.Count) service principals", "Confirm compromised")) {
            $body = @{ servicePrincipalIds = $buffer.ToArray() }
            Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/identityProtection/riskyServicePrincipals/confirmCompromised' -Body ($body | ConvertTo-Json) -ContentType 'application/json' -ErrorAction Stop | Out-Null
        }
    }
}
