#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Inventory application credentials (secrets, certificates, federated credentials) and assess risk.

.DESCRIPTION
Retrieves applications and inspects passwordCredentials, keyCredentials, and federated identity credentials.
Flags long-lived credentials (>180 days), near-expiry (<30 days), and absence of modern (federated/cert) credentials.
Docs: Get-MgApplication — https://learn.microsoft.com/powershell/module/microsoft.graph.applications/get-mgapplication?view=graph-powershell-1.0
Federated: New-MgApplicationFederatedIdentityCredential — https://learn.microsoft.com/powershell/module/microsoft.graph.applications/new-mgapplicationfederatedidentitycredential?view=graph-powershell-1.0

.PARAMETER Filter
Optional OData filter passed to application query.

.PARAMETER All
Enumerate all applications (automatic paging).

.OUTPUTS
PSCustomObject (Credential inventory records)
#>
Function Get-WiApplicationCredentialInventory {
    [CmdletBinding()] 
    [OutputType([psobject])]
    Param(
        [Parameter()][string]$Filter,
        [Parameter()][switch]$All
    )
    Function New-Record {
        Param(
            [string]$ApplicationId,
            [string]$DisplayName,
            [string]$CredentialId,
            [string]$CredentialType,
            [Nullable[DateTime]]$StartDate,
            [Nullable[DateTime]]$EndDate,
            [string[]]$RiskReasons,
            [string]$RiskLevel
        )
        [PSCustomObject]@{
            ApplicationId   = $ApplicationId
            DisplayName     = $DisplayName
            CredentialId    = $CredentialId
            CredentialType  = $CredentialType
            StartDate       = $StartDate
            EndDate         = $EndDate
            DaysUntilExpiry = if ($EndDate) { [math]::Round(($EndDate - (Get-Date)).TotalDays, 0) } else { $null }
            LongLived       = if ($EndDate -and $StartDate) { ($EndDate - $StartDate).TotalDays -gt 180 } else { $false }
            NearExpiry      = if ($EndDate) { ($EndDate - (Get-Date)).TotalDays -lt 30 } else { $false }
            RiskLevel       = $RiskLevel
            RiskReasons     = $RiskReasons
        }
    }
    try {
        $params = @{ }
        if ($Filter) { $params.Filter = $Filter }
        if ($All) { $params.All = $true }
        $apps = Get-MgApplication @params
    }
    catch {
        Throw "Failed to retrieve applications: $($_.Exception.Message)"
    }
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($app in $apps) {
        $display = $app.DisplayName
        foreach ($pwd in $app.PasswordCredentials) {
            $riskReasons = @()
            $riskLevel = 'None'
            if ($pwd.EndDateTime) {
                $days = ($pwd.EndDateTime - (Get-Date)).TotalDays
                if ($days -lt 30) { $riskReasons += 'NearExpiry'; $riskLevel = 'Medium' }
            }
            if ($pwd.StartDateTime -and $pwd.EndDateTime) {
                $lifetime = ($pwd.EndDateTime - $pwd.StartDateTime).TotalDays
                if ($lifetime -gt 180) { $riskReasons += 'LongLived'; $riskLevel = 'High' }
            }
            if ($riskReasons.Count -eq 0) { $riskReasons = @('SecretPresent') }
            $results.Add((New-Record -ApplicationId $app.Id -DisplayName $display -CredentialId $pwd.KeyId -CredentialType 'Secret' -StartDate $pwd.StartDateTime -EndDate $pwd.EndDateTime -RiskReasons $riskReasons -RiskLevel $riskLevel))
        }
        foreach ($key in $app.KeyCredentials) {
            $riskReasons = @()
            $riskLevel = 'None'
            if ($key.EndDateTime) {
                $days = ($key.EndDateTime - (Get-Date)).TotalDays
                if ($days -lt 30) { $riskReasons += 'NearExpiry'; $riskLevel = 'Medium' }
            }
            if ($key.StartDateTime -and $key.EndDateTime) {
                $lifetime = ($key.EndDateTime - $key.StartDateTime).TotalDays
                if ($lifetime -gt 180) { $riskReasons += 'LongLived'; $riskLevel = 'High' }
            }
            if ($riskReasons.Count -eq 0) { $riskReasons = @('CertificatePresent') }
            $results.Add((New-Record -ApplicationId $app.Id -DisplayName $display -CredentialId $key.KeyId -CredentialType 'Certificate' -StartDate $key.StartDateTime -EndDate $key.EndDateTime -RiskReasons $riskReasons -RiskLevel $riskLevel))
        }
        if ($app | Get-Member -Name 'FederatedIdentityCredentials') {
            foreach ($fid in $app.FederatedIdentityCredentials) {
                $results.Add((New-Record -ApplicationId $app.Id -DisplayName $display -CredentialId $fid.Id -CredentialType 'Federated' -StartDate $null -EndDate $null -RiskReasons @('FederatedCredential') -RiskLevel 'None'))
            }
        }
        $hasSecret = $results.Where({ $_.ApplicationId -eq $app.Id -and $_.CredentialType -eq 'Secret' }).Count -gt 0
        $hasModern = $results.Where({ $_.ApplicationId -eq $app.Id -and ($_.CredentialType -eq 'Certificate' -or $_.CredentialType -eq 'Federated') }).Count -gt 0
        if ($hasSecret -and -not $hasModern) {
            $results.Add((New-Record -ApplicationId $app.Id -DisplayName $display -CredentialId ([guid]::NewGuid().Guid) -CredentialType 'Recommendation' -StartDate $null -EndDate $null -RiskReasons @('MigrateToFederatedOrCertificate') -RiskLevel 'Medium'))
        }
    }
    return $results
}
