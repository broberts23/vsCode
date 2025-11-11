#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Add (or rotate) a certificate credential on an application.

.DESCRIPTION
Wrapper for Add-MgApplicationKey. Requires proof of possession of existing key if keys exist; for first-time add use Update application method (not implemented here). Expects a DER or CER file path.
Docs: Add-MgApplicationKey — https://learn.microsoft.com/powershell/module/microsoft.graph.applications/add-mgapplicationkey?view=graph-powershell-1.0

.PARAMETER ApplicationId
Target application object ID.
.PARAMETER CertificatePath
Path to certificate file (.cer) containing public key.
.PARAMETER DisplayName
Friendly display name for credential.
.PARAMETER EndDate
Expiration date (UTC); defaults to 180 days from now.
.PARAMETER Usage
Key usage (Verify|Sign). Default Verify.
.PARAMETER Type
Key type (AsymmetricX509Cert). Default AsymmetricX509Cert.
.PARAMETER Proof
Proof-of-possession JWT generated with existing key (required when existing key credentials present).

.OUTPUTS
Key credential object.
#>
Function Add-WiApplicationCertificateCredential {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    [OutputType([psobject])]
    Param(
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$ApplicationId,
        [Parameter(Mandatory)][ValidateScript({ Test-Path $_ })][string]$CertificatePath,
        [Parameter()][string]$DisplayName = 'RotatedCert',
        [Parameter()][DateTime]$EndDate = (Get-Date).ToUniversalTime().AddDays(180),
        [Parameter()][ValidateSet('Verify','Sign')][string]$Usage = 'Verify',
        [Parameter()][ValidateSet('AsymmetricX509Cert','X509CertAndPassword')][string]$Type = 'AsymmetricX509Cert',
        [Parameter()][string]$Proof
    )
    if ($PSCmdlet.ShouldProcess("App $ApplicationId","Add certificate credential $DisplayName")) {
        $bytes = [System.IO.File]::ReadAllBytes($CertificatePath)
        $keyB64 = [System.Convert]::ToBase64String($bytes)
        $keyCredential = @{ type = $Type; usage = $Usage; key = [System.Text.Encoding]::ASCII.GetBytes($keyB64); displayName = $DisplayName; endDateTime = $EndDate }
        $body = @{ keyCredential = $keyCredential; passwordCredential = $null; proof = $Proof }
        try {
            $result = Add-MgApplicationKey -ApplicationId $ApplicationId -BodyParameter $body
        } catch {
            Throw "Failed to add application key: $($_.Exception.Message). Ensure proof parameter is supplied if required."
        }
        return $result
    }
}
