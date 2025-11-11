#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../../src/WorkloadIdentityTools/WorkloadIdentityTools.psd1') -Force

Describe 'Module Load' {
    It 'Exports expected functions' {
        $expected = 'Connect-WiGraph','Get-WiRiskyServicePrincipal','Get-WiApplicationCredentialInventory','Get-WiServicePrincipalPrivilegedAssignments','Get-WiHighPrivilegeAppPermissions','Get-WiTenantConsentSettings','New-WiFederatedCredential','Add-WiApplicationCertificateCredential'
        foreach ($fn in $expected) { (Get-Command -Name $fn -ErrorAction Stop) | Should -Not -BeNullOrEmpty }
    }
}
